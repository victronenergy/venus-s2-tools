#!/usr/bin/env python3
"""Passive S2 message sniffer for D-Bus.

Features:
- Capture both S2 directions:
  - RM -> CEM via Message signal
  - CEM -> RM via Message method call
- Resolve transient owner names (:1.x) to Victron service names
- Optional filters by service and/or message type
- Optional hiding of ReceptionStatus
- Compact terminal output with optional JSON preview truncation
- Optional full-message append log file
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import Any, Optional

S2_IFACE = "com.victronenergy.S2"
RM_PATH = "/S2/0/Rm"
DBUS_NAME = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
VIC_PREFIX = "com.victronenergy."


class S2SnifferError(RuntimeError):
    pass


def load_dbus():
    try:
        from dbus_fast import BusType, Message, MessageType
        from dbus_fast.aio import MessageBus
        return BusType, Message, MessageType, MessageBus
    except ImportError:
        try:
            from dbus_next import BusType, Message, MessageType
            from dbus_next.aio import MessageBus
            return BusType, Message, MessageType, MessageBus
        except ImportError as exc:
            raise S2SnifferError(
                "Neither dbus-fast nor dbus-next is available. Install one of them on the target system."
            ) from exc


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_message_type(payload: str) -> Optional[str]:
    try:
        data = json.loads(payload)
        return data.get("message_type") or data.get("MessageType")
    except (json.JSONDecodeError, KeyError, AttributeError):
        return None


class S2Sniffer:
    def __init__(
        self,
        bus: Any,
        message_cls: Any,
        message_type_cls: Any,
        service_filter: Optional[str] = None,
        message_type_filter: Optional[str] = None,
        hide_reception_status: bool = False,
        hide_power_measurement: bool = False,
        hide_keep_alive: bool = False,
        max_preview_lines: int = 40,
        full_log_file: Optional[str] = None,
        verbose: bool = False,
        count: Optional[int] = None,
    ):
        self.bus = bus
        self.Message = message_cls
        self.MessageType = message_type_cls
        self.service_filter = service_filter
        self.message_type_filter = message_type_filter
        self.hide_reception_status = hide_reception_status
        self.hide_power_measurement = hide_power_measurement
        self.hide_keep_alive = hide_keep_alive
        self.max_preview_lines = max_preview_lines
        self.full_log_file = full_log_file
        self.verbose = verbose
        self.count = count

        self._handler_installed = False
        self._message_handler = None
        self._match_rules: list[str] = []
        self._message_count = 0
        self._closed = False
        self._owner_to_service: dict[str, str] = {}
        self._full_log_handle: Optional[Any] = None
        # serial -> (cem_id, rm_service) for in-flight KeepAlive calls
        self._pending_keepalives: dict[int, tuple[str, str]] = {}

    async def __aenter__(self) -> "S2Sniffer":
        self.install_handler()
        await self.add_signal_matches()
        await self.refresh_name_cache()
        if self.full_log_file:
            self._full_log_handle = open(self.full_log_file, "a", encoding="utf-8")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    def install_handler(self) -> None:
        if self._handler_installed:
            return

        def handler(message: Any) -> bool:
            if self._closed:
                return False

            if (
                message.message_type == self.MessageType.SIGNAL
                and message.path == DBUS_PATH
                and message.interface == DBUS_NAME
                and message.member == "NameOwnerChanged"
            ):
                try:
                    name, old_owner, new_owner = message.body
                except Exception:
                    return False
                self._handle_name_owner_changed(str(name), str(old_owner), str(new_owner))
                return False

            # Handle Connect/Disconnect method calls and Disconnect signals
            if message.path == RM_PATH and message.interface == S2_IFACE:
                if message.member == "Connect":
                    if message.message_type == self.MessageType.METHOD_CALL:
                        try:
                            cem_id = str(message.body[0]) if message.body else "<unknown>"
                            keep_alive_interval = int(message.body[1]) if len(message.body) > 1 else None
                        except Exception:
                            cem_id = "<unknown>"
                            keep_alive_interval = None
                        direction = "CEM_TO_RM"
                        rm_service = self.resolve_service_name(message.destination)
                        self._print_connection_event("CONNECT", direction, cem_id, rm_service, keep_alive_interval=keep_alive_interval)
                        return True

                elif message.member == "Disconnect":
                    if message.message_type == self.MessageType.METHOD_CALL:
                        try:
                            cem_id = str(message.body[0]) if message.body else "<unknown>"
                        except Exception:
                            cem_id = "<unknown>"
                        direction = "CEM_TO_RM"
                        rm_service = self.resolve_service_name(message.destination)
                        self._print_connection_event("DISCONNECT_REQUEST", direction, cem_id, rm_service)
                        return True
                    elif message.message_type == self.MessageType.SIGNAL:
                        try:
                            cem_id = str(message.body[0]) if message.body else "<unknown>"
                            reason = str(message.body[1]) if len(message.body) > 1 else None
                        except Exception:
                            cem_id = "<unknown>"
                            reason = None
                        direction = "RM_TO_CEM"
                        rm_service = self.resolve_service_name(message.sender)
                        self._print_connection_event("DISCONNECT", direction, cem_id, rm_service, reason=reason)
                        return True

                elif message.member == "KeepAlive":
                    if message.message_type == self.MessageType.METHOD_CALL:
                        try:
                            cem_id = str(message.body[0]) if message.body else "<unknown>"
                        except Exception:
                            cem_id = "<unknown>"
                        rm_service = self.resolve_service_name(message.destination)
                        try:
                            serial = int(message.serial)
                            self._pending_keepalives[serial] = (cem_id, rm_service)
                        except Exception:
                            pass
                        if not self.hide_keep_alive:
                            self._print_connection_event("KEEP_ALIVE", "CEM_TO_RM", cem_id, rm_service)
                        return True

            # KeepAlive reply: METHOD_RETURN from RM back to CEM
            if (
                message.message_type == self.MessageType.METHOD_RETURN
                and message.reply_serial is not None
            ):
                pending = self._pending_keepalives.pop(int(message.reply_serial), None)
                if pending is not None:
                    cem_id, rm_service = pending
                    if not self.hide_keep_alive:
                        try:
                            accepted = bool(message.body[0]) if message.body else True
                        except Exception:
                            accepted = True
                        self._print_connection_event(
                            "KEEP_ALIVE_OK" if accepted else "KEEP_ALIVE_REJECTED",
                            "RM_TO_CEM",
                            cem_id,
                            rm_service,
                        )
                    return True

            if message.path != RM_PATH or message.interface != S2_IFACE or message.member != "Message":
                return False

            if message.message_type == self.MessageType.SIGNAL:
                try:
                    client_id, raw_payload = message.body
                except Exception:
                    return False
                direction = "RM_TO_CEM"
                cem_id = str(client_id)
                rm_service = self.resolve_service_name(message.sender)

            elif message.message_type == self.MessageType.METHOD_CALL:
                try:
                    client_id, raw_payload = message.body
                except Exception:
                    return False
                direction = "CEM_TO_RM"
                cem_id = str(client_id)
                rm_service = self.resolve_service_name(message.destination)

            else:
                return False

            msg_type = get_message_type(str(raw_payload))

            if self.hide_reception_status and msg_type == "ReceptionStatus":
                return False
            if self.hide_power_measurement and msg_type == "PowerMeasurement":
                return False

            if self.message_type_filter:
                if msg_type is None or self.message_type_filter.lower() not in msg_type.lower():
                    return False

            if self.service_filter:
                needle = self.service_filter.lower()
                rm_short = self.strip_service_name(rm_service).lower()
                if needle not in rm_short and needle not in cem_id.lower():
                    return False

            self._print_message(direction, cem_id, rm_service, raw_payload)
            return True

        self._message_handler = handler
        self.bus.add_message_handler(handler)
        self._handler_installed = True

    async def add_signal_matches(self) -> None:
        self._match_rules = [
            (
                "type='signal',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "eavesdrop='true',"
                "member='Message'"
            ),
            (
                "type='method_call',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "eavesdrop='true',"
                "member='Message'"
            ),
            (
                "type='method_call',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "eavesdrop='true',"
                "member='Connect'"
            ),
            (
                "type='method_call',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "eavesdrop='true',"
                "member='Disconnect'"
            ),
            (
                "type='signal',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "eavesdrop='true',"
                "member='Disconnect'"
            ),
            (
                "type='method_call',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "eavesdrop='true',"
                "member='KeepAlive'"
            ),
            (
                "type='method_return',"
                "eavesdrop='true'"
            ),
            (
                "type='signal',"
                f"sender='{DBUS_NAME}',"
                f"interface='{DBUS_NAME}',"
                f"path='{DBUS_PATH}',"
                "member='NameOwnerChanged'"
            ),
        ]

        for rule in self._match_rules:
            reply = await self.bus.call(
                self.Message(
                    destination=DBUS_NAME,
                    path=DBUS_PATH,
                    interface=DBUS_NAME,
                    member="AddMatch",
                    signature="s",
                    body=[rule],
                )
            )
            if reply.message_type == self.MessageType.ERROR:
                raise S2SnifferError(f"AddMatch failed for {rule}: {reply.error_name} {reply.body}")

    async def remove_signal_matches(self) -> None:
        for rule in self._match_rules:
            try:
                reply = await self.bus.call(
                    self.Message(
                        destination=DBUS_NAME,
                        path=DBUS_PATH,
                        interface=DBUS_NAME,
                        member="RemoveMatch",
                        signature="s",
                        body=[rule],
                    )
                )
                if self.verbose and reply.message_type == self.MessageType.ERROR:
                    print(f"Warning: RemoveMatch failed for {rule}: {reply.error_name} {reply.body}", file=sys.stderr)
            except Exception:
                pass
        self._match_rules = []

    def _handle_name_owner_changed(self, name: str, old_owner: str, new_owner: str) -> None:
        if not name.startswith(VIC_PREFIX):
            return
        if old_owner:
            self._owner_to_service.pop(old_owner, None)
        if new_owner:
            self._owner_to_service[new_owner] = name

    async def refresh_name_cache(self) -> None:
        reply = await self.bus.call(
            self.Message(
                destination=DBUS_NAME,
                path=DBUS_PATH,
                interface=DBUS_NAME,
                member="ListNames",
            )
        )
        if reply.message_type == self.MessageType.ERROR or not reply.body:
            return

        names = [str(name) for name in reply.body[0]]
        mapping: dict[str, str] = {}

        for name in names:
            if not name.startswith(VIC_PREFIX):
                continue
            owner_reply = await self.bus.call(
                self.Message(
                    destination=DBUS_NAME,
                    path=DBUS_PATH,
                    interface=DBUS_NAME,
                    member="GetNameOwner",
                    signature="s",
                    body=[name],
                )
            )
            if owner_reply.message_type == self.MessageType.ERROR or not owner_reply.body:
                continue
            mapping[str(owner_reply.body[0])] = name

        self._owner_to_service = mapping

    def resolve_service_name(self, name: Optional[str]) -> str:
        if not name:
            return "<unknown>"
        if name.startswith(VIC_PREFIX):
            return name
        if name.startswith(":"):
            return self._owner_to_service.get(name, name)
        return name

    def strip_service_name(self, service: str) -> str:
        if service.startswith(VIC_PREFIX):
            return service[len(VIC_PREFIX):]
        return service

    def _print_connection_event(
        self,
        event_type: str,
        direction: str,
        cem_id: str,
        rm_service: str,
        keep_alive_interval: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Print Connect/Disconnect events."""
        self._message_count += 1
        if self.count is not None and self._message_count > self.count:
            self._closed = True
            return

        timestamp = utc_now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        rm_display = self.strip_service_name(rm_service)

        if direction == "CEM_TO_RM":
            left, right = cem_id, rm_display
        else:
            left, right = rm_display, cem_id

        if event_type == "CONNECT":
            extra = f" (keep_alive_interval={keep_alive_interval}s)" if keep_alive_interval else ""
            event_msg = f"{timestamp} | '{left}' -> '{right}' | CONNECT{extra}"
        elif event_type == "DISCONNECT":
            extra = f" (reason: {reason})" if reason else ""
            event_msg = f"{timestamp} | '{left}' -> '{right}' | DISCONNECT (confirmed){extra}"
        elif event_type == "DISCONNECT_REQUEST":
            event_msg = f"{timestamp} | '{left}' -> '{right}' | DISCONNECT (requested)"
        elif event_type == "KEEP_ALIVE":
            event_msg = f"{timestamp} | '{left}' -> '{right}' | KEEP_ALIVE"
        elif event_type == "KEEP_ALIVE_OK":
            event_msg = f"{timestamp} | '{left}' -> '{right}' | KEEP_ALIVE (ok)"
        elif event_type == "KEEP_ALIVE_REJECTED":
            event_msg = f"{timestamp} | '{left}' -> '{right}' | KEEP_ALIVE (rejected)"
        else:
            event_msg = f"{timestamp} | '{left}' -> '{right}' | {event_type}"

        if self._full_log_handle is not None:
            self._full_log_handle.write(f"{event_msg}\n")
            self._full_log_handle.flush()

        print(event_msg)

    def _print_message(self, direction: str, cem_id: str, rm_service: str, raw_payload: Any) -> None:
        self._message_count += 1
        if self.count is not None and self._message_count > self.count:
            self._closed = True
            return

        timestamp = utc_now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        rm_display = self.strip_service_name(rm_service)

        if direction == "RM_TO_CEM":
            left = rm_display
            right = cem_id
        else:
            left = cem_id
            right = rm_display

        try:
            message_json = json.loads(str(raw_payload))
        except (json.JSONDecodeError, ValueError):
            message_json = {"raw": str(raw_payload)}

        s2_json = json.dumps(message_json, indent=2, sort_keys=True, default=str, ensure_ascii=False)
        header = f"{timestamp} | '{left}' -> '{right}' | S2:"

        if self._full_log_handle is not None:
            self._full_log_handle.write(f"{header} {s2_json}\n")
            self._full_log_handle.flush()

        if self.max_preview_lines > 0:
            lines = s2_json.splitlines()
            if len(lines) > self.max_preview_lines:
                shown = "\n".join(lines[: self.max_preview_lines])
                hidden = len(lines) - self.max_preview_lines
                print(f"{header} {shown}")
                if self.full_log_file:
                    print(f"... [{hidden} more JSON lines hidden; full message in {self.full_log_file}]")
                else:
                    print("... [{hidden} more JSON lines hidden; use --max-preview-lines 0 or --full-log-file <path>]".format(hidden=hidden))
                return

        print(f"{header} {s2_json}")

    async def close(self) -> None:
        self._closed = True

        if self._full_log_handle is not None:
            try:
                self._full_log_handle.close()
            except Exception:
                pass
            self._full_log_handle = None

        if self._handler_installed and self._message_handler is not None:
            try:
                self.bus.remove_message_handler(self._message_handler)
            except Exception:
                pass
            self._message_handler = None
            self._handler_installed = False

        await self.remove_signal_matches()

    async def run(self) -> None:
        print("Listening for S2 messages on D-Bus (both directions)...", file=sys.stderr)
        if self.service_filter:
            print(f"  Service filter: {self.service_filter}", file=sys.stderr)
        if self.message_type_filter:
            print(f"  Message type filter: {self.message_type_filter}", file=sys.stderr)
        if self.hide_reception_status:
            print("  Hiding ReceptionStatus", file=sys.stderr)
        if self.hide_power_measurement:
            print("  Hiding PowerMeasurement", file=sys.stderr)
        if self.hide_keep_alive:
            print("  Hiding KeepAlive", file=sys.stderr)
        if self.max_preview_lines > 0:
            print(f"  Max preview lines: {self.max_preview_lines}", file=sys.stderr)
        else:
            print("  Max preview lines: unlimited", file=sys.stderr)
        if self.full_log_file:
            print(f"  Full log file: {self.full_log_file}", file=sys.stderr)
        if self.count:
            print(f"  Max messages: {self.count}", file=sys.stderr)
        print("Press Ctrl+C to stop.", file=sys.stderr)

        last_refresh = asyncio.get_running_loop().time()
        while not self._closed:
            now = asyncio.get_running_loop().time()
            if now - last_refresh >= 5.0:
                try:
                    await self.refresh_name_cache()
                except Exception:
                    pass
                last_refresh = now
            await asyncio.sleep(0.1)


async def async_main(args: argparse.Namespace) -> int:
    BusType, Message, MessageType, MessageBus = load_dbus()
    bus_type = BusType.SYSTEM if args.dbus == "system" else BusType.SESSION
    bus = await MessageBus(bus_type=bus_type).connect()

    async with S2Sniffer(
        bus=bus,
        message_cls=Message,
        message_type_cls=MessageType,
        service_filter=args.service,
        message_type_filter=args.message_type,
        hide_reception_status=args.hide_reception_status,
        hide_power_measurement=args.hide_power_measurement,
        hide_keep_alive=args.hide_keep_alive,
        max_preview_lines=args.max_preview_lines,
        full_log_file=args.full_log_file,
        verbose=args.verbose,
        count=args.count,
    ) as sniffer:
        await sniffer.run()

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dbus", choices=("system", "session"), default="system", help="Which D-Bus to use.")
    parser.add_argument("--service", default=None, help="Filter by CEM id or RM service substring.")
    parser.add_argument("--message-type", default=None, help="Filter by S2 message_type substring.")
    parser.add_argument(
        "--hide-reception-status",
        action="store_true",
        help="Hide S2 messages where message_type is ReceptionStatus.",
    )
    parser.add_argument(
        "--hide-power-measurement",
        action="store_true",
        help="Hide S2 messages where message_type is PowerMeasurement.",
    )
    parser.add_argument(
        "--hide-keep-alive",
        action="store_true",
        help="Hide KeepAlive method calls.",
    )
    parser.add_argument(
        "--max-preview-lines",
        type=int,
        default=40,
        help="Maximum S2 JSON lines printed per message (0 = unlimited).",
    )
    parser.add_argument(
        "--full-log-file",
        default=None,
        help="Optional file path where full S2 messages are appended.",
    )
    parser.add_argument("--count", type=int, default=None, help="Stop after this many messages.")
    parser.add_argument("--verbose", action="store_true", help="Print debug warnings.")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except S2SnifferError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
