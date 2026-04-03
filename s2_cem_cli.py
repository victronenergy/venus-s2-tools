#!/usr/bin/env python3
"""Interactive CLI for discovering and driving Victron S2 resource managers over D-Bus.

Features:
- scan D-Bus for Victron services that positively answer Discover on /S2/0/Rm
- connect to one selected RM
- handle S2 messaging asynchronously in a background receiver task
- auto-ack incoming messages with ReceptionStatus where appropriate
- keep KeepAlive running asynchronously while connected
- choose control types
- for NOT_CONTROLABLE:
  - print incoming PowerMeasurement updates
  - offer to go back to control types
  - offer to disconnect and go back to service selection
- for OMBC:
  - show current OMBC.Status
  - show all reachable transitions from the current mode
  - highlight abnormal_condition_only transitions very clearly
  - offer to go back to control types
  - offer to disconnect and go back to service selection
- when the RM sends a Disconnect signal, automatically return to the services list
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from s2python.common import (
    ControlType,
    Handshake,
    HandshakeResponse,
    PowerMeasurement,
    ReceptionStatus,
    ReceptionStatusValues,
    ResourceManagerDetails,
    SelectControlType,
    Transition,
)
from s2python.message import S2Message
from s2python.ombc import OMBCInstruction, OMBCOperationMode, OMBCStatus, OMBCSystemDescription
from s2python.s2_parser import S2Parser
from s2python.s2_validation_error import S2ValidationError
from s2python.version import S2_VERSION

S2_IFACE = "com.victronenergy.S2"
RM_PATH = "/S2/0/Rm"
DBUS_NAME = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
BUSITEM_IFACE = "com.victronenergy.BusItem"
DEFAULT_CLIENT_ID = "s2_cli"
DEFAULT_KEEPALIVE_S = 15


class S2CliError(RuntimeError):
    pass


class BackToServices(Exception):
    pass


@dataclass
class ServiceCandidate:
    service_name: str
    owner: str
    label: str


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
            raise S2CliError(
                "Neither dbus-fast nor dbus-next is available. Install one of them on the target system."
            ) from exc


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_id(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "root"):
        return str(value.root)
    return str(value)


def enum_text(value: Any) -> str:
    return getattr(value, "value", str(value))


def model_to_pretty_json(value: Any) -> str:
    if hasattr(value, "to_json_dict"):
        return json.dumps(value.to_json_dict(), indent=2, sort_keys=True)
    if hasattr(value, "to_dict"):
        return json.dumps(value.to_dict(), indent=2, sort_keys=True, default=str)
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def mode_label(mode: OMBCOperationMode) -> str:
    label = mode.diagnostic_label or normalize_id(mode.id)
    parts: list[str] = []
    for power_range in mode.power_ranges:
        quantity = enum_text(power_range.commodity_quantity)
        start = power_range.start_of_range
        end = power_range.end_of_range
        if start == end:
            parts.append(f"{quantity}={end}")
        else:
            parts.append(f"{quantity}={start}..{end}")
    suffix = f" [{' ; '.join(parts)}]" if parts else ""
    if getattr(mode, "abnormal_condition_only", False):
        suffix += " [MODE abnormal_condition_only=True]"
    return f"{label}{suffix}"


class S2Session:
    def __init__(
        self,
        bus: Any,
        message_cls: Any,
        message_type_cls: Any,
        service: ServiceCandidate,
        client_id: str,
        keepalive_s: int,
        verbose: bool = False,
    ):
        self.bus = bus
        self.Message = message_cls
        self.MessageType = message_type_cls
        self.service = service
        self.client_id = client_id
        self.keepalive_s = keepalive_s
        self.verbose = verbose
        self.parser = S2Parser()

        self.connected = False
        self._closed = False
        self._handler_installed = False
        self._message_handler = None
        self._match_rules: list[str] = []

        self._keepalive_task: Optional[asyncio.Task] = None
        self._receiver_task: Optional[asyncio.Task] = None

        self._raw_message_queue: asyncio.Queue[str] = asyncio.Queue()
        self._disconnect_queue: asyncio.Queue[str] = asyncio.Queue()
        self._reception_waiters: dict[str, asyncio.Future] = {}
        self._state_event = asyncio.Event()

        self.handshake: Optional[Handshake] = None
        self.rm_details: Optional[ResourceManagerDetails] = None
        self.active_control_type: Optional[ControlType] = None
        self.ombc_system_description: Optional[OMBCSystemDescription] = None
        self.ombc_status: Optional[OMBCStatus] = None
        self.power_measurement: Optional[PowerMeasurement] = None

        self._bootstrap_handshake_future: Optional[asyncio.Future] = None
        self._bootstrap_rm_details_future: Optional[asyncio.Future] = None
        self._disconnect_reason: Optional[str] = None

    async def __aenter__(self) -> "S2Session":
        self.install_handler()
        await self.add_signal_matches()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    def ensure_connected(self) -> None:
        if not self.connected:
            reason = f": {self._disconnect_reason}" if self._disconnect_reason else ""
            raise BackToServices(f"Disconnected{reason}")

    async def add_signal_matches(self) -> None:
        self._match_rules = [
            (
                "type='signal',"
                f"sender='{self.service.service_name}',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "member='Message'"
            ),
            (
                "type='signal',"
                f"sender='{self.service.service_name}',"
                f"interface='{S2_IFACE}',"
                f"path='{RM_PATH}',"
                "member='Disconnect'"
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
                raise S2CliError(f"AddMatch failed for {rule}: {reply.error_name} {reply.body}")

    def install_handler(self) -> None:
        if self._handler_installed:
            return

        def handler(message: Any) -> bool:
            if message.message_type != self.MessageType.SIGNAL:
                return False
            if message.path != RM_PATH or message.interface != S2_IFACE:
                return False
            if message.sender not in {self.service.owner, self.service.service_name}:
                return False

            if self.verbose:
                print(
                    f"[signal] sender={message.sender} member={message.member} "
                    f"body={getattr(message, 'body', None)}"
                )

            if message.member == "Message":
                try:
                    client_id, raw_payload = message.body
                except Exception:
                    return False
                if client_id == self.client_id:
                    self._raw_message_queue.put_nowait(str(raw_payload))
                    return True
                return False

            if message.member == "Disconnect":
                try:
                    client_id, reason = message.body
                except Exception:
                    return False
                if client_id == self.client_id:
                    self._disconnect_queue.put_nowait(str(reason))
                    return True
                return False

            return False

        self._message_handler = handler
        self.bus.add_message_handler(handler)
        self._handler_installed = True

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

    async def close(self) -> None:
        self._closed = True
        was_connected = self.connected

        if was_connected:
            try:
                await self.disconnect()
            except Exception:
                pass

        self.connected = False

        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None

        if self._receiver_task is not None:
            self._receiver_task.cancel()
            try:
                await self._receiver_task
            except asyncio.CancelledError:
                pass
            self._receiver_task = None

        for waiter in self._reception_waiters.values():
            if not waiter.done():
                waiter.cancel()
        self._reception_waiters.clear()

        if self._handler_installed and self._message_handler is not None:
            try:
                self.bus.remove_message_handler(self._message_handler)
            except Exception:
                pass
            self._message_handler = None
            self._handler_installed = False

        await self.remove_signal_matches()

        self._clear_queues()

    def _clear_queue(self, q: asyncio.Queue) -> None:
        while True:
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                break

    def _clear_queues(self) -> None:
        self._clear_queue(self._raw_message_queue)
        self._clear_queue(self._disconnect_queue)

    async def dbus_call(self, member: str, signature: str = "", body: Optional[list[Any]] = None) -> Any:
        reply = await self.bus.call(
            self.Message(
                destination=self.service.service_name,
                path=RM_PATH,
                interface=S2_IFACE,
                member=member,
                signature=signature,
                body=body or [],
            )
        )
        if reply.message_type == self.MessageType.ERROR:
            raise S2CliError(f"D-Bus error calling {member}: {reply.error_name} {reply.body}")
        return reply

    async def connect(self) -> None:
        self._clear_queues()

        reply = await self.dbus_call("Connect", "si", [self.client_id, self.keepalive_s])
        ok = bool(reply.body[0]) if reply.body else False
        if not ok:
            raise S2CliError("Connect returned False")

        self.connected = True
        self._closed = False
        self._disconnect_reason = None
        self._receiver_task = asyncio.create_task(self._receiver_loop(), name="s2_receiver")
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="s2_keepalive")

    async def disconnect(self) -> None:
        try:
            await self.dbus_call("Disconnect", "s", [self.client_id])
        finally:
            self.connected = False

    async def _keepalive_loop(self) -> None:
        try:
            while self.connected and not self._closed:
                await asyncio.sleep(self.keepalive_s)
                if not self.connected or self._closed:
                    break

                if self.verbose:
                    print(f"--> KeepAlive(client_id={self.client_id})")

                reply = await self.dbus_call("KeepAlive", "s", [self.client_id])
                ok = bool(reply.body[0]) if reply.body else False
                if not ok:
                    raise S2CliError("KeepAlive returned False")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.connected = False
            self._fail_waiters(exc)
            print(f"\nKeepAlive failed: {exc}", file=sys.stderr)

    async def _next_transport_event(self) -> tuple[str, str]:
        disconnect_task = asyncio.create_task(self._disconnect_queue.get())
        message_task = asyncio.create_task(self._raw_message_queue.get())
        try:
            done, pending = await asyncio.wait(
                {disconnect_task, message_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if disconnect_task in done:
                message_task.cancel()
                return ("disconnect", str(disconnect_task.result()))

            disconnect_task.cancel()
            return ("message", str(message_task.result()))
        finally:
            for task in (disconnect_task, message_task):
                if not task.done():
                    task.cancel()

    async def _receiver_loop(self) -> None:
        try:
            while self.connected and not self._closed:
                kind, payload = await self._next_transport_event()

                if kind == "disconnect":
                    self._disconnect_reason = payload
                    self.connected = False
                    self._state_event.set()
                    raise BackToServices(f"Peer disconnected: {payload}")

                if self.verbose:
                    print(f"<-- {payload}")

                try:
                    msg = self.parser.parse_as_any_message(payload)
                except (json.JSONDecodeError, S2ValidationError) as exc:
                    raise S2CliError(f"Failed to parse incoming S2 message: {exc}") from exc

                await self._handle_incoming_message(msg)
        except asyncio.CancelledError:
            raise
        except BackToServices as exc:
            self._fail_waiters(exc)
        except Exception as exc:
            self.connected = False
            self._fail_waiters(exc)

    def _fail_waiters(self, exc: Exception) -> None:
        for waiter in self._reception_waiters.values():
            if not waiter.done():
                waiter.set_exception(exc)
        self._reception_waiters.clear()
        self._state_event.set()

        if self._bootstrap_handshake_future is not None and not self._bootstrap_handshake_future.done():
            self._bootstrap_handshake_future.set_exception(exc)
        if self._bootstrap_rm_details_future is not None and not self._bootstrap_rm_details_future.done():
            self._bootstrap_rm_details_future.set_exception(exc)

    async def _handle_incoming_message(self, message: S2Message) -> None:
        if isinstance(message, Handshake):
            self.handshake = message
            if self._bootstrap_handshake_future is not None and not self._bootstrap_handshake_future.done():
                self._bootstrap_handshake_future.set_result(message)

        elif isinstance(message, ResourceManagerDetails):
            self.rm_details = message
            if self._bootstrap_rm_details_future is not None and not self._bootstrap_rm_details_future.done():
                self._bootstrap_rm_details_future.set_result(message)

        elif isinstance(message, OMBCSystemDescription):
            self.ombc_system_description = message

        elif isinstance(message, OMBCStatus):
            self.ombc_status = message

        elif isinstance(message, PowerMeasurement):
            self.power_measurement = message

        elif isinstance(message, ReceptionStatus):
            key = normalize_id(message.subject_message_id)
            waiter = self._reception_waiters.pop(key, None)
            if waiter is not None and not waiter.done():
                waiter.set_result(message)

        self._state_event.set()

        if self._should_auto_ack(message):
            await self.send_reception(ReceptionStatusValues.OK, message)

    def _should_auto_ack(self, message: S2Message) -> bool:
        if isinstance(message, ReceptionStatus):
            return False
        if not hasattr(message, "to_dict"):
            return False
        try:
            d = message.to_dict()
        except Exception:
            return False
        if d.get("message_type") == "ReceptionStatus":
            return False
        return bool(d.get("message_id"))

    async def send_message(self, message_obj: S2Message, wait_for_reception: bool = False) -> Optional[ReceptionStatus]:
        self.ensure_connected()

        payload = message_obj.to_json()
        key: Optional[str] = None
        waiter: Optional[asyncio.Future] = None

        if hasattr(message_obj, "to_dict"):
            message_id = message_obj.to_dict().get("message_id")
            if wait_for_reception and message_id is not None:
                key = normalize_id(message_id)
                waiter = asyncio.get_running_loop().create_future()
                self._reception_waiters[key] = waiter

        if self.verbose:
            print(f"--> {type(message_obj).__name__}: {payload}")

        try:
            await self.dbus_call("Message", "ss", [self.client_id, payload])
            if waiter is not None:
                return await asyncio.wait_for(waiter, timeout=10)
            return None
        finally:
            if key is not None:
                existing = self._reception_waiters.get(key)
                if existing is waiter:
                    self._reception_waiters.pop(key, None)

    async def send_reception(
        self,
        status: ReceptionStatusValues,
        src: Any,
        diagnostic_label: Optional[str] = None,
    ) -> None:
        if hasattr(src, "to_dict"):
            d = src.to_dict()
            if d.get("message_type") == "ReceptionStatus":
                return
            subject_message_id = normalize_id(d.get("message_id"))
        else:
            subject_message_id = normalize_id(src)

        if not subject_message_id or not self.connected:
            return

        await self.send_message(
            ReceptionStatus(
                subject_message_id=subject_message_id,
                status=status,
                diagnostic_label=diagnostic_label,
            ),
            wait_for_reception=False,
        )

    async def bootstrap(self) -> None:
        loop = asyncio.get_running_loop()
        self._bootstrap_handshake_future = loop.create_future()
        self._bootstrap_rm_details_future = loop.create_future()

        try:
            handshake = await asyncio.wait_for(self._bootstrap_handshake_future, timeout=60)
            versions = [str(v) for v in handshake.supported_protocol_versions]
            if S2_VERSION not in versions:
                raise S2CliError(
                    f"RM offered protocol versions {versions}; this CLI expects {S2_VERSION}."
                )

            await self.send_message(
                HandshakeResponse(
                    message_id=uuid.uuid4(),
                    selected_protocol_version=S2_VERSION,
                ),
                wait_for_reception=False,
            )

            await asyncio.wait_for(self._bootstrap_rm_details_future, timeout=60)
        finally:
            self._bootstrap_handshake_future = None
            self._bootstrap_rm_details_future = None

    async def wait_for_state(self, timeout: float = 15.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        while True:
            self.ensure_connected()

            need_sd = (
                self.active_control_type == ControlType.OPERATION_MODE_BASED_CONTROL
                and self.ombc_system_description is None
            )
            need_status = (
                self.active_control_type == ControlType.OPERATION_MODE_BASED_CONTROL
                and self.ombc_status is None
            )

            if not need_sd and not need_status:
                return

            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()

            self._state_event.clear()
            await asyncio.wait_for(self._state_event.wait(), timeout=remaining)

    async def drain_unsolicited(self, timeout: float = 0.05) -> None:
        self.ensure_connected()
        await asyncio.sleep(timeout)
        self.ensure_connected()

    async def select_control_type(self, control_type: ControlType) -> ReceptionStatus:
        if control_type == ControlType.OPERATION_MODE_BASED_CONTROL:
            self.ombc_system_description = None
            self.ombc_status = None
            self._state_event.set()

        reply = await self.send_message(
            SelectControlType(
                message_id=uuid.uuid4(),
                control_type=control_type,
            ),
            wait_for_reception=True,
        )

        if reply is None:
            raise S2CliError("No ReceptionStatus returned for SelectControlType.")
        if reply.status != ReceptionStatusValues.OK:
            detail = f": {reply.diagnostic_label}" if reply.diagnostic_label else ""
            raise S2CliError(f"SelectControlType was rejected with {enum_text(reply.status)}{detail}")

        self.active_control_type = control_type
        return reply

    async def send_ombc_instruction(
        self,
        operation_mode: OMBCOperationMode,
        abnormal_condition: bool,
    ) -> ReceptionStatus:
        reply = await self.send_message(
            OMBCInstruction(
                message_id=uuid.uuid4(),
                id=uuid.uuid4(),
                execution_time=utc_now(),
                operation_mode_factor=1.0,
                operation_mode_id=normalize_id(operation_mode.id),
                abnormal_condition=abnormal_condition,
            ),
            wait_for_reception=True,
        )
        if reply is None:
            raise S2CliError("No ReceptionStatus returned for OMBC.Instruction.")
        return reply

    async def wait_for_ombc_status_change(self, previous_active_mode_id: str, timeout: float = 3.0) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        while True:
            self.ensure_connected()

            current_active_mode_id = (
                normalize_id(self.ombc_status.active_operation_mode_id)
                if self.ombc_status is not None
                else ""
            )
            if current_active_mode_id and current_active_mode_id != previous_active_mode_id:
                return True

            remaining = deadline - loop.time()
            if remaining <= 0:
                return False

            self._state_event.clear()
            try:
                await asyncio.wait_for(self._state_event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return False


async def list_bus_names(bus: Any, message_cls: Any, message_type_cls: Any) -> list[str]:
    reply = await bus.call(
        message_cls(
            destination=DBUS_NAME,
            path=DBUS_PATH,
            interface=DBUS_NAME,
            member="ListNames",
        )
    )
    if reply.message_type == message_type_cls.ERROR:
        raise S2CliError(f"ListNames failed: {reply.error_name} {reply.body}")
    return list(reply.body[0])


async def get_name_owner(bus: Any, message_cls: Any, message_type_cls: Any, service_name: str) -> str:
    reply = await bus.call(
        message_cls(
            destination=DBUS_NAME,
            path=DBUS_PATH,
            interface=DBUS_NAME,
            member="GetNameOwner",
            signature="s",
            body=[service_name],
        )
    )
    if reply.message_type == message_type_cls.ERROR:
        raise S2CliError(f"GetNameOwner({service_name}) failed: {reply.error_name} {reply.body}")
    return str(reply.body[0])


async def try_discover(
    bus: Any,
    message_cls: Any,
    message_type_cls: Any,
    service_name: str,
) -> bool:
    reply = await bus.call(
        message_cls(
            destination=service_name,
            path=RM_PATH,
            interface=S2_IFACE,
            member="Discover",
            signature="",
            body=[],
        )
    )

    if reply.message_type != message_type_cls.METHOD_RETURN:
        raise S2CliError(f"Discover failed on {service_name}")
    if not reply.body:
        raise S2CliError(f"Discover returned empty body on {service_name}")

    return reply.body[0] is True


async def read_bus_item_value(
    bus: Any,
    message_cls: Any,
    message_type_cls: Any,
    service_name: str,
    path: str,
) -> Optional[Any]:
    reply = await bus.call(
        message_cls(
            destination=service_name,
            path=path,
            interface=BUSITEM_IFACE,
            member="GetValue",
        )
    )
    if reply.message_type == message_type_cls.ERROR or not reply.body:
        return None
    value = reply.body[0]
    return getattr(value, "value", value)


async def read_bus_item_text(
    bus: Any,
    message_cls: Any,
    message_type_cls: Any,
    service_name: str,
    path: str,
) -> Optional[str]:
    for iface in [BUSITEM_IFACE, S2_IFACE]:
        try:
            reply = await bus.call(
                message_cls(
                    destination=service_name,
                    path=path,
                    interface=iface,
                    member="GetText",
                    signature="",
                    body=[],
                )
            )
        except Exception:
            continue

        if reply.message_type == message_type_cls.ERROR:
            continue
        if not reply.body:
            return None

        value = reply.body[0]
        return value if isinstance(value, str) else str(value)

    return None


async def build_candidate(
    bus: Any,
    message_cls: Any,
    message_type_cls: Any,
    service_name: str,
) -> Optional[ServiceCandidate]:
    try:
        discovered = await try_discover(bus, message_cls, message_type_cls, service_name)
    except Exception:
        return None

    if not discovered:
        return None

    owner = await get_name_owner(bus, message_cls, message_type_cls, service_name)

    label_parts = [service_name]
    status_text = await read_bus_item_text(bus, message_cls, message_type_cls, service_name, RM_PATH)
    custom_name = await read_bus_item_value(bus, message_cls, message_type_cls, service_name, "/CustomName")
    product_name = await read_bus_item_value(bus, message_cls, message_type_cls, service_name, "/ProductName")
    device_instance = await read_bus_item_value(bus, message_cls, message_type_cls, service_name, "/DeviceInstance")

    label_parts.append(f"text='{status_text}'")
    human_name = custom_name or product_name
    if human_name:
        label_parts.append(f"name='{human_name}'")
    if device_instance is not None:
        label_parts.append(f"instance={device_instance}")

    return ServiceCandidate(
        service_name=service_name,
        owner=owner,
        label=" | ".join(label_parts),
    )


async def scan_s2_services(
    bus: Any,
    message_cls: Any,
    message_type_cls: Any,
    prefix: Optional[str] = None,
) -> list[ServiceCandidate]:
    names = await list_bus_names(bus, message_cls, message_type_cls)
    candidates = [name for name in names if name.startswith("com.victronenergy.")]
    if prefix:
        candidates = [name for name in candidates if prefix.lower() in name.lower()]

    results: list[ServiceCandidate] = []
    for name in candidates:
        try:
            candidate = await build_candidate(bus, message_cls, message_type_cls, name)
        except Exception:
            candidate = None
        if candidate is not None:
            results.append(candidate)

    results.sort(key=lambda item: item.service_name)
    return results


def available_control_types(details: Optional[ResourceManagerDetails]) -> list[ControlType]:
    if details is None:
        return []
    return list(details.available_control_types)


def current_ombc_mode(
    sd: Optional[OMBCSystemDescription],
    status: Optional[OMBCStatus],
) -> Optional[OMBCOperationMode]:
    if sd is None or status is None:
        return None
    active_id = normalize_id(status.active_operation_mode_id)
    for mode in sd.operation_modes:
        if normalize_id(mode.id) == active_id:
            return mode
    return None


def reachable_transitions(
    sd: Optional[OMBCSystemDescription],
    status: Optional[OMBCStatus],
) -> list[tuple[OMBCOperationMode, Transition]]:
    current = current_ombc_mode(sd, status)
    if sd is None or current is None:
        return []

    transitions: list[tuple[OMBCOperationMode, Transition]] = []
    current_id = normalize_id(current.id)
    by_id = {normalize_id(mode.id): mode for mode in sd.operation_modes}
    for transition in sd.transitions:
        if normalize_id(transition.from_) != current_id:
            continue
        target = by_id.get(normalize_id(transition.to))
        if target is not None:
            transitions.append((target, transition))
    return transitions


def print_power_measurement(session: S2Session) -> None:
    pm = session.power_measurement
    if pm is None:
        print("Latest PowerMeasurement: <none>")
        return
    print("Latest PowerMeasurement:")
    print(model_to_pretty_json(pm))


def print_status(session: S2Session) -> None:
    print("\n=== Session state ===")
    print(f"Service: {session.service.service_name}")
    if session.rm_details is not None:
        print(f"RM name: {session.rm_details.name}")
        offered = ", ".join(enum_text(ct) for ct in session.rm_details.available_control_types) or "<none>"
        print(f"Available control types: {offered}")
    print(f"Active control type: {enum_text(session.active_control_type) if session.active_control_type else '<none>'}")

    if session.active_control_type == ControlType.NOT_CONTROLABLE:
        print_power_measurement(session)

    if session.active_control_type == ControlType.OPERATION_MODE_BASED_CONTROL:
        active = current_ombc_mode(session.ombc_system_description, session.ombc_status)
        print(f"Active OMBC mode: {mode_label(active) if active else '<not yet reported>'}")
        if session.ombc_status is not None:
            print("Latest OMBC.Status:")
            print(model_to_pretty_json(session.ombc_status))


async def async_input(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


async def prompt_choice(prompt: str, options: list[str], allow_quit: bool = True) -> int:
    while True:
        print(prompt)
        for idx, option in enumerate(options, start=1):
            print(f"  {idx}. {option}")
        if allow_quit:
            print("  q. Quit")

        choice = (await async_input("> ")).strip().lower()

        if allow_quit and choice in {"q", "quit", "exit"}:
            raise KeyboardInterrupt()

        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(options):
                return index

        print("Invalid selection. Try again.\n")


def print_ombc_model(session: S2Session) -> None:
    sd = session.ombc_system_description
    if sd is None:
        print("OMBC.SystemDescription: <none>")
        return

    print("\n=== OMBC System Description ===")

    print("\nOperation modes:")
    if not sd.operation_modes:
        print("  <none>")
    else:
        active = current_ombc_mode(session.ombc_system_description, session.ombc_status)
        active_id = normalize_id(active.id) if active else None

        for mode in sd.operation_modes:
            marker = "*" if normalize_id(mode.id) == active_id else " "
            print(f" {marker} {normalize_id(mode.id)}")
            print(f"     {mode_label(mode)}")

    if session.verbose:
        print("\nTransitions:")
        if not sd.transitions:
            print("  <none>")
        else:
            by_id = {normalize_id(mode.id): mode for mode in sd.operation_modes}

            for tr in sd.transitions:
                from_id = normalize_id(tr.from_)
                to_id = normalize_id(tr.to)
                from_mode = by_id.get(from_id)
                to_mode = by_id.get(to_id)

                from_label = mode_label(from_mode) if from_mode else from_id
                to_label = mode_label(to_mode) if to_mode else to_id

                extra: list[str] = []
                if getattr(tr, "abnormal_condition_only", False):
                    extra.append("abnormal_condition_only=True")
                if getattr(tr, "start_timers", None):
                    extra.append("start_timers=" + ",".join(normalize_id(x) for x in tr.start_timers))
                if getattr(tr, "blocking_timers", None):
                    extra.append("blocking_timers=" + ",".join(normalize_id(x) for x in tr.blocking_timers))

                duration = getattr(tr, "transition_duration", None)
                if duration is not None:
                    duration_text = getattr(duration, "root", duration)
                    extra.append(f"transition_duration={duration_text}")

                suffix = f" [{' | '.join(extra)}]" if extra else ""
                print(f"  {normalize_id(tr.id)}: {from_label} -> {to_label}{suffix}")

        print("\nTimers:")
        timers = getattr(sd, "timers", None)
        if not timers:
            print("  <none>")
        else:
            for timer in timers:
                print(f"  {model_to_pretty_json(timer)}")


async def ombc_menu(session: S2Session) -> None:
    try:
        await session.wait_for_state(timeout=15)
    except asyncio.TimeoutError:
        print("Timed out waiting for OMBC.SystemDescription / OMBC.Status.")
        return

    print_ombc_model(session)

    first_iteration = True

    while True:
        await session.drain_unsolicited()

        if first_iteration:
            first_iteration = False
        else:
            print_status(session)

        options: list[str] = ["Refresh"]
        actions: list[tuple[str, Optional[tuple[OMBCOperationMode, Transition]]]] = [("refresh", None)]

        for mode, transition in reachable_transitions(session.ombc_system_description, session.ombc_status):
            abnormal = bool(transition.abnormal_condition_only)
            warnings: list[str] = []
            if abnormal:
                warnings.append("REQUIRES abnormal_condition=True")
            if getattr(mode, "abnormal_condition_only", False):
                warnings.append("target mode has abnormal_condition_only=True")
            if transition.blocking_timers:
                warnings.append(
                    "blocking_timers=" + ",".join(normalize_id(item) for item in transition.blocking_timers)
                )

            extra = f" [{' | '.join(warnings)}]" if warnings else ""
            options.append(
                ("ABNORMAL: " if abnormal else "") +
                f"{mode_label(mode)}" +
                (f" via transition {normalize_id(transition.id)}{extra}" if session.verbose else "")
            )
            actions.append(("transition", (mode, transition)))

        options.append("Back to control types")
        actions.append(("back", None))

        options.append("Disconnect and go back to services")
        actions.append(("disconnect", None))

        index = await prompt_choice("\nChoose a target OMBC transition:", options, allow_quit=True)
        action, payload = actions[index]

        if action == "refresh":
            print_status(session)
            continue

        if action == "back":
            return

        if action == "disconnect":
            await session.disconnect()
            raise BackToServices()

        mode, transition = payload
        abnormal = bool(transition.abnormal_condition_only)

        if abnormal:
            print("\n*** WARNING ***")
            print("This transition has abnormal_condition_only=True.")
            print("The CLI will therefore send OMBC.Instruction with abnormal_condition=True.")
            print("****************\n")

        previous_status_id = normalize_id(session.ombc_status.active_operation_mode_id) if session.ombc_status else ""

        reply = await session.send_ombc_instruction(mode, abnormal_condition=abnormal)
        status_text = enum_text(reply.status)
        detail = f" ({reply.diagnostic_label})" if reply.diagnostic_label else ""
        print(f"Instruction result: {status_text}{detail}")

        changed = await session.wait_for_ombc_status_change(previous_status_id, timeout=3.0)
        if not changed:
            print("Note: no updated OMBC.Status received within 3 seconds, showing current options anyway.")


async def no_control_menu(session: S2Session) -> None:
    while True:
        await session.drain_unsolicited()
        print_status(session)

        options = [
            "Refresh",
            "Back to control types",
            "Disconnect and go back to services",
        ]
        index = await prompt_choice("\nChoose an action:", options, allow_quit=True)

        if index == 0:
            continue
        if index == 1:
            return
        if index == 2:
            await session.disconnect()
            raise BackToServices()


async def control_type_menu(session: S2Session) -> None:
    while True:
        await session.drain_unsolicited()
        print_status(session)

        offered = available_control_types(session.rm_details)
        if not offered:
            print("RM did not report any available control types.")
            return

        options = ["Refresh"] + [enum_text(ct) for ct in offered]
        options.append("Disconnect and go back to services")

        index = await prompt_choice("\nChoose a control type:", options, allow_quit=True)

        if index == 0:
            continue

        if index == len(options) - 1:
            await session.disconnect()
            raise BackToServices()

        selected = offered[index - 1]
        reply = await session.select_control_type(selected)
        status_text = enum_text(reply.status)
        detail = f" ({reply.diagnostic_label})" if reply.diagnostic_label else ""
        print(f"SelectControlType result: {status_text}{detail}")

        if selected == ControlType.OPERATION_MODE_BASED_CONTROL:
            await ombc_menu(session)
        elif selected == ControlType.NOT_CONTROLABLE:
            await no_control_menu(session)
        else:
            print(f"No interactive flow implemented for {enum_text(selected)} yet.")


async def run_service_session(
    bus: Any,
    message_cls: Any,
    message_type_cls: Any,
    service: ServiceCandidate,
    args: argparse.Namespace,
    client_id: str,
) -> None:
    async with S2Session(
        bus=bus,
        message_cls=message_cls,
        message_type_cls=message_type_cls,
        service=service,
        client_id=client_id,
        keepalive_s=args.keepalive,
        verbose=args.verbose,
    ) as session:
        await session.connect()
        await session.bootstrap()
        print_status(session)
        await control_type_menu(session)


async def async_main(args: argparse.Namespace) -> int:
    BusType, Message, MessageType, MessageBus = load_dbus()
    bus_type = BusType.SYSTEM if args.dbus == "system" else BusType.SESSION
    bus = await MessageBus(bus_type=bus_type).connect()

    print("Collecting services ...")
    while True:
        services = await scan_s2_services(bus, Message, MessageType, prefix=args.filter)
        if not services:
            print("No S2-capable services found on D-Bus.")
            return 1

        options = ["Refresh"] + [item.label for item in services]

        index = await prompt_choice(
            "\nSelect an S2-capable service:",
            options,
            allow_quit=True,
        )

        if index == 0:
            print("Refreshing services ...")
            continue

        service = services[index - 1]
        print(f"\nConnecting to {service.label}\n")

        try:
            session_client_id = f"{args.client_id}-{uuid.uuid4().hex[:8]}"
            await run_service_session(bus, Message, MessageType, service, args, session_client_id)
        except BackToServices as exc:
            if str(exc):
                print(f"\n{exc}\n")
            continue

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dbus", choices=("system", "session"), default="system", help="Which D-Bus to use.")
    parser.add_argument("--filter", default=None, help="Case-insensitive substring filter for service names.")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="S2 client id for Connect/Message calls.")
    parser.add_argument("--keepalive", type=int, default=DEFAULT_KEEPALIVE_S, help="KeepAlive interval in seconds.")
    parser.add_argument("--verbose", action="store_true", help="Print raw incoming/outgoing S2 JSON payloads.")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except S2CliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
