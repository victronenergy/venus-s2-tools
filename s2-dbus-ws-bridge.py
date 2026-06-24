#!/usr/bin/env python3
import argparse
import sys
import os
import asyncio
import websockets
from aiovelib.service import Service
from aiovelib.s2 import S2ServerItem

dbus_server = None
ws_server = None
current_client = None

def load_dbus():
    try:
        from dbus_fast import BusType, Message, MessageType
        from dbus_fast.aio import MessageBus
        from dbus_fast.auth import AuthAnonymous
        return BusType, Message, MessageType, MessageBus, AuthAnonymous
    except ImportError:
        try:
            from dbus_next import BusType, Message, MessageType, AuthAnonymous
            from dbus_next.aio import MessageBus
            from dbus_next.auth import AuthAnonymous
            return BusType, Message, MessageType, MessageBus, AuthAnonymous
        except ImportError as exc:
            raise S2CliError(
                "Neither dbus-fast nor dbus-next is available. Install one of them on the target system."
            ) from exc

async def handler(websocket):
    global current_client
    current_client = websocket
    print("New WebSocket client connected")
    try:
        async for message in websocket:
            print(f"websocket -> dbus: {message}")
            if dbus_server.is_connected:
                try:
                    dbus_server._send_message(message)
                except Exception as e:
                    print(f"Error sending message to D-Bus: {e}")
    except websockets.exceptions.ConnectionClosed:
        print("WebSocket connection closed")
    finally:
        current_client = None

async def onMessageFromDbus(message):
    print(f"dbus -> websocket: {message}")
    if current_client is not None:
        try:
            await current_client.send(message)
        except Exception as e:
            print(f"Error sending message to WebSocket client: {e}")

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dbus", choices=("system", "session"), default="system", help="Which D-Bus to use.")
    parser.add_argument("--auth", choices=("external", "anonymous"), default="external", help="Which D-Bus auth method to use.")
    parser.add_argument("--port", type=int, default=8765, help="KeepAlive interval in seconds.")
    return parser

async def main():
    global dbus_server
    global ws_server

    parser = build_arg_parser()
    args = parser.parse_args()

    BusType, Message, MessageType, MessageBus, AuthAnonymous = load_dbus()
    bus_type = BusType.SYSTEM if args.dbus == "system" else BusType.SESSION
    auth = AuthAnonymous() if args.auth == "anonymous" else None
    bus = await MessageBus(bus_type=bus_type, auth=auth).connect()

    service = Service(bus, f'com.victronenergy.s2bridge.port_{args.port}')
    await service.register()

    dbus_server = S2ServerItem('/S2/0/Rm')
    service.add_item(dbus_server)
    dbus_server._on_s2_message = onMessageFromDbus
    await dbus_server.set_ready()

    ws_server = await websockets.serve(handler, None, 8765)
    print(f"WebSocket server running on ws://localhost:{args.port}")
    await asyncio.gather(ws_server.wait_closed(), bus.wait_for_disconnect())

if __name__ == "__main__":
    asyncio.run(main())