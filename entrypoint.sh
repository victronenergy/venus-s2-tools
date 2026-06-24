#!/bin/bash
set -e

if [ -z "$DBUS_SYSTEM_BUS_ADDRESS" ]; then
    echo "No system D-Bus configured, starting private system bus..."

    mkdir -p /run/dbus

    # Start system bus
    dbus-daemon \
        --system \
        --nofork \
        --print-address &

    export DBUS_SYSTEM_BUS_ADDRESS="unix:path=/run/dbus/system_bus_socket"

    echo "Started system bus:"
    echo "$DBUS_SYSTEM_BUS_ADDRESS"
else
    echo "Using existing D-Bus:"
    echo "$DBUS_SYSTEM_BUS_ADDRESS"
fi

exec "$@"