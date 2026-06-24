# Venus S2 Tools

Command line tools for Victron S2 over D-Bus communication.

1. `s2-cem-cli.py` - Interactive command line tool to connect to S2 Resource Manager using Victron S2 over D-Bus communication.
1. `s2-sniffer.py` - Passive listener for all S2 messages on D-Bus.
1. `s2-dbus-ws-bridge.py` - Bridge between Victron S2 over D-Bus and S2 over WebSocket.
1. `dbus-spy` - Debug tool to inspect all Victron D-Bus services.

A docker image can be built with the tools included + either a D-Bus bus running or connecting to the bus of a GX device.

## s2-cem-cli.py

Interactive command line tool to connect to S2 Resource Manager using Victron S2 over D-Bus communication.

### What it does

- Scans D-Bus for services exposing `/S2/0/Rm`
- Lets you select a service
- Connects through `com.victronenergy.S2`
- Performs the S2 handshake using `s2python`
- Reads `ResourceManagerDetails`
- Lets you select one of the offered control types
- For OMBC:
  - Waits for `OMBC.SystemDescription` and `OMBC.Status`
  - Prints the reported status
  - Shows reachable transitions from the current operation mode
  - Highlights transitions with `abnormal_condition_only=True`
  - Sends `OMBC.Instruction` with `abnormal_condition=True` for those transitions

### Requirements

- Python 3.11+
- `s2python`
- either `dbus-fast` or `dbus-next`

### Run

```bash
python3 s2-cem-cli.py
```

Optional flags:

```bash
python3 s2-cem-cli.py --dbus system --filter evcharger --verbose
```

### Notes

- The implementation follows the same S2 message flow used by `venus-opportunity-loads`.
- The tool uses typed `s2python` messages
- Non-OMBC control types can be selected, but only OMBC currently has an interactive post-selection flow.

---

## s2-sniffer.py

Passive listener for all S2 messages on D-Bus. Useful for debugging and monitoring S2 protocol traffic without connecting to a service.

### What it does

- Passively captures both message directions: RM → CEM (signals) and CEM → RM (method calls)
- Displays each message with timestamp, sender, receiver, and S2 JSON payload
- Resolves D-Bus service names correctly (handles transient owner changes on service restart)
- Filters by service name or message type
- Can hide specific message types (e.g., ReceptionStatus, PowerMeasurement) to reduce noise
- Truncates long JSON output to protect terminal scrollback (configurable)
- Optional full-log file to capture complete messages while keeping terminal compact

### Run

```bash
python3 s2-sniffer.py
```

Optional flags:

```bash
python3 s2-sniffer.py --service cem --hide-reception-status --hide-power-measurement
python3 s2-sniffer.py --message-type OMBC --full-log-file messages.log
python3 s2-sniffer.py --dbus session --max-preview-lines 0  # Unlimited JSON per message
```

### Notes

- Useful for protocol debugging and analysis without modifying system state.
- Requires D-Bus eavesdropping support (may require system policy configuration on some systems).

## s2-dbus-ws-bridge.py

Bridge between Victron S2 over D-Bus and S2 over WebSocket.

### What it does

- Create a D-Bus service with the `/S2/0/Rm` path
- Create a WebSocket server
- Forward messages between the D-Bus service and a WebSocket connection
- Log all messages with their direction

### Run

```bash
python3 s2-dbus-ws-bridge.py
```

Optional arguments:  
```bash
--dbus session|system
--auth anonymous|external
--port 1234
```

## Docker

### Build the docker image

```bash
docker build -t venus-s2-tools-image .
```

### Run the docker image with its own dbus

```bash
docker run -it --rm --name venus-s2-tools -p 8765:8765 venus-s2-tools-image
```

Port 8765 is forwarded to 8765 on the host, to be used with `s2-dbus-ws-bridge.py`.
Adjust if you need a different port.

Run tools with:  
```bash
./s2-cem-cli.py ...
./s2-sniffer.py ...
./s2-dbus-ws-bridge.py ...
dbus-spy
```

### Run the docker image with a tunnel to a GX device

In the GX's settings, set `com.victronenergy.settings/Settings/Services/InsecureDbusOverTcp` to `1`.

```bash
docker run -it --rm --name venus-s2-tools -p 8765:8765 -e DBUS_SYSTEM_BUS_ADDRESS="tcp:host=<gx_ip>,port=78" venus-s2-tools-image
```

Run tools with:
```bash
./s2-cem-cli.py --auth anonymous ...
./s2-sniffer.py --auth anonymous ...
./s2-dbus-ws-bridge.py --auth anonymous ...
dbus-spy
```

### Opening another shell

```bash
docker exec -it venus-s2-tools bash
```