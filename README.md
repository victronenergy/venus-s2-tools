# Venus S2 Tools

Command line tools for Victron S2 over D-Bus communication.

## s2_cem_cli.py

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
python3 s2_cem_cli.py
```

Optional flags:

```bash
python3 s2_cem_cli.py --dbus system --filter evcharger --verbose
```

### Notes

- The implementation follows the same S2 message flow used by `venus-opportunity-loads`.
- The tool uses typed `s2python` messages
- Non-OMBC control types can be selected, but only OMBC currently has an interactive post-selection flow.

---

## s2_sniffer.py

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
python3 s2_sniffer.py
```

Optional flags:

```bash
python3 s2_sniffer.py --service cem --hide-reception-status --hide-power-measurement
python3 s2_sniffer.py --message-type OMBC --full-log-file messages.log
python3 s2_sniffer.py --dbus session --max-preview-lines 0  # Unlimited JSON per message
```

### Notes

- Useful for protocol debugging and analysis without modifying system state.
- Requires D-Bus eavesdropping support (may require system policy configuration on some systems).
