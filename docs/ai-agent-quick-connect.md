# AI agent quick connect

Status: **read-only beta**

ShakerProxy packages a read-only MCP bridge at `/usr/bin/shakerproxy-mcp`. The quickest safe connection is three steps and keeps the API token on the ShakerProxy sensor.

## 1. Create the investigator token in the Web UI

Open **Integrations → AI agents** and choose whether the AI runs on the sensor or another computer.

The wizard creates a 24-hour token directly after fresh administrator-password verification. The scopes are fixed to exactly:

```text
system:read
devices:read
traffic:read
```

The wizard does not offer write scopes. The API marks the secret `display-once`; the UI shows it only after successful creation, automatically removes it from the page after ten minutes, and provides an immediate **Hide now** control.

Do not paste the token into an AI prompt, MCP JSON, command-line argument, or shell history.

## 2. Save it on the sensor

Run as the non-root Linux account that will own the MCP bridge:

```bash
/usr/bin/shakerproxy-mcp setup
```

The command prompts for the display-once token, disables terminal echo when possible, and writes the credential atomically to the user's ShakerProxy configuration directory with private permissions. It refuses an unsafe token path or symlink destination.

For an AI client on another workstation, perform setup over an interactive SSH connection to the sensor:

```bash
ssh -t analyst@shakerproxy-sensor /usr/bin/shakerproxy-mcp setup
```

The token stays on the sensor; remote MCP does not require copying the token to the Mac or workstation.

## 3. Verify before connecting the AI

Run:

```bash
/usr/bin/shakerproxy-mcp doctor
```

or remotely:

```bash
ssh -t analyst@shakerproxy-sensor /usr/bin/shakerproxy-mcp doctor
```

Doctor verifies the private token file, management TLS trust, API authentication, and the bounded agent evidence overview. A successful connection can still report `EVIDENCE DEGRADED` when ingestion or analyzers are not ready; that is different from an authentication failure.

Generate secret-free MCP configuration with:

```bash
/usr/bin/shakerproxy-mcp config local
```

or:

```bash
/usr/bin/shakerproxy-mcp config ssh analyst@shakerproxy-sensor
```

The Web UI generates the equivalent JSON interactively and provides copy buttons. The JSON never contains the API token.

## Remote account requirements

For remote MCP, prefer a dedicated or otherwise constrained Linux account that:

- uses SSH public-key authentication;
- has no sudo permission;
- has no Docker socket access;
- owns only its private MCP token file;
- cannot write ShakerProxy binaries, configuration, management CA, or interception CA;
- does not emit login banners to stdout for the MCP restricted command.

Where practical, restrict the SSH key to `/usr/bin/shakerproxy-mcp`.

## What the AI receives

Seventeen read-only tools: `list_devices`, `find_device`, `device_report`, `device_activity`, `compare_runs`, `protocols`, `search_traffic`, `traffic_summary`, `dns_lookups`, `tls_issues`, `http_requests`, `test_sessions`, `system_status`, `dns_visibility`, `visibility_coverage`, `vpn_devices`, and `wifi_activity`. Devices can be named by friendly name, IP address, MAC address, or device ID, and every result includes plain-language summary lines.

Try asking:

- "What does my TV talk to?" — the agent finds the device and reads its report: domains with the company behind them and what they are for (telemetry, advertising, …).
- "Is the camera secure?" — the report's findings (for example unencrypted HTTP, outdated TLS, telnet, or accepting untrusted certificates), each with evidence and a fix.
- "What changed between firmware 1.2 and 1.3?" — the agent lists test sessions and compares the two runs: new domains, new protocols, new or resolved findings.

For the best answers, run each firmware or app version as a test session (Tests in the Web UI, or `shakerproxy test start <device>`), and record whether the ShakerProxy CA is installed on the device.

It does **not** expose decrypted HTTP bodies, sensitive request/response headers, raw PCAP, TLS key logs, CA private keys, shell commands, network changes, capture mutation, policy mutation, or deletion tools.

Every MCP evidence result labels captured strings as untrusted data rather than instructions.

For the complete protocol, limits, tool schemas, and threat model, see `docs/mcp-agent-integration.md`.
