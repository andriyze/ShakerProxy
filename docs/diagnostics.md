# Appliance diagnostics

The local `shakerproxy doctor` command and `GET /api/v1/system/diagnostics` return
the same schema-1 report. The API endpoint requires an authenticated local
administrator session. The dashboard refreshes it every 30 seconds in normal
operation and every 60 seconds while CPU, memory, or disk pressure is degraded.

Analyzer broker health is intentionally a separate authenticated report at
`GET /api/v1/analyzers/status`. It reads the internal-only Zeek and Suricata
maintenance brokers without opening a host port, reports fresh idle, actively
scanning, and stale states, and isolates a failed engine behind a generic
unavailable result. The dashboard refreshes this report every 30 seconds and
shows bounded completed-capture/event totals plus Suricata ruleset provenance.

The report always contains exactly these checks in stable order:

1. interfaces
2. firewall
3. routes
4. DNS resolver configuration
5. fixed service-port ownership for 53, 443, 853, and 8443
6. kernel forwarding
7. managed DHCPv4 expectation
8. Docker systemd state
9. gateway/capture capability state
10. disk reserve and inode capacity
11. CPU, memory, and disk resource-pressure stage
12. time synchronization
13. capture session state and analyzer-feed evictions
14. capture-worker packet drops

Each check is `PASS`, `WARNING`, `FAIL`, or `UNKNOWN`. Any failure makes the
overall result `FAIL`. Warnings or unavailable evidence make the overall result
`WARNING`; `UNKNOWN` is never treated as success.

The daemon reads only fixed kernel/configuration paths and invokes only fixed
`systemctl is-active` or `timedatectl show` commands with bounded output. It
does not accept a caller-selected path, command, or service. It does not open
the Docker socket, enumerate arbitrary containers, send DNS traffic, restart a
service, or alter the packet path. Docker being stopped therefore degrades the
application-stack check without making the independent forwarding path fail.

The resource-pressure check combines Linux CPU PSI `avg10`, `MemAvailable`, and
the managed capture filesystem reserve. At degraded pressure, the browser
reduces diagnostic polling to 60 seconds. At critical pressure, the host daemon
also refuses new captures. Existing routing, emergency recovery, management,
and already-running capture state are preserved; the evaluator never kills a
process or rewrites network state. Missing `/proc` or filesystem evidence is
`UNKNOWN`, never healthy. These thresholds are conservative safety controls,
not a reference-hardware capacity certification.

`GET /api/v1/system/ports` and `shakerproxy ports` expose the same read-only fixed
port plan. A `systemd-resolved` listener on a loopback address such as
`127.0.0.53` is classified as safe to preserve: a future ShakerProxy resolver must
bind only the selected lab address. Any unrelated owner or wildcard bind is a
conflict requiring review. The planner never stops or reconfigures the owner.

The dashboard's **Run explicit connectivity probe** button and
`shakerproxy probe-connectivity` compare two fixed IPv4 paths: an HTTPS `HEAD /`
request dialed directly to `1.1.1.1:443` with the TLS identity
`one.one.one.one`, and a TCP connect to `1.1.1.1:53`. The probe does not use
DNS, sends no DNS question, accepts no caller-selected destination, has a
seven-second host deadline, and the HTTP endpoint is limited to one run per 15
seconds. `restricted_port_53` means the verified HTTPS path worked while TCP
port 53 did not; it does not prove UDP behavior or a provider policy.

The current report intentionally shows only capture-worker drop counters.
Direct Suricata capture/kernel drops, Zeek packet-loss telemetry, per-interface
byte counters, conntrack utilization, write latency, and container restart
counts remain future observability work and must not be inferred from `PASS` on
another check. Analyzer broker `HEALTHY` likewise means recent broker progress,
not zero packet loss inside either engine.
