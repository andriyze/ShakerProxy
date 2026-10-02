# Documentation map

ShakerProxy is pre-alpha. The [capability registry](../schemas/feature-flags.yaml)
and the [platform support matrix](../schemas/support-matrix.yaml) define what the
project currently claims; [capability claims](capabilities.md) explains how to
read them. Design prose and passing source tests do not promote a capability
beyond those records.

## Start here

- [Device testing quick start](device-testing-quickstart.md) walks through
  connecting a phone or TV, decrypting its HTTPS or testing certificate
  validation, blocking its internet or a domain, and reading its report.
- [Development quick start](quick-start.md) covers the non-routing local stack
  and the `make dev-demo` demo lab.
- [Installation and release lifecycle](installation.md) separates the current
  source workflow from the not-yet-published signed installer.
- [AI agent quick connect](ai-agent-quick-connect.md) is the three-step path for
  creating a read-only token, saving it securely on the sensor, verifying the
  connection, and generating local or SSH MCP client configuration.
- [Architecture](architecture.md) explains the privileged host/application
  boundary.
- [Capability claims](capabilities.md) defines feature status and platform
  certification language.
- [Protocol support](protocol-support.md) states capture, classification,
  proxy, and decryption boundaries separately.
- [Threat model](threat-model.md) records the security assumptions and
  non-goals.

## Operate and evaluate

- [Networking and guarded activation](networking.md)
- [Wi-Fi access point](wifi-access-point.md)
- [Wi-Fi visibility](wifi-visibility.md)
- [IPv6 in the lab](ipv6.md)
- [DNS forwarding and encrypted-DNS policy](dns-forwarding.md)
- [TLS interception, certificate onboarding, and bypass](tls-interception.md)
- [Protocol discovery](protocol-discovery.md)
- [Capture, analysis, retention, and deletion](capture-and-storage.md)
- [Device inventory and correction](device-inventory.md)
- [Device reports, findings, and test runs](device-reports.md)
- [Diagnostics](diagnostics.md)
- [Native detections and pressure controls](native-detections.md)
- [Cases and evidence holds](cases-and-holds.md)
- [Scoped API tokens and forwarding](integrations.md)
- [AI agent quick connect](ai-agent-quick-connect.md)
- [MCP agent integration architecture](mcp-agent-integration.md)
- [MCP evidence-readiness semantics](mcp-evidence-readiness.md)
- [Decrypted HTTP content retention](decrypted-content-retention.md)
- [Management TLS and authority separation](management-tls.md)
- [Signed rules and catalog lifecycle](signed-content.md)
- [Recovery objectives](recovery-objectives.md)
- [Appliance-wide configuration lock](configuration-lock.md)

## Build and release

- [Contributing](../CONTRIBUTING.md)
- [Signed release process](release-process.md)
- [Suricata ruleset maintenance](suricata-rules.md)
- [Dependency license matrix](licenses/dependency-matrix.md)
- [Security policy](../SECURITY.md)
- [Third-party notices](../THIRD_PARTY_NOTICES.md)

Architecture decisions live under [`docs/adr`](adr/). Executable and retained
test descriptions live under [`docs/testing`](testing/); the Ubuntu 26.04
shared-VPS boundary is recorded in
[UBU2604-001](testing/evidence/foundation/UBU2604-001/README.md). Run
`make docs-check` for the fast documentation-only validation or `make verify`
for the complete portable repository gate.
