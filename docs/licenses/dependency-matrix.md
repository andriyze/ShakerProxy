# Dependency license matrix

[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) is the complete, human-readable credit list:
authors, upstream projects, licences and how each component is used. This matrix records where
each dependency's version is pinned and what remains to be done before a public release.

| Dependency | Use | Version source | License status |
|---|---|---|---|
| ShakerProxy first-party source | Gateway, control API, UI, ingestion, host tooling, rules, catalogs | Repository source tree | AGPL-3.0-only unless a file explicitly states otherwise |
| Go modules linked into shipped binaries | pgx, MCP Go SDK, jsonschema-go, segmentio, uritemplate, golang.org/x | `go.mod`, `go.sum` | Verified from each module's `LICENSE`: MIT, BSD-3-Clause; the MCP SDK is MIT transitioning to Apache-2.0 and its upstream `LICENSE` is preserved |
| Public Suffix List (via golang.org/x/net) | Registrable-domain grouping in device reports | `go.mod` (`golang.org/x/net` v0.42.0) | MPL-2.0 data embedded in a BSD-3-Clause module |
| Web UI runtime (react, react-dom, scheduler) | Shipped UI bundle | `apps/web-ui/package-lock.json` | MIT (verified from the lock file); build-time packages are not shipped |
| Zeek | Passive analysis image | `versions.lock.yaml` (8.2.1 digest) | BSD-3-Clause |
| Suricata | IDS/flow analysis image | `versions.lock.yaml` (8.0.6 digest) | GPL-2.0-only; each release must publish or offer the corresponding source |
| mitmproxy | TLS interception image | `versions.lock.yaml` (12.2.3 digest) | MIT |
| PostgreSQL, Caddy, nginx, distroless | Application runtime images | `versions.lock.yaml`, Dockerfiles | PostgreSQL License, Apache-2.0, BSD-2-Clause, Apache-2.0 |
| Ubuntu host packages (Kea, hostapd, radvd, dumpcap, Docker, …) | Host runtime, installed from Ubuntu's archive | `packaging/deb/control.in` | Their own licences; not redistributed by ShakerProxy |
| ShakerProxy cleartext Suricata policy | Ten narrow cleartext-service policy alerts | `apps/analyzer-worker/suricata-ruleset.json` | AGPL-3.0-only first-party |

Release gate: every published image carries an SBOM and provenance attestation, and this matrix
and the notices file are re-checked against that SBOM before the release is tagged.
