# Third-party software and data

ShakerProxy stands on the work of many open-source networking and security projects. This file
credits the engines, system tools, libraries and data sets that ShakerProxy bundles in its container
images, compiles into its binaries, relies on from the host operating system, or contacts at
runtime, together with their authors and licences.

Each component remains under its own licence. Nothing here changes those terms, and ShakerProxy's own
[AGPL-3.0-only licence](LICENSE) does not apply to them. Where a licence requires it, the full
licence text ships with the component: inside container images (for Debian and Alpine packages
under `/usr/share/doc/<package>/copyright` or `/usr/share/licenses`, for Python packages in their
`*.dist-info` directory), in the Ubuntu packages the host installs, and for Go modules in the
module source recorded by `go.sum`. Release images are built with SBOM and provenance attestations
(`docker buildx build --sbom=true --provenance=mode=max` in `packaging/build-push-images.sh`).

To obtain the corresponding source for a GPL- or LGPL-licensed component in a published image,
use the upstream URL and the exact version or image digest pinned in `versions.lock.yaml` and the
Dockerfiles listed below, or open an issue and we will provide it.

## Traffic analysis and interception engines (container images)

| Component | Author / maintainer | Upstream | Licence | How ShakerProxy uses it |
|---|---|---|---|---|
| Zeek 8.2.1 | The Zeek Project (International Computer Science Institute and contributors) | https://zeek.org | BSD-3-Clause | Base of the Zeek analyzer image (`zeek/zeek`, digest in `versions.lock.yaml`); analyzes closed capture segments into connection, DNS, TLS and HTTP logs |
| Suricata 8.0.6 | Open Information Security Foundation (OISF) | https://suricata.io | GPL-2.0-only | Base of the Suricata analyzer image (`jasonish/suricata`, digest in `versions.lock.yaml`); flow, protocol and alert analysis with ShakerProxy's own ruleset |
| Suricata container image | Jason Ish | https://github.com/jasonish/docker-suricata | MIT (build files); Suricata and packages under their own licences | Upstream image the Suricata analyzer is built on |
| mitmproxy 12.2.3 | Aldo Cortesi, Maximilian Hils and contributors | https://mitmproxy.org | MIT | Base of the interception image (`mitmproxy/mitmproxy`); transparent TLS interception with ShakerProxy's addon |

## Application services (container images)

| Service | Author / maintainer | Upstream | Licence | How ShakerProxy uses it |
|---|---|---|---|---|
| PostgreSQL 16.15 | PostgreSQL Global Development Group | https://www.postgresql.org | PostgreSQL License | Event and inventory database (`postgres`, digest-pinned) |
| Caddy 2.10.2 | Matt Holt and the Caddy authors | https://caddyserver.com | Apache-2.0 | HTTPS edge in front of the web UI and API |
| nginx 1.29.1 | F5, Inc. and NGINX contributors | https://nginx.org | BSD-2-Clause | Serves the built web UI inside its image |
| Distroless static (Debian 12) | Google LLC | https://github.com/GoogleContainerTools/distroless | Apache-2.0; bundled Debian files under their own licences | Minimal runtime base for the Go service images |
| Alpine Linux base (in the Caddy and nginx images) | Alpine Linux contributors | https://alpinelinux.org | Per package (musl libc: MIT; BusyBox: GPL-2.0) | Base operating system of those upstream images |

## Host software (Ubuntu packages the installer depends on)

These are installed from Ubuntu's archive by the `shakerproxy-host` package (Depends/Recommends) and
invoked at runtime; ShakerProxy does not redistribute them.

| Component | Upstream | Licence | How ShakerProxy uses it |
|---|---|---|---|
| Docker Engine, containerd and Docker Compose v2 | https://www.docker.com | Apache-2.0 | Runs the application containers |
| Kea DHCPv4 server | Internet Systems Consortium, https://www.isc.org/kea | MPL-2.0 | DHCP for the lab network |
| hostapd and iw (optional) | Jouni Malinen and contributors, https://w1.fi/hostapd; https://wireless.wiki.kernel.org | BSD-3-Clause; ISC | Wi-Fi access point and radio capability detection |
| radvd (optional) | Reuben Hawkins and contributors, https://radvd.litech.org | radvd licence (BSD-style) | IPv6 router advertisements for the lab |
| Wireshark `dumpcap` (`wireshark-common`) | The Wireshark developers, https://www.wireshark.org | GPL-2.0-or-later | Packet capture into rotating PCAPNG files |
| iproute2, iptables, nftables | Linux networking developers and the netfilter project | GPL-2.0-or-later | Interfaces, routing, NAT and filtering |
| Netplan | Canonical Ltd., https://netplan.io | GPL-3.0 | Persistent interface configuration |
| systemd, util-linux, procps | Their respective projects | LGPL-2.1-or-later / GPL-2.0-or-later | Service management and host inspection |
| curl, jq, OpenSSL, zstd | Daniel Stenberg; jq contributors; OpenSSL Project; Meta Platforms | curl licence; MIT; Apache-2.0; BSD-3-Clause or GPL-2.0 | Installer downloads, JSON handling, signature checks, bundle decompression |
| `ieee-data` | IEEE Registration Authority data, packaged by Debian/Ubuntu | See `/usr/share/doc/ieee-data/copyright` | MAC vendor lookup; read from `/var/lib/ieee-data` at runtime |

## Go libraries compiled into ShakerProxy binaries

Exactly the modules below are linked into the shipped binaries (`go list -deps ./apps/... ./host/...`);
versions are pinned in `go.mod` and `go.sum`. The Go standard library (BSD-3-Clause, The Go
Authors) is statically linked into every binary.

| Module | Author / maintainer | Licence |
|---|---|---|
| github.com/jackc/pgx/v5 v5.10.0, pgpassfile, pgservicefile, puddle/v2 | Jack Christensen | MIT |
| github.com/modelcontextprotocol/go-sdk v1.7.0 | Model Context Protocol contributors | MIT, transitioning to Apache-2.0 (non-specification documentation CC-BY-4.0); the upstream `LICENSE` is preserved as published |
| github.com/google/jsonschema-go v0.4.3 | JSON Schema Go Project Authors | MIT |
| github.com/segmentio/asm v1.1.3, github.com/segmentio/encoding v0.5.4 | Segment | MIT |
| github.com/yosida95/uritemplate/v3 v3.0.2 | Kohei Yoshida | BSD-3-Clause |
| golang.org/x/crypto, net, oauth2, sync, sys, text, time | The Go Authors | BSD-3-Clause |

## Web UI libraries

Only these packages are included in the shipped web UI bundle (`apps/web-ui/package-lock.json`):

| Package | Author / maintainer | Licence |
|---|---|---|
| react 19.2.8, react-dom 19.2.8, scheduler 0.27.0 | Meta Platforms, Inc. and contributors | MIT |

The UI is built with Vite, `@vitejs/plugin-react` and TypeScript. Build-time packages are not
shipped; their licences are MIT, Apache-2.0 (TypeScript), ISC (picocolors), BSD-3-Clause
(source-map-js) and MPL-2.0 (lightningcss). The UI loads no fonts, scripts or styles from
third-party servers.

## Data sets

| Data | Author / maintainer | Upstream | Licence / terms | How ShakerProxy uses it |
|---|---|---|---|---|
| Public Suffix List | Mozilla Foundation and contributors | https://publicsuffix.org | MPL-2.0 | Embedded through `golang.org/x/net/publicsuffix`; groups domains by registrable domain in device reports |
| IEEE MA-L / MA-M / MA-S registries | IEEE Registration Authority | https://standards.ieee.org/products-programs/regauth/ | IEEE terms, via Ubuntu's `ieee-data` package | Read at runtime on the host; the files in `testdata/ieee` are documentation-only fixtures |
| DoH resolver catalog (`apps/mitmproxy/resolvers.json`) | ShakerProxy contributors | This repository | AGPL-3.0-only | Lists public DNS-over-HTTPS hostnames (factual data) for encrypted-DNS detection |
| Domain ownership and category table (`internal/domainclass`) | ShakerProxy contributors | This repository | AGPL-3.0-only | Curated from public facts; not derived from third-party block lists |
| Protocol catalog (`internal/protocolclass`) | ShakerProxy contributors | This repository | AGPL-3.0-only | Protocol names, categories and well-known ports |
| ShakerProxy cleartext Suricata ruleset | ShakerProxy contributors | `apps/analyzer-worker/suricata.rules` | AGPL-3.0-only | Narrow first-party ruleset; not a third-party IDS feed |

## External services

ShakerProxy sends no telemetry and needs no account. It contacts other systems only in these cases:

- **Installation and updates** download the signed release, host package and container images
  from GitHub Releases and the GitHub Container Registry, and Ubuntu packages from the configured
  apt mirrors. The PostgreSQL image is pulled from Docker Hub by digest.
- **Connectivity probe:** `shakerproxy probe-connectivity` and the dashboard's probe button connect to Cloudflare's
  `1.1.1.1` on TCP/443 and TCP/53 without sending a DNS question. Nothing else is sent.
- **DNS forwarding** sends lab devices' queries to the upstream resolvers the administrator
  configures.
- **Cloud connector** (optional) stays idle and connects nowhere until an administrator
  enrols the appliance. Only then does it talk to a control plane, uploading only bounded
  metadata (device inventory, protocol summaries and event metadata). Raw packets, decrypted
  content and private keys stay on the appliance.
- **AI agents** reach ShakerProxy only through the local MCP server with a token an administrator
  creates; ShakerProxy itself does not call any AI provider.

If you believe a component is missing or mis-attributed, please open an issue.
