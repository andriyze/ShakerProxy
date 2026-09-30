# ShakerProxy

ShakerProxy turns an Ubuntu box into a test gateway for the devices your team is
responsible for: phones, smart TVs, cameras, speakers, IoT sensors and
industrial controllers. Connect a device to ShakerProxy's lab network (a LAN port
or Wi-Fi), and ShakerProxy shows what it talks to in plain language, decrypts its
HTTPS when you install the ShakerProxy CA on it (or checks whether it wrongly
accepts untrusted certificates when you do not), records packets, flags
security problems with evidence, and lets you block the internet or single
domains to see how the device fails. Everything runs on the appliance;
nothing leaves it unless you set up event forwarding.

> **Pre-alpha.** ShakerProxy is under active development and no stable release
> has been published yet. [Capability claims](docs/capabilities.md) state which
> capabilities are implemented and which have been proven on real hosts.

## What you can do

- See every device on the lab network with its vendor, addresses and a
  friendly name you choose.
- Watch a device live: "DNS lookup api.example.com", "HTTPS
  api.example.com — decrypted", "MQTT to 3.4.5.6:1883 · 12 KB".
- Decrypt a device's HTTPS after installing the ShakerProxy CA from a QR code, or
  leave the CA off to test certificate validation.
- Get a security report per device: findings with severity, evidence and
  what to do, plus every domain it contacted. Share it as a single HTML file.
- Run named test runs ("Firmware 2.1 first boot") and compare two runs.
- Record packets to PCAP files and open them in Wireshark.
- Block a device's internet access or specific domains.
- Find unusual protocols: MQTT, CoAP, RTSP, Matter, Modbus, BACnet, OPC UA
  and more.
- Search recorded traffic, forward events, and connect AI agents over MCP.

## Try it in 5 minutes (development stack)

You need Docker with Compose v2, Make, Bash, OpenSSL and curl. `make verify`
additionally needs Node.js 22+ with npm, python3 and ripgrep (`rg`).

```bash
git clone https://github.com/andriyze/ShakerProxy.git shakerproxy
cd shakerproxy
make dev
```

Open <http://localhost:8443> and enter the one-time setup token that
`make dev` printed. The development stack shows the management UI and API
but never routes, captures or intercepts traffic. Run `make` to list every
target; `make dev-down` stops the stack and `make dev-reset` starts over.

To explore protocols, device reports and findings without hardware, start
the stack with analyzers and load a demo lab (a smart TV, an Android phone, an
IP camera, a smart plug, a PLC gateway and a laptop):

```bash
make dev-observe
make dev-demo
```

Details: [docs/quick-start.md](docs/quick-start.md).

## Install on an appliance

Use a dedicated Ubuntu Server 24.04 or 26.04 amd64 machine with one network
port for the uplink and one (or Wi-Fi) for the devices under test. Once a
release is published, run this as a regular user with sudo rights:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy/main/install/index.sh | sh
```

It checks the machine, verifies the signed release and starts ShakerProxy in a
safe setup mode that changes no networking. Add `SHAKERPROXY_DRY_RUN=1` before `sh`
to check without installing; run it again later to upgrade. Options:
[install/README.md](install/README.md).

The dashboard listens on the appliance's loopback only. Open
<https://127.0.0.1:8443/> on the appliance, or from your laptop through SSH:

```bash
ssh -N -L 8443:127.0.0.1:8443 <you>@<appliance-ip>
```

Create the admin account with the setup token from
`sudo cat /etc/shakerproxy/setup-token`, and follow **Network** to put the lab
network online. Details: [docs/installation.md](docs/installation.md).

## Common tasks

Sign the CLI in once with `shakerproxy login`. A device can be named by its
friendly name, IP address, MAC address or ID. Every command has `--help` with
examples, and `--json` for scripts.

```bash
shakerproxy status                                   # health and mode at a glance
shakerproxy devices                                  # what is connected
shakerproxy device "Living room TV"                  # details, controls, quick findings
shakerproxy watch "Living room TV"                   # live activity in plain language
shakerproxy ca                                       # QR code to install the ShakerProxy CA
shakerproxy decrypt "Living room TV" on              # decrypt its HTTPS
shakerproxy test start "Living room TV" --name "Firmware 2.1" --capture
shakerproxy test stop "Living room TV"
shakerproxy report "Living room TV" --html tv.html   # shareable security report
shakerproxy compare <test-id-a> <test-id-b>          # what changed between two runs
shakerproxy block "Living room TV" internet          # see how it behaves offline
shakerproxy search 'tls.state:FAILED' --window 24h   # search recorded traffic
shakerproxy capture export <capture-id> --all ./pcaps
shakerproxy doctor                                   # diagnose the appliance
sudo shakerproxy logs gatewayd -f                    # follow a service log
```

`shakerproxy login` keeps your token in `~/.config/shakerproxy`, readable only by you.
`status`, `doctor` and `capture` talk to the gateway daemon, which members of
the `shakerproxy-host` group may use; the installer adds the user who installed
ShakerProxy (effective at their next login; until then use `sudo`). Run `shakerproxy`
on its own for a short overview.

## Documentation

- [Documentation map](docs/README.md) — every guide in one place
- [Development quick start](docs/quick-start.md) and
  [installation and lifecycle](docs/installation.md)
- [Networking and guarded activation](docs/networking.md),
  [capture and storage](docs/capture-and-storage.md),
  [device inventory](docs/device-inventory.md),
  [diagnostics](docs/diagnostics.md)
- [API tokens and forwarding](docs/integrations.md) and
  [AI agent quick connect](docs/ai-agent-quick-connect.md)
- [Capability claims](docs/capabilities.md),
  [architecture](docs/architecture.md) and
  [threat model](docs/threat-model.md)
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

## Safety and authorization

Only inspect networks and devices for which you have explicit authorization.
Interception can expose credentials, tokens, private communications, and
personal data. Active spoofing and manipulation are not part of the safe setup
slice and will remain opt-in, session-scoped features.

## License

First-party ShakerProxy code is licensed under the GNU Affero General Public License
version 3 only (`AGPL-3.0-only`) unless a file explicitly states otherwise.
Third-party components retain their own licenses; see [LICENSE](LICENSE),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and
[docs/licenses/dependency-matrix.md](docs/licenses/dependency-matrix.md).
