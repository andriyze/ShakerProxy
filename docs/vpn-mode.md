# VPN mode (WireGuard)

VPN mode routes a phone's or laptop's **entire** connection through
ShakerProxy from any network. The tester scans a QR code with the WireGuard
app once; from then on every connection the device makes (IPv4, IPv6 and
local-network destinations) goes through ShakerProxy and appears in Traffic
under the device's name, for example `Pixel (VPN) · 10.89.0.2`.

Compared with a lab network, a VPN device needs no static IP, no cable and no
Wi-Fi from ShakerProxy, and nothing can take its traffic around ShakerProxy:
another DHCP server, another IPv6 router or a direct path to a local device
cannot apply to a full tunnel.

VPN mode is **off** by default. Until it is turned on there is no WireGuard
interface and nothing listens.

## Set up a phone

1. **Network → VPN devices → Turn on VPN mode** (or `shakerproxy vpn on`).
2. Type a name (`Pixel`) and choose **Add device** (or `shakerproxy vpn add Pixel`,
   which prints the QR code in the terminal).
3. On the phone, install **WireGuard** from the App Store or Google Play.
4. In WireGuard tap **+** → **Scan from QR code** (Android: *Scan from QR
   code*; iOS: *Create from QR code*), scan the code and allow the VPN
   configuration.
5. Turn the tunnel on. The device shows **Connected** in VPN devices, and its
   traffic appears in Traffic within about a second (DNS and new connections)
   and with full details (TLS, HTTP, QUIC) after the recording is analyzed.

On a laptop, choose **Download** (or `shakerproxy vpn add Laptop --save laptop.conf`)
and import the file in the WireGuard app.

The QR code holds the device's **private key** and is shown only once:
ShakerProxy keeps only the public key. If it is lost, revoke the device and
add it again.

## Using it from outside your network

Devices dial the address shown in VPN devices (by default this appliance's
own address, UDP port 51820). That works on the same network. From anywhere
else:

1. On your router, **forward UDP port 51820** to this appliance's address.
2. In **VPN settings**, set the address in device configurations to your
   public IP address or a (dynamic) DNS name, adding `:port` if the router
   forwards a different port (`shakerproxy vpn set --address home.example.net`).
3. Add the device (configurations made before the change dial the old address).

Some networks (hotel or corporate Wi-Fi, some mobile carriers) block UDP or
unusual ports. Port 443 often passes: forward UDP 443 and set the VPN port to
443 (`shakerproxy vpn set --port 443`).

## What VPN devices can reach

- The internet and the networks behind ShakerProxy (the lab and the LAN it
  sits on), NATed to ShakerProxy's address.
- **Not** ShakerProxy itself: the management page (8443), SSH and every other
  host or container service are refused. The DNS and HTTPS the traffic
  policy redirects to ShakerProxy are the only exceptions.
- **Not each other**, unless *Let VPN devices reach each other* is on
  (`shakerproxy vpn set --peer-to-peer on`); then that traffic crosses
  ShakerProxy and is recorded too. Nothing outside can open a connection to a
  VPN device.

## What ShakerProxy sees

VPN devices get the same treatment as lab devices:

- **DNS**: the configuration sets ShakerProxy's VPN address (`10.89.0.1`) as
  the device's DNS server; plain DNS sent to any other resolver is redirected
  to it while *Force plain DNS* is on. Encrypted DNS is identified, or blocked
  when *Block encrypted DNS* is on.
- **Connections**: every new connection is reported from the kernel's
  connection tracking within about a second, named from the device's own DNS
  answers.
- **Recording**: while VPN mode is on, a second automatic recording ("VPN
  traffic") records the WireGuard interface beside the lab recording, so
  Zeek and Suricata analyze VPN devices' TLS, HTTP, QUIC and alerts. (One
  file cannot hold both: the lab carries Ethernet frames, the VPN raw IP
  packets.) A manual capture of the lab does not stop it.
- **Per-device controls**: blocking, domain blocks and HTTPS decryption
  apply by the device's VPN address, which WireGuard binds to the device's
  key. Install the ShakerProxy CA before turning decryption on; the
  lab-side CA page is not served over the VPN, so download the CA from the
  management page and open it on the device.
- **Visibility coverage** shows a "VPN devices" finding with no bypass.

During an **emergency bypass**, VPN devices keep routing but nothing is
inspected, redirected or recorded; their DNS to `10.89.0.1` stops being
answered until the bypass ends.

## IPv6

The tunnel carries all IPv6 (`AllowedIPs = 0.0.0.0/0, ::/0`) and each device
gets a private (unique-local) IPv6 address, so no IPv6 leaves the device
outside the tunnel. When this host forwards IPv6 (a lab plan that routes
IPv6), VPN devices reach IPv6 sites through ShakerProxy (NAT66). Otherwise
their IPv6 ends at ShakerProxy and they use IPv4 for everything. ShakerProxy
never turns IPv6 forwarding on for the VPN alone: on a host that learns its
own IPv6 route from router advertisements that would cut it off.

## Limits

- **Battery**: the configuration keeps the tunnel alive with a keepalive
  every 25 seconds so pushes reach an idle phone; that costs some battery.
  Turn the tunnel off when not testing.
- **Local discovery** (mDNS, SSDP, AirPlay, casting) on the device's own
  Wi-Fi does not cross the tunnel, so it is not seen.
- **Performance**: all traffic takes the detour through ShakerProxy;
  latency-sensitive apps (games, calls) behave as on a slower link.
- Some apps detect VPNs and change behavior or refuse to run.
- Changing the VPN network (`10.89.0.0/24` by default) needs every device
  revoked first. A revoked device's address is only reused once every other
  address has been handed out, so recorded traffic keeps its name.
- The kernel needs WireGuard (every standard Ubuntu kernel has it).

## Reference

| Surface | How |
| --- | --- |
| Web UI | Network → VPN devices |
| CLI | `shakerproxy vpn`, `vpn on/off`, `vpn add <name> [--save FILE]`, `vpn revoke <name>`, `vpn set --address/--port/--peer-to-peer` |
| API | `GET/PUT /api/v1/vpn`, `POST /api/v1/vpn/devices`, `DELETE /api/v1/vpn/devices/{id}` (see `openapi.yaml`) |
| MCP | `vpn_devices` (read-only) |

Under the hood gatewayd runs the `wg-lab` kernel WireGuard interface over
netlink (no extra packages), keeps the server key in the root-only
`/var/lib/shakerproxy/gatewayd/vpn.json`, and owns the `SHAKERPROXY-VPN-*`
firewall chains, hooked below the traffic policy's security chains. A change
that cannot be applied leaves the previous VPN running (or none); a
reconcile every 15 seconds repairs a deleted interface or flushed chain.
`tests/netlab/vpn-mode.sh` proves the whole path in network namespaces.
