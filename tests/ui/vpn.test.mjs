import assert from "node:assert/strict"
import test from "node:test"
import { validVPNName, vpnByteText, vpnHeadline, vpnNeverConnectedHint, vpnPeerState, vpnSettingsChange } from "../../apps/web-ui/src/lib/vpn.ts"
import { encodeQR } from "../../apps/web-ui/src/features/qr.ts"
import { webUIFile } from "./web-ui-source.mjs"

const now = Date.parse("2026-10-02T12:00:00Z")
const peer = (overrides = {}) => ({
  id: "vpn-0123456789abcdef",
  name: "Pixel",
  public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
  ipv4: "10.89.0.2",
  ipv6: "fd12:3456:789a:1::2",
  created_at: "2026-10-02T11:00:00Z",
  connected: false,
  received_bytes: 0,
  sent_bytes: 0,
  ...overrides,
})
const status = (overrides = {}) => ({
  schema: 1,
  revision: 3,
  enabled: true,
  up: true,
  interface: "wg-lab",
  listen_port: 51820,
  endpoint: "192.168.10.177:51820",
  endpoint_setting: "",
  default_endpoint_host: "192.168.10.177",
  server_public_key: "k",
  ipv4_cidr: "10.89.0.0/24",
  gateway_ipv4: "10.89.0.1",
  ipv6_prefix: "fd12:3456:789a:1::/64",
  gateway_ipv6: "fd12:3456:789a:1::1",
  ipv6_routed: false,
  allow_peer_to_peer: false,
  peers: [],
  notes: [],
  ...overrides,
})

test("a VPN device is connected, was connected, or never connected", () => {
  assert.deepEqual(vpnPeerState(peer({ connected: true, last_handshake: "2026-10-02T11:59:30Z" }), now), { label: "Connected", tone: "online" })
  assert.deepEqual(vpnPeerState(peer(), now), { label: "Not connected yet", tone: "never" })
  assert.deepEqual(vpnPeerState(peer({ last_handshake: "2026-10-02T11:40:00Z" }), now), { label: "Last connected 20 min ago", tone: "idle" })
})

test("the headline says whether VPN mode is off, broken or running", () => {
  assert.match(vpnHeadline(status({ enabled: false })), /off\. Nothing listens/)
  assert.match(vpnHeadline(status({ up: false, problem: "UDP port 51820 is already in use on this host" })), /not running: UDP port 51820/)
  assert.equal(
    vpnHeadline(status({ peers: [peer({ connected: true }), peer({ id: "vpn-1111111111111111", name: "Laptop" })] })),
    "VPN mode is on. Devices connect to 192.168.10.177:51820; 2 devices, 1 connected.",
  )
})

test("devices that never connected get the port-forwarding hint", () => {
  assert.equal(vpnNeverConnectedHint(status({ peers: [peer({ connected: true })] })), "")
  const hint = vpnNeverConnectedHint(status({ peers: [peer()] }))
  assert.match(hint, /^Pixel has not connected yet/)
  assert.match(hint, /forward UDP 51820/)
})

test("bytes are shown from the device's side", () => {
  assert.equal(vpnByteText(peer()), "")
  assert.equal(vpnByteText(peer({ received_bytes: 1500, sent_bytes: 2_500_000 })), "1.5 KB sent · 2.5 MB received")
})

test("names and settings are checked before they are sent", () => {
  assert.equal(validVPNName("Pixel 9"), true)
  assert.equal(validVPNName("  "), false)
  assert.equal(validVPNName("a".repeat(65)), false)
  assert.equal(validVPNName("two\nlines"), false)
  const current = status()
  assert.deepEqual(vpnSettingsChange(current, { endpoint: "", listen_port: "51820", allow_peer_to_peer: false }), {})
  assert.deepEqual(vpnSettingsChange(current, { endpoint: " home.example.net ", listen_port: "443", allow_peer_to_peer: true }), {
    endpoint: "home.example.net",
    listen_port: 443,
    allow_peer_to_peer: true,
  })
  assert.equal(vpnSettingsChange(current, { endpoint: "", listen_port: "70000", allow_peer_to_peer: false }), "The port must be a number from 1 to 65535.")
})

test("a device configuration fits a QR code the WireGuard app scans", () => {
  const config =
    "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.89.0.2/32, fd12:3456:789a:1::2/128\nDNS = 10.89.0.1\n\n" +
    "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.home-lab.example.net:51820\nPersistentKeepalive = 25\n"
  const code = encodeQR(config, { errorCorrection: "M" })
  assert.ok(code.version <= 14, `version ${code.version} is too dense to scan from a screen`)
})

test("the Network page shows VPN devices and never keeps the configuration", () => {
  assert.match(webUIFile("workspaces/network/NetworkWorkspace.tsx"), /<FeatureViews workspace="network" \/>/)
  const panel = webUIFile("features/VPNDevices.tsx")
  assert.match(panel, /registerView\(\{ id: "vpn-devices", workspace: "network",/)
  assert.match(webUIFile("features/index.ts"), /import "\.\/VPNDevices"/)
  assert.match(panel, /QRCodeSVG text=\{added\.config\}/)
  assert.doesNotMatch(panel, /localStorage|sessionStorage/)
  assert.match(webUIFile("main.tsx"), /styles\/vpn\.css/)
})
