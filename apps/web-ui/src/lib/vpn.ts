// VPN mode (WireGuard): pure helpers for the Network page's "VPN devices".
// Keep this file free of runtime imports so node --test can load it directly.

// VPNPeer mirrors one device in GET /api/v1/vpn.
export type VPNPeer = {
  id: string
  name: string
  device_id?: string
  public_key: string
  ipv4: string
  ipv6: string
  created_at: string
  created_by?: string
  connected: boolean
  last_handshake?: string
  remote_address?: string
  // Bytes ShakerProxy received from the device and sent to it.
  received_bytes: number
  sent_bytes: number
}

// VPNStatus mirrors GET /api/v1/vpn.
export type VPNStatus = {
  schema: number
  revision: number
  enabled: boolean
  up: boolean
  interface: string
  listen_port: number
  endpoint?: string
  endpoint_setting?: string
  default_endpoint_host?: string
  server_public_key: string
  ipv4_cidr: string
  gateway_ipv4: string
  ipv6_prefix: string
  gateway_ipv6: string
  ipv6_routed: boolean
  allow_peer_to_peer: boolean
  peers: VPNPeer[]
  problem?: string
  notes: string[]
}

// VPNAdded mirrors POST /api/v1/vpn/devices: the one-time configuration.
export type VPNAdded = {
  peer: VPNPeer
  config: string
  file_name: string
  device_id?: string
  device_name: string
  warnings: string[]
}

export type VPNPeerState = { label: string; tone: "online" | "idle" | "never" }

// vpnPeerState says whether a VPN device is connected now, was connected,
// or has not connected yet (its QR code was never scanned or it cannot
// reach ShakerProxy).
export function vpnPeerState(peer: VPNPeer, now: number): VPNPeerState {
  if (peer.connected) return { label: "Connected", tone: "online" }
  if (!peer.last_handshake) return { label: "Not connected yet", tone: "never" }
  return { label: `Last connected ${agoText(now - Date.parse(peer.last_handshake))}`, tone: "idle" }
}

function agoText(elapsed: number): string {
  if (!Number.isFinite(elapsed) || elapsed < 60_000) return "just now"
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)} min ago`
  if (elapsed < 48 * 3_600_000) return `${Math.floor(elapsed / 3_600_000)} h ago`
  return `${Math.floor(elapsed / 86_400_000)} days ago`
}

// vpnHeadline is the one-line state of VPN mode.
export function vpnHeadline(status: VPNStatus): string {
  if (!status.enabled) return "VPN mode is off. Nothing listens until you turn it on."
  if (!status.up) return `VPN mode is on but not running: ${status.problem || "the WireGuard interface is not up yet"}.`
  const connected = status.peers.filter((peer) => peer.connected).length
  const devices = status.peers.length === 1 ? "1 device" : `${status.peers.length} devices`
  return `VPN mode is on. Devices connect to ${status.endpoint ?? "this appliance"}; ${devices}, ${connected} connected.`
}

// vpnUntouchedHint warns when a device was added but never connected: the
// usual causes, in the order a tester should check them.
export function vpnNeverConnectedHint(status: VPNStatus): string {
  const waiting = status.peers.filter((peer) => !peer.connected && !peer.last_handshake)
  if (waiting.length === 0) return ""
  return `${waiting.map((peer) => peer.name).join(", ")} ${waiting.length === 1 ? "has" : "have"} not connected yet. Check that the tunnel is on in the WireGuard app and that the device can reach ${status.endpoint ?? "ShakerProxy"} over UDP; from outside this network, forward UDP ${status.listen_port} on your router.`
}

// vpnByteText is what crossed the tunnel, from the device's point of view.
export function vpnByteText(peer: VPNPeer): string {
  if (!peer.received_bytes && !peer.sent_bytes) return ""
  return `${bytesText(peer.received_bytes)} sent · ${bytesText(peer.sent_bytes)} received`
}

function bytesText(value: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"]
  let amount = Math.max(0, value || 0)
  let unit = 0
  while (amount >= 1000 && unit < units.length - 1) {
    amount /= 1000
    unit++
  }
  return unit === 0 ? `${amount} B` : `${amount >= 100 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`
}

// validVPNName mirrors the server's rule: 1-64 characters on one line.
export function validVPNName(name: string): boolean {
  const trimmed = name.trim()
  return trimmed.length > 0 && [...trimmed].length <= 64 && !/[\u0000-\u001f\u007f]/.test(trimmed)
}

// vpnSettingsChange returns only the settings that differ from status, for
// PUT /api/v1/vpn; an empty endpoint means "this appliance's address".
export function vpnSettingsChange(
  status: VPNStatus,
  form: { endpoint: string; listen_port: string; allow_peer_to_peer: boolean },
): { endpoint?: string; listen_port?: number; allow_peer_to_peer?: boolean } | string {
  const change: { endpoint?: string; listen_port?: number; allow_peer_to_peer?: boolean } = {}
  const endpoint = form.endpoint.trim()
  if (endpoint !== (status.endpoint_setting ?? "")) change.endpoint = endpoint
  const port = Number(form.listen_port.trim() || status.listen_port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return "The port must be a number from 1 to 65535."
  if (port !== status.listen_port) change.listen_port = port
  if (form.allow_peer_to_peer !== status.allow_peer_to_peer) change.allow_peer_to_peer = form.allow_peer_to_peer
  return change
}
