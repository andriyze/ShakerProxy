import type { LabRoutingDevice, LabRoutingReport } from "../types"

// A device can be on the lab network and still send everything straight to
// the router: in a single-arm lab the router's DHCP gives it the router as
// its gateway, and ShakerProxy sees only its broadcasts. These helpers word
// that, and the ways to fix it, from the real addresses.

export function labDeviceTitle(device: Pick<LabRoutingDevice, "display_name" | "host_name" | "address">): string {
  const name = device.display_name || device.host_name
  return name ? `${name} · ${device.address}` : device.address
}

export function bypassingDevices(report: LabRoutingReport | null | undefined): LabRoutingDevice[] {
  if (!report?.available) return []
  return report.devices.filter((device) => device.routing === "BYPASSING")
}

export function bypassHeadline(device: LabRoutingDevice, report: LabRoutingReport): string {
  const router = report.router_address ? `your router (${report.router_address})` : "your router"
  return `${labDeviceTitle(device)} is on the lab network, but its traffic goes straight to ${router}, so ShakerProxy can't see it.`
}

export type FixSteps = {
  iphone: string[]
  android: string[]
  vpn: string
  router: string[]
}

function prefixLength(prefix: string | undefined): string {
  const bits = prefix?.split("/")[1]
  return bits && /^\d{1,2}$/.test(bits) ? bits : "24"
}

// fixSteps says how to send one device's traffic through ShakerProxy.
export function fixSteps(device: LabRoutingDevice, report: LabRoutingReport): FixSteps {
  const gateway = report.shakerproxy_address || "ShakerProxy's lab address"
  const mask = report.subnet_mask || "255.255.255.0"
  return {
    iphone: [
      "Settings → Wi-Fi → tap (i) next to the lab network.",
      `Configure IP → Manual: IP Address ${device.address}, Subnet Mask ${mask}, Router ${gateway}.`,
      `Configure DNS → Manual: remove the other servers and add ${gateway}.`,
    ],
    android: [
      "Settings → Network & internet → Internet → the gear next to the lab network → Edit (pencil) → Advanced options.",
      `IP settings: Static. IP address ${device.address}, Gateway ${gateway}, Network prefix length ${prefixLength(report.prefix)}, DNS 1 ${gateway}.`,
    ],
    vpn: "Or use VPN mode: Network → VPN devices, add the device and scan the QR code with the WireGuard app. It works on any network, with no IP settings.",
    router: [
      `To send every device through ShakerProxy without touching each one, set the gateway and the DNS server that your router's DHCP hands out on this network to ${gateway}.`,
      `On UniFi: Settings → Networks → this network → DHCP: set "DHCP Default Gateway" and "DNS Server" to ${gateway}, then reconnect the device.`,
      "While ShakerProxy is off, devices on this network then have no internet until you change it back.",
    ],
  }
}

// labRoutingSummary is the one-line count for the Start and System pages.
export function labRoutingSummary(report: LabRoutingReport | null | undefined): string {
  if (!report) return ""
  if (!report.available) return report.unavailable ?? ""
  const { through_shakerproxy: through, bypassing, unknown } = report.counts
  if (bypassing === 0 && through === 0 && unknown === 0) return "No devices seen on the lab network in the last 10 minutes."
  const parts: string[] = []
  if (through > 0) parts.push(`${through} ${through === 1 ? "device sends its" : "devices send their"} traffic through ShakerProxy`)
  if (bypassing > 0) parts.push(`${bypassing} ${bypassing === 1 ? "device bypasses" : "devices bypass"} it`)
  if (unknown > 0) parts.push(`${unknown} just ${unknown === 1 ? "appeared and is" : "appeared and are"} not judged yet`)
  return `${parts.join("; ")}.`
}
