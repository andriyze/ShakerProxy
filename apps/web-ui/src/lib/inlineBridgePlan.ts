// The inline bridge (topology TRANSPARENT_BRIDGE): ShakerProxy sits between a
// test device and the router as a bridge over two ports. Pure helpers for the
// plan fields the Network page sends.

const ipv4CIDRPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/

// ipv4NetworkCIDR masks a host CIDR to its network (192.168.10.177/24 →
// 192.168.10.0/24); anything else is returned unchanged.
function ipv4NetworkCIDR(cidr: string): string {
  const match = ipv4CIDRPattern.exec(cidr)
  if (!match) return cidr
  const octets = match.slice(1, 5).map(Number)
  const bits = Number(match[5])
  if (octets.some((octet) => octet > 255) || bits > 32) return cidr
  const address = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  const network = (address & mask) >>> 0
  return `${network >>> 24}.${(network >>> 16) & 255}.${(network >>> 8) & 255}.${network & 255}/${bits}`
}

// routerGuess suggests the network's router: the first host address of the
// network ShakerProxy is on now (192.168.10.177/24 → 192.168.10.1). The
// tester can change it.
export function routerGuess(hostCIDR: string): string {
  const network = ipv4NetworkCIDR(hostCIDR.trim())
  const match = ipv4CIDRPattern.exec(network)
  if (!match || Number(match[5]) > 30) return ""
  return `${match[1]}.${match[2]}.${match[3]}.${Number(match[4]) + 1}`
}

// inlineBridgeFields returns the wan, ipv4 and ipv6 sections of an inline
// bridge plan: the bridge takes over ShakerProxy's address (a static
// address, so it is the same before and after) with the router as gateway
// and DNS; the lab is the network itself; nothing is routed or NATed.
// ShakerProxy takes its IPv6 address from the router's advertisements
// (SLAAC), so DNS that devices send over IPv6 is answered too.
export function inlineBridgeFields(
  hostCIDR: string,
  router: string,
  acknowledged: { workingConnection: boolean; cloudInit: boolean },
) {
  const address = hostCIDR.trim()
  return {
    wan: {
      ipv4_mode: "STATIC",
      ipv4_address: address,
      ipv4_gateway: router.trim(),
      ipv6_mode: "SLAAC",
      dns_mode: "USE_DHCP",
      upstream_nat: false,
      clamp_mss: false,
      allow_working_wan_change: acknowledged.workingConnection,
      allow_cloud_init_override: acknowledged.cloudInit,
    },
    ipv4: {
      enabled: true,
      lab_cidr: ipv4NetworkCIDR(address),
      gateway_address: address.split("/")[0] ?? "",
      nat44: false,
      client_isolation: false,
    },
    ipv6: { strategy: "OBSERVE_ONLY" },
  }
}
