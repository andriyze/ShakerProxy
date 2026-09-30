# ADR 0003: Kea DHCPv4/DHCPv6 and radvd

Status: DHCPv4 accepted; DHCPv6 and Router Advertisement acceptance pending

Use Kea for leases and reservations and `radvd` for explicit Router
Advertisements. Their configuration validators and event hooks support the
transactional plan and inventory model without putting these protocols in the
privileged daemon. IPv6 strategies remain separately selectable; NAT66 is
labelled a lab compromise. No DHCP or RA process starts in setup mode.

The DHCPv4 slice uses Ubuntu's confined Kea paths and service account. Native
syntax validation reads the rendered document from standard input before host
mutation. A watchdog-armed apply writes `/etc/kea/kea-dhcp4.conf`, starts a
hardened ShakerProxy-owned unit without enabling it at boot, and requires both an
active service and usable lab link for health. Durable confirmation enables the
unit; every rollback path disables it and restores the exact previous Kea
configuration. Clean-VM acceptance includes a real virtual-client lease and
outbound NAT round trip. DHCPv6 and `radvd` remain unimplemented.
