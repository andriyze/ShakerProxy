# Device inventory and correction controls

ShakerProxy treats an address as time-bounded evidence, never as a device identity.
The current passive inventory reconciles Kea DHCPv4 leases into durable devices
using normalized MAC and DHCP client identifiers. Each address retains its
validity interval, source, confidence, and reconciliation time. When the
gateway reports a confirmed routed plan, new lease intervals also retain the
lab interface, optional VLAN, and confirmed plan SHA-256 that defined their
network scope. Older records and reconciliations performed while gateway state
is unavailable remain valid with scope explicitly unknown; ShakerProxy does not
guess or backfill them. Conflicting identities remain separate and carry
visible warnings.

When a confirmed plan routes lab IPv6 (see [IPv6 in the lab](ipv6.md)), the
inventory sync also reads the gateway's IPv6 neighbor table for the lab
interface. Each MAC-to-IPv6 mapping (SLAAC, privacy, and link-local
addresses) becomes an `NDP` address observation with confidence 80, below the
DHCP lease's 95, scoped to the confirmed lab interface and plan. Its window
runs from the first to the last time the kernel confirmed the device was
reachable, plus 10 minutes; a device that returns after that opens a new
window. A MAC that only appears in the neighbor table creates a device with an
`NDP` MAC identity, so IPv6-only devices are listed too. Neighbor entries
outside the lab prefix are never recorded.

## Inventory views and shareable filters

The authenticated device list supports strict server-side views rather than
downloading the complete inventory and hiding rows in the browser:

```text
GET /api/v1/devices?view=online&q=camera&interface=enp2s0.20&vlan_id=20
GET /api/v1/devices?view=recent&category=sensor&tag=test%20bench&sort=name&direction=asc
```

`view` is exactly `all`, `online`, or `recent`; recent means a `last_seen`
within 24 hours of the snapshot's generated time. Search is a bounded,
case-insensitive substring over immutable IDs, current and retained friendly
names, review-only name suggestions, owner, location, category, notes, vendor
evidence, identities, addresses, interfaces, hostnames, and tags. Interface,
VLAN, vendor, category, and canonical tag filters are exact. Additional
evidence-quality controls require IPv4 or IPv6 observations, set a minimum
attribution-confidence score, or select devices with/without current warnings.
These filters compose on the server; they do not relabel uncertain evidence in
the browser. Sort is limited to display name, first seen, last seen, or
confidence with an explicit direction; the immutable device ID breaks ties so
results are deterministic.

Unknown or repeated parameters and noncanonical values fail with
`invalid_query`. The responsive UI exposes the same controls and records only
nondefault device settings under `device_*` URL parameters. Existing traffic
query state is preserved, so an operator can copy a filtered inventory URL and
another authenticated operator sees the same view.

Each inventory result also opens an authenticated detail drawer backed by
`GET /api/v1/devices/{deviceID}`. The drawer shows the immutable ID, current
status, attribution confidence and warnings, all bounded identity/address/
hostname evidence, and retained name revisions. Opening it adds a validated
`device_id` to the current URL without discarding device or traffic filters;
invalid identifiers are never copied into generated links. The drawer is
keyboard-dismissible, becomes full-width on narrow screens, and can be opened
directly from a shared URL after sign-in.

Rename and DHCP-hostname suggestion acceptance are available inside the detail
surface. They use the same reauthentication, reason, expected alias revision,
idempotency, and audit-history contract as the inventory-row control. A stale
open drawer therefore conflicts instead of silently overwriting a newer name.

## DHCP observed on the lab

In a single-arm lab or an inline bridge the network's router, not ShakerProxy,
serves DHCP, so ShakerProxy's own lease file names no devices. The lab
recording still sees the clients' DHCP broadcasts (and, on a bridge, the
router's answers). Zeek logs each exchange with the client's name (option 12),
FQDN (81), vendor class (60, `client_software`), the order of the options it
asks for (55, `client_param_list`), and from the server's reply the router it
hands out (3, `routers`). ingestd merges the last week of `zeek.dhcp` and
`suricata.dhcp` records per client MAC (`GET /v1/observed-dhcp`), and the
inventory takes them as `OBSERVED_DHCP` evidence:

| Evidence | Source and confidence | Effect |
| --- | --- | --- |
| A server's acknowledgement binding MAC and address | `OBSERVED_DHCP`, 90 (ShakerProxy's own lease 95, NDP 80, ARP 70) | An address window for the lease (1 hour when the reply had none, at most 7 days); a neighbor-sourced MAC identity is upgraded. A newer acknowledgement of the address to another device ends the older window. |
| The name the client gave itself | `OBSERVED_DHCP` hostname, 70 (ShakerProxy's own lease 75) | A suggested name. It never replaces a name an administrator chose. Titles keep the device's own spelling ("iPad"). |
| Vendor class and option order | `observed_dhcp` on the device | Shown on the Devices page and in the device drawer, in the API, and in MCP `list_devices` and `find_device`, and used as a platform hint. |

A MAC seen only asking adds its name and fingerprint to a device the lab
already knows, but creates nothing: a lab segment also carries requests from
neighbouring networks. Only an acknowledged lease inside the lab's IPv4 prefix
creates a device. A phone that rotates its private MAC and gets the same
address again stays one device.

### Devices that bypass ShakerProxy

A device can be on the lab network and still send everything straight to the
router: in a single-arm lab the router's DHCP gives it the router as its
gateway. ShakerProxy then records only its DHCP request and its multicast
(mDNS, SSDP). ingestd reports, per lab address over the last 30 minutes, those
sightings with the MACs Zeek saw sending from it, and how much of its traffic
reached ShakerProxy: connections and lookups ShakerProxy handled, or recorded
traffic to a unicast address, which a single-arm lab records only when it is
sent to ShakerProxy (`GET /v1/lab-presence`). The control API judges each
device seen in the last 10 minutes (`GET /api/v1/lab-routing`, also
`lab_routing` on `/api/v1/devices` and MCP `lab_routing`):

| State | When |
| --- | --- |
| `THROUGH_SHAKERPROXY` | Some of its traffic reached ShakerProxy in the last 30 minutes, and it has not rejoined through the router's DHCP since. |
| `BYPASSING` | Seen for 2 minutes or more with none of its traffic reaching ShakerProxy: it asked the router's DHCP for an address (in a lab where ShakerProxy serves no DHCP), sent at least three messages, or kept sending for 2 minutes. The reason names the router: "It got its address from your router's DHCP, so it uses the router (192.168.10.1) as its gateway, not ShakerProxy." |
| `UNKNOWN` | It just appeared; it may not have sent traffic yet. |

ShakerProxy and the router (the lab interface's default gateway) are not
judged. A device that bypasses ShakerProxy also becomes a device in the
inventory, with the weakest evidence, `OBSERVED_LAN` at confidence 50 (below
ARP's 70): its MAC, the address it used for 15 minutes after it was last seen,
and its DHCP name as a suggestion. Pinned addresses and MAC rotation apply as
for every other source, and a name an administrator chose is never touched.

The Live view, the Start page and the System page show such devices with the
fix, filled with the device's address and ShakerProxy's: set the device's
gateway and DNS to ShakerProxy (manual IP settings), use VPN mode, or have the
router's DHCP hand out ShakerProxy as gateway and DNS for the whole network
(devices then have no internet while ShakerProxy is off). The coverage check
names them first.

The platform hint from a DHCP request is conservative: `android-dhcp-*` is an
Android device, `MSFT 5.0` a Windows PC, `dhcpcd-*` a Linux or Android device,
`udhcp` an embedded Linux device, and Apple's option order
(`1,121,3,6,15,…` with 119 and 252, no vendor class) an Apple device. An
operating system's own connectivity check is more specific and wins a tie
("GrapheneOS phone" over "Android device"). The Devices page says which
evidence named the device: "Identified from its DHCP request: android-dhcp-14".

## Hardware vendor evidence

For globally administered unicast MAC addresses, ShakerProxy consults the local
Ubuntu `ieee-data` cache. It loads the fixed `oui.csv`, `mam.csv`, and
`oui36.csv` files for IEEE MA-L (24-bit), MA-M (28-bit), and MA-S (36-bit)
assignments. Longest-prefix matching ensures a smaller MA-M or MA-S allocation
is not mislabeled as its parent MA-L holder.

The files are mounted read-only, opened with `O_NOFOLLOW`, bounded by bytes and
records, required to use the exact UTF-8 IEEE CSV schema, and represented in
the device record with registry, assignment, confidence, observation time, and
source-file SHA-256. Conflicting duplicate assignments yield `AMBIGUOUS`.
Locally administered addresses yield `LOCALLY_ADMINISTERED`, and an unmatched
global address yields `NO_MATCH`; neither is presented as a hardware vendor.

## Friendly names and revision history

Friendly names are mutable display labels; the generated `device-…` ID remains
the immutable identity. A rename requires current administrator credentials, a
reason, an `Idempotency-Key`, and the alias revision the caller loaded:

```text
PUT /api/v1/devices/{device_id}/alias
```

The write is rejected with `alias_revision_conflict` if another administrator
renamed the device first. Every accepted change retains its revision, actor,
UTC timestamp, previous value, new value, and reason. History is bounded to the
latest 256 revisions and explicitly reports when earlier revisions were pruned.
Duplicate names are permitted because real labs reuse labels, but every current
duplicate is marked `friendly_name_conflict` using case-insensitive comparison.

Authenticated recent and live event responses resolve administrator names in
the control plane, not in analyzer or ingest workers. They expose the current
name, alias revision, duplicate warning, and the name in effect at the event's
`occurred_at` timestamp. Legacy names without revision timestamps and events
older than truncated history report capture-time name as unknown instead of
guessing. If inventory reading fails, `device_labels_available` is false while
immutable device IDs and event evidence remain available.

The inventory and live-traffic UI show the friendly name first, keep the device
ID visible, display capture-time differences, and provide inline reauthenticated
rename controls.

Up to eight recent, distinct DHCP hostnames are projected as review-only name
suggestions with source, confidence, and observation times. They are computed
from persisted evidence when the API response is built, are never stored as
administrator metadata, and are never applied without an explicit rename,
reason, password, expected revision, and idempotency key. Hostnames that exceed
the friendly-name limit or already equal the current alias are omitted.

Authenticated operators can export a deterministic current alias/tag snapshot
as JSON or RFC 4180 CSV:

```text
GET /api/v1/device-aliases/export?format=json
GET /api/v1/device-aliases/export?format=csv
```

Rows are sorted by immutable device ID and contain only `device_id`, current
`friendly_name`, `alias_revision`, and tags. The CSV `tags_json` cell is a JSON
string array so commas and quoting round-trip without inventing a delimiter.
Both formats are no-store downloads bounded to 64 MiB. Owner, location,
category, icon, notes, address evidence, credentials, and traffic are excluded.

The UI and API can import either format in batches of at most 256 rows. Parsing
is strict: unknown JSON fields, a changed CSV header, duplicate device IDs,
invalid names/tags, malformed `tags_json`, and oversized input are rejected.
Preview is read-only and binds the canonical rows, current alias revisions,
current tag-set hashes, a common audit reason, and a ten-minute validity window:

```text
POST /api/v1/device-aliases/import-preview
POST /api/v1/device-aliases/import
```

Missing device IDs and stale alias revisions are explicit preview blockers.
Duplicate proposed names are allowed but warned. Apply requires administrator
reauthentication and an idempotency key, then rechecks every alias revision and
tag hash under the inventory lock. Any drift rejects the entire batch before a
write. Accepted names receive ordinary alias-history entries, all changes and
one hash-chained audit event commit atomically, and exact retries replay the
original audit identity.

## Administrator metadata

An authenticated administrator may set an owner, location, canonical category,
allowlisted presentation icon, up to 32 tags, and bounded notes. Icons are
semantic names from a fixed product set—not URLs, SVG, HTML, or captured
content—so metadata cannot create a rendering injection path. Categories are
lowercase identifiers suitable for later policy matching. The legacy combined endpoint also accepts `friendly_name`; any change is
converted into a revision with a generic migration reason. Saving requires the current administrator password and an
`Idempotency-Key`. The password is used only for reauthentication; it is not
stored in the inventory or audit record.

```text
PUT /api/v1/devices/{device_id}/metadata
```

Metadata is applied as one validated patch: omitted fields are preserved for
older clients, while an explicit empty string or array clears that field.
Tags are trimmed, lowercased, deduplicated, sorted, and bounded. Metadata is
additive to the schema, so existing schema-1 stores without the new fields
remain valid and acquire them only after an explicit administrator update.

## Scoped address aliases

An address alias is an explicit fallback label for traffic that has no reliable
device identity. It is never a device primary key and never moves lease history.
Every entry requires an IPv4/IPv6 address or CIDR, Linux interface, inclusive
`valid_from`, priority, confidence, and administrator reason. VLAN and the
exclusive `valid_until` are optional. Bare addresses are stored canonically as
`/32` or `/128`; CIDRs are masked before persistence.

```text
POST /api/v1/address-aliases
PUT /api/v1/address-aliases/{address_alias_id}
GET /api/v1/address-aliases/resolve?address=...&interface=...&vlan_id=...&at=...
```

Create and update require reauthentication and an `Idempotency-Key`; updates
also require the loaded revision. Resolution first chooses the longest prefix,
then VLAN-specific scope, priority, and confidence. If differently named
candidates tie at that semantic rank, resolution fails closed with `conflict`
instead of using creation order. A deterministic timestamp/ID order is used
only for non-conflicting candidates.

The inventory snapshot annotates overlapping differently named manual aliases.
It also flags overlap with conclusive device lease evidence. Scoped DHCPv4
records conflict only on a compatible interface, VLAN, and time interval.
Legacy records without confirmed interface/VLAN evidence remain conservative:
the warning explicitly states that ShakerProxy cannot dismiss the overlap
automatically. This preserves the plan's rule that an IP reuse or privacy
address must not silently transfer old traffic.

## Explicit merge and split

Automatic reconciliation does not merge conflicting stable identities. An
administrator can correct a known correlation explicitly:

```text
POST /api/v1/devices/{target_device_id}/merge
POST /api/v1/devices/{source_device_id}/split
```

A merge retains the selected target ID. Evidence is deduplicated; the target's
non-empty friendly name, owner, location, category, icon, and notes win
conflicts, while tags are united. Conflicting source metadata remains visible as
an attribution warning instead of silently replacing the target.
The source device disappears only in the same atomic write that records the
audit event.

A split must move at least one identity and leave at least one identity on the
original device. It selects exact evidence records:

- identity kind, value, and evidence source;
- address, evidence source, `valid_from`, `valid_until`, and its complete
  interface/VLAN/plan-hash scope when known;
- hostname and evidence source.

This prevents a broad "move this IP" operation from silently moving unrelated
historical leases. A retry with the same `Idempotency-Key` returns the original
audit identity; reuse for different semantics is rejected.

## Analyzer-event attribution

Before a normalized Zeek or Suricata record is committed to PostgreSQL, ShakerProxy
compares its source/originator IPv4 or IPv6 address with the inventory at the
event's timestamp (DHCPv4 windows for IPv4, NDP windows for IPv6). If the source is external or unmatched, the destination is checked
to attribute return traffic. A match must fall inside a half-open
`[valid_from, valid_until)` lease interval and resolve to exactly one device.
Overlapping windows remain unattributed rather than selecting a device. The
event confidence is capped by both parser and address-evidence confidence.

For newly attributed Zeek and Suricata events, the database stores a bounded
immutable explanation beside the device ID: whether the source or destination
endpoint matched, the canonical IPv4 or IPv6 address, the `DHCP4_LEASE` or
`NDP` evidence source and confidence, the exact half-open validity interval, and any confirmed
interface/VLAN/plan-hash scope. Recent and live traffic APIs expose this object
without the raw analyzer payload, and the traffic inspector renders it. Legacy
rows or explicitly supplied device associations leave the explanation absent
and are labeled unavailable rather than reconstructed from mutable inventory.

Attribution happens after the immutable spool identity is established. A retry
therefore cannot change the source/event identity, and a previously committed
row is not rewritten if an administrator later corrects the inventory. The
ingest service receives only a read-only inventory mount; malformed inventory
state pauses database drain instead of committing guessed attribution.

Inventory data lives in a dedicated volume: the control API receives write
access while ingestd receives read-only access. On first startup after this
layout change, a valid legacy inventory is copied atomically and the source is
renamed with a `.migrated` suffix as a recovery copy. Invalid, symlinked, or
conflicting migration state stops startup.

Authenticated traffic queries can use `device.name:"Bench Camera"` (or the
short aliases `name:` and `device:`). Matching is exact and case-insensitive
over current and retained historical friendly names, so an old alias continues
to locate immutable events after a rename. The control API resolves names from
one bounded inventory snapshot and forwards only sorted device IDs to the event
store. A live connection keeps that membership until reconnect. More than 32
name operands or 256 total device associations is rejected instead of silently
truncated; `device.id` can narrow an intentionally duplicated name. Alias
revisions already pruned at the 256-entry per-device history limit are not
searchable.

## Audit boundary

Each successful mutation records a bounded event containing the actor,
operation ID, timestamp, action, source/result device or address-alias IDs, and a non-secret
change summary. The ledger is stored atomically with the device mutation and is
available to authenticated clients at:

```text
GET /api/v1/device-audit?limit=100
```

Every entry contains the previous entry's SHA-256 plus its own canonical digest,
so accidental or casual edits break validation. The ledger stops accepting
mutations at 4,096 records rather than silently discarding history. External
signed checkpoints, archival, and the appliance-wide PostgreSQL audit remain
release work; the hash chain does not protect against a fully compromised root
user who can recompute it.

## Current limits

This slice uses DHCPv4 identity/address evidence and, for routed lab IPv6,
NDP neighbor evidence; there is no DHCPv6 evidence. Normalized analyzer
events can carry a device ID plus current/capture-time friendly-name projection,
typed current/retained-alias search, and IEEE vendor evidence. Scoped manual
address aliases are durable and resolvable through the control API, but are not
automatically applied during normalized analyzer-event attribution. DHCPv4
address intervals carry interface/VLAN/plan scope when reconciliation can bind
them to a confirmed network plan, and a successful event match freezes that
scope in its immutable attribution explanation; legacy intervals remain
unknown.
DHCP vendor class,
mDNS/LLMNR/NBNS names, SSDP/UPnP services, device-level DNS/TLS summaries,
IPv6 identities, traffic totals, CA state, and policy assignments are not yet
populated. The UI and API leave those fields absent instead of guessing.
