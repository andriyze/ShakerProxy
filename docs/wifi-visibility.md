# Wi-Fi visibility

A device's traffic tells you what it talks to. Its radio tells you something
else: which Wi-Fi networks it searches for by name (often the networks it has
saved, so where it has been), when it joins, roams between access points and
disconnects, and why, and which hardware addresses it uses on each network.
With a Wi-Fi adapter that supports monitor mode, ShakerProxy listens to these
802.11 management frames and shows them in Traffic, on each device's page, in
the API and through MCP.

> Status: implemented in source and covered by automated tests with synthetic
> 802.11 frames. It still needs runs with physical adapters before it is
> claimed as supported; see [What needs real hardware](#what-needs-real-hardware).

Wi-Fi visibility is **off by default** and **passive**: ShakerProxy never
transmits, injects frames, probes for networks or disconnects anyone. A
monitor interface only receives.

## What you need

- **A Wi-Fi adapter that supports monitor mode.** Either:
  - a second USB Wi-Fi adapter (recommended); or
  - the adapter that serves ShakerProxy's own [Wi-Fi access point](wifi-access-point.md),
    when its driver lets a monitor interface run beside the access point
    (`iw list` shows `monitor` under "software interface modes"). It then hears
    only the access point's channel.
- **`iw`** (`sudo apt install iw`; the `shakerproxy-host` package recommends it).

ShakerProxy never takes over an adapter that carries the host's own network
connection (it has addresses or a default route). An idle adapter is taken
down while ShakerProxy listens with it and brought back up when listening
stops.

Chipsets commonly used for monitor mode on Linux. These are examples, not
guarantees: firmware, kernel and adapter design matter. The System page and
`shakerproxy wifi` show what each connected adapter supports.

| Chipset (driver) | Notes |
| --- | --- |
| MediaTek MT7612U (`mt76x2u`) | In-kernel, 2.4 and 5 GHz, reliable monitor mode. A good default. |
| MediaTek MT7921AU (`mt7921u`) | In-kernel since Linux 5.18, 2.4/5 GHz (6 GHz on MT7921AUN with a recent kernel). |
| Atheros AR9271 (`ath9k_htc`) | In-kernel, 2.4 GHz only, very well tested for monitor mode. |
| Realtek RTL8812AU / RTL8814AU | Out-of-tree drivers only. Monitor mode depends on the driver build and often breaks with kernel updates; avoid for an appliance. |
| Intel AX200/AX210 (`iwlwifi`) | Monitor mode works on many kernels, but the firmware may filter some frames; use as a fallback. |

## Turn it on

- **System page → Wi-Fi → Listen on Wi-Fi.** The panel says plainly whether an
  adapter can listen and, if not, why.
- **CLI:** `shakerproxy wifi` shows the state and adapters; `shakerproxy wifi on`
  starts listening, `shakerproxy wifi off` stops, and `shakerproxy wifi
  channel 6` (or `auto`, `hop`) picks the channel.
- **API:** `GET` and `PUT /api/v1/wifi-visibility` (an administrator session or a
  `lab:write` token to change it).

If no adapter can listen, turning it on fails with the reason and changes
nothing on the host. A failed start undoes every step it took.

### Channels

A radio listens on one channel at a time.

- **auto** (default): when ShakerProxy runs the lab access point, listen on its
  channel, where lab devices are. Otherwise hop.
- **one channel:** follows a device closely; use it when you know where the
  device is.
- **hop:** cycles through the common channels (1, 6, 11 and the non-DFS 5 GHz
  channels the adapter supports) every half second. You see more networks, but
  you miss frames sent while the radio listens elsewhere: a short association
  may be missed entirely.

## What is recorded

| Event | What it says |
| --- | --- |
| `wifi.probe` | A device searched for a network by name, or for any network (a scan). Signal and channel. The same name from the same address is recorded at most once per 30 seconds. |
| `wifi.auth` | Authentication with an access point finished or failed (open, SAE/WPA3, fast transition), with the status. |
| `wifi.assoc` | A device joined, rejoined or roamed (with the access point it left), or was refused, or got no answer. |
| `wifi.deauth`, `wifi.disassoc` | A device left or was dropped, by whom, and the reason (for example "4-way handshake timeout (often a wrong password)"). |
| `wifi.beacon_summary` | A network that is broadcasting: name, security (open, WPA2, WPA3, transition, enterprise), channel and signal range; once when first seen, then at most every 5 minutes. |

Events are attributed to devices by hardware address, including the private
(randomized) addresses ShakerProxy merged into a device. A device's page shows
the networks it searched for, its joins and disconnects, and the addresses it
used on Wi-Fi.

Phones change their private address for probing. When a probe from an unknown
randomized address has the same radio fingerprint (the capabilities it
advertises) as exactly one lab device, and its sequence numbers continue that
device's within 30 seconds, the event notes it as a **possible match** with low
confidence (20). This is a hint, not proof: identical models share
fingerprints.

The MCP tool `wifi_activity` summarizes a device's Wi-Fi activity for AI agents.

## Privacy defaults

Probe requests from phones nearby are other people's data. By default
ShakerProxy records only:

- frames to or from lab devices: hardware addresses from the lab's neighbor
  tables, and devices that join ShakerProxy's own access point;
- frames of the lab's own access point and network name.

Everything else is dropped as it is parsed and never stored.

**Also record nearby devices and networks** is an explicit opt-in. The
interface asks for confirmation (the API needs `acknowledge_nearby: true`, the
CLI `--confirm`), and nearby events are deleted after 24 hours. Turn it on
only where you are allowed to record the people around you.

## How it works

1. gatewayd adds a monitor interface (`spmon0`) on the chosen adapter's radio
   with `iw`, tunes it, and writes the recording scope
   (`/var/lib/shakerproxy/wifi/scope.json`): lab access point, lab network name,
   lab device addresses and the nearby setting. It refreshes the scope as
   devices come and go, and rebuilds the monitor after a restart or if the
   adapter was unplugged.
2. `shakerproxy-wifi-capture` runs dumpcap on `spmon0` with a capture filter for
   management frames only, into its own ring of 5-second files
   (`/var/lib/shakerproxy/wifi/ring`, at most 120 × 2 MiB). It is separate from the
   lab recording and never touches it.
3. `shakerproxy-wifi-worker` reads the ring and parses the radiotap and 802.11
   headers. Frames off the air are hostile input, so it runs with no network,
   no capabilities and a system-call filter; it can read the ring and the scope
   and write event files into the host event spool, and nothing else.
4. The host event forwarder delivers the events to ingest, which attributes,
   classifies (`wifi`, network management) and stores them.

## Limits

- **Data frames stay encrypted.** WPA2 and WPA3 encrypt the traffic itself;
  monitor mode sees who talks to which network, not what they say. The traffic
  is what the rest of ShakerProxy records once the device is on the lab network.
- **Management frame protection** (802.11w, mandatory with WPA3) encrypts
  deauthentication and disassociation frames: you see that a device left, but
  not the reason.
- **One channel at a time.** See [Channels](#channels).
- **Range.** A USB adapter hears what is near it. Place it near the device under
  test.
- **6 GHz** networks are shown when the adapter supports them, but hopping covers
  only 2.4 and 5 GHz.

## What needs real hardware

The parser, privacy filter, rate limits, monitor management and every API
are tested with synthetic radiotap frames and fake radios. These still need
runs with physical adapters:

- monitor interface creation and channel changes on the chipsets above, and
  beside a running hostapd;
- dumpcap's management-frame filter on real radiotap headers from each driver;
- the `mac80211_hwsim` end-to-end test (`tests/netlab/wifi-hwsim.sh`) on a host
  that can load the module.
