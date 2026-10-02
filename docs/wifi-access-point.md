# Wi-Fi access point

Most phones, TVs, speakers, and IoT devices join networks over Wi-Fi. ShakerProxy
can broadcast the lab network itself, so a device under test only needs to join
a Wi-Fi network: no external access point, no bridging by hand. Everything the
device does then passes through ShakerProxy for capture, analysis, DNS policy, and
optional HTTPS decryption.

The access point is part of the network plan. It goes through the same
preview, rollback-protected apply, health checks, and explicit confirmation as
every other network change. If you do not confirm in time, or a health check
fails, ShakerProxy stops the access point and restores the previous network.

> Status: implemented in source and covered by automated tests. Like the other
> routed topologies, it still needs physical-adapter acceptance runs on Ubuntu
> 24.04 and 26.04 before it is claimed as supported; see
> [physical-client acceptance](testing/mvp-physical-client-acceptance.md).

## What you need

- **A Wi-Fi adapter that can run as an access point (AP mode).** Many adapters
  only work as clients. Check before you plan:
  - In the ShakerProxy preflight (`GET /api/v1/preflight`, or the Network page), the
    adapter shows `"wireless": true` and `"ap_supported": true`.
    `"ap_supported": null` means ShakerProxy could not check; install `iw`.
  - On the host: `iw list`, then look for `* AP` under
    `Supported interface modes`.
- **The access point software:** `sudo apt install hostapd iw`. The
  `shakerproxy-host` package recommends both; validation tells you if they are
  missing.
- **A separate uplink (WAN)** for the lab's Internet access, and ideally a
  separate management interface so your own SSH or browser session never uses
  the lab network.

Examples of chipsets whose in-kernel Linux drivers are commonly used in AP
mode. These are examples, not guarantees: firmware, kernel version, adapter
design, and regulatory settings all matter, so always check `ap_supported`.

| Chipset family (driver) | Notes |
| --- | --- |
| MediaTek MT7612U / MT7610U (`mt76x2u`, `mt76x0u`) | Popular USB adapters; 2.4 and 5 GHz AP. |
| MediaTek MT7921AU / MT7922 (`mt7921u`, `mt7921e`) | Wi-Fi 6; AP mode needs a recent kernel (Ubuntu 24.04's is fine). |
| Qualcomm Atheros AR9271 (`ath9k_htc`) | USB, 2.4 GHz only. |
| Qualcomm Atheros PCIe (`ath9k`, `ath10k`) | Common in mini-PCs and routers. |
| Intel Wi-Fi 6/6E AX200/AX210 (`iwlwifi`) | AP usually works on 2.4 GHz only; the firmware normally refuses to start an AP on 5 GHz. |

Adapters that need out-of-tree Realtek drivers often lack AP mode or behave
unpredictably; prefer adapters supported by the mainline kernel.

## Choose a layout

| Layout | Interfaces | Lab network |
| --- | --- | --- |
| **Wi-Fi only** | `WAN` + `WIFI_AP` (+ optional `MANAGEMENT`) | The Wi-Fi network is the whole lab. |
| **Wi-Fi and wired lab port** | `WAN` + `LAB` + `WIFI_AP` with `bridge_with_lab: true` | Wired and Wi-Fi devices share one lab network through bridge `lgbr0`. |
| **Wi-Fi on an inline bridge** | `TRANSPARENT_BRIDGE`: `WAN` (router port) + `LAB` (device port) + `WIFI_AP` with `bridge_with_lab: true` | The access point joins `spbr0`; Wi-Fi devices get addresses from your own router through ShakerProxy. See [Inline bridge](bridge-mode.md#wi-fi-on-the-bridge). |

Wi-Fi works with the `TWO_NIC`, `THREE_INTERFACE`, `EXISTING_ROUTED_VLAN`,
`TRANSPARENT_BRIDGE`, and `ADVANCED_CUSTOM` topologies. It is not available
for single-arm, VLAN trunk, or passive-sensor plans, because those have no
separate lab segment for the access point.

In the bridged layout the lab gateway address, DHCP, firewall rules, capture,
and HTTPS decryption all move to `lgbr0`, so a phone on Wi-Fi and a TV on the
wired port are on the same network and can discover each other (casting,
AirPlay, and similar features keep working).

## Set it up

1. Install the tools: `sudo apt install hostapd iw`.
2. Check the preflight and note the adapter's `stable_id`, `current_name`,
   `ap_supported`, and `wireless_bands`.
3. Build the plan. A minimal Wi-Fi-only example:

   ```json
   {
     "schema": 1,
     "name": "Wi-Fi lab",
     "topology": "TWO_NIC",
     "interfaces": [
       {"stable_id": "<from preflight>", "current_name": "enp1s0", "role": "WAN"},
       {"stable_id": "<from preflight>", "current_name": "wlan0", "role": "WIFI_AP"}
     ],
     "management": {"preserve_active_ssh": true},
     "ipv4": {"enabled": true, "lab_cidr": "10.77.0.0/24", "gateway_address": "10.77.0.1",
              "dhcp_start": "10.77.0.100", "dhcp_end": "10.77.0.200",
              "nat44": true, "client_isolation": false},
     "ipv6": {"strategy": "DISABLED"},
     "wifi": {"enabled": true, "ssid": "ShakerProxy", "security": "WPA2_PSK",
              "passphrase": "choose-a-strong-password", "country_code": "US",
              "band": "2.4GHZ", "channel": 6, "hidden": false,
              "client_isolation": false, "bridge_with_lab": false}
   }
   ```

   For the bridged layout, add the wired port with role `LAB` and set
   `"bridge_with_lab": true`.
4. Preview the plan. The preview includes `hostapd_conf`, the exact access point
   configuration with the password shown as `<redacted>`, plus the Netplan,
   DHCP, and firewall changes and a plain-language impact list.
5. Stage, apply, and confirm as usual. ShakerProxy starts the access point only
   after the rollback deadline is armed, waits for the adapter to come up, and
   then starts DHCP. The health checks include a `WIFI_AP` check.
6. Join the network from the device under test. It receives an address from
   ShakerProxy and appears on the Devices page.

## Settings

### Security

| `security` | Use it when | Notes |
| --- | --- | --- |
| `WPA2_PSK` | Default choice. | Works with almost every device. AES (CCMP) only; no TKIP. |
| `WPA2_WPA3` | You want WPA3 for new devices without locking out old ones. | Transition mode: WPA3 (SAE) with protected management frames for capable devices, WPA2 for the rest. |
| `WPA3_SAE` | You are testing WPA3-only behavior. | Management frame protection is required; many older phones, TVs, and IoT devices cannot join. |
| `OPEN` | The device can only join open networks (some setup modes). | Anyone in range can join and read unencrypted traffic. Validation warns. |

The password must be 8 to 63 printable ASCII characters (letters, digits,
spaces, and symbols). It is stored in the plan so you can read it back when
connecting devices; it appears in previews only as `<redacted>` and is written
to `/etc/shakerproxy/hostapd/shakerproxy.conf`, which only root can read.

### Country, band, and channel

- `country_code` is required: the two-letter ISO 3166 code of the country where
  ShakerProxy is used (for example `US`, `GB`, `DE`). It sets the legal channels and
  transmit power; use the real location.
- `band` is `2.4GHZ` (default; the most compatible, required by many IoT
  devices) or `5GHZ` (faster, less crowded).
- `channel` defaults to 6 on 2.4 GHz and 36 on 5 GHz. 2.4 GHz accepts 1 to 13
  (1, 6, and 11 do not overlap; 12 and 13 are not allowed in some countries,
  including the US and Canada). 5 GHz accepts only channels that never require
  radar detection: 36, 40, 44, 48, 149, 153, 157, 161, 165. Channels 149 to 165
  are not allowed for access points in some countries, including Japan and
  parts of Europe; 36 to 48 are the safest choice.
- The access point uses 20 MHz channels for maximum compatibility.

### Other options

- `hidden: true` stops broadcasting the network name. It does not make the lab
  private, and some devices cannot join hidden networks.
- `client_isolation: true` stops Wi-Fi devices from talking to each other
  directly. In the bridged layout, Wi-Fi devices can still reach wired lab
  devices; to block that too, also set `ipv4.client_isolation`.
- `bridge_with_lab` is required when the plan also has a wired `LAB` interface.

## How it works

- Netplan never configures the adapter as a Wi-Fi client. In the Wi-Fi-only
  layout it only gives the adapter the lab gateway address (as a
  `systemd-networkd` link, which also tells NetworkManager to leave it alone).
  In the bridged layout Netplan creates `lgbr0` with the wired port (spanning
  tree off, so ports forward immediately) and `hostapd` adds the adapter.
- `shakerproxy-hostapd.service` runs `hostapd` in the foreground with only the
  `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities and a read-only filesystem.
  Package installation never enables it; confirming a Wi-Fi plan does.
- ShakerProxy runs only fixed commands for the access point:
  `systemctl restart|enable|disable --now|is-active --quiet shakerproxy-hostapd.service`,
  and `iw phy <phyN> info` for preflight.
- Rollback (by the watchdog, a failed health check, or an expired deadline)
  stops and disables the access point before DHCP and restores or removes
  `/etc/shakerproxy/hostapd/shakerproxy.conf`.

## Troubleshooting

Start with the access point log:

```sh
sudo journalctl -u shakerproxy-hostapd -n 100 --no-pager
```

(`shakerproxy logs hostapd` shows the same log where the CLI provides it.) To see
connected devices:

```sh
sudo hostapd_cli -p /run/shakerproxy-hostapd -i wlan0 all_sta
```

| Symptom | Likely cause and fix |
| --- | --- |
| Validation: "Wi-Fi access point software is not installed" | `sudo apt install hostapd iw`, then preview again. |
| Validation: "cannot run as an access point" | The driver has no AP mode. Use another adapter (see above). |
| Validation: "currently carries this host's default route" | The adapter is still connected to another Wi-Fi network. Disconnect it (for example `sudo nmcli device disconnect wlan0`, or remove it from the host's Netplan) and give ShakerProxy a wired uplink. |
| Apply fails: "hostapd stopped while starting the access point" | Read the log. Common causes are below. |
| Log: `rfkill: WLAN soft blocked` or `Operation not possible due to RF-kill` | Run `rfkill list`, then `sudo rfkill unblock wifi`. A hardware switch or BIOS setting may also block Wi-Fi. |
| Log: `Could not set channel for kernel driver` or channel not allowed | The channel is not permitted for `country_code`, or the firmware refuses 5 GHz AP (Intel). Choose 2.4 GHz channel 1, 6, or 11, or 5 GHz channel 36. |
| Apply fails while generating Netplan | The adapter is also configured in another Netplan file, often under `wifis:` as a Wi-Fi client. Remove it from that file (keep a backup), then preview again. |
| Log: `nl80211: Could not configure driver mode` | Another program owns the adapter (NetworkManager or `wpa_supplicant`). See the next row. |
| The access point starts, then disappears | NetworkManager took the adapter back. Run `sudo nmcli device set wlan0 managed no` and add `unmanaged-devices=interface-name:wlan0` under `[keyfile]` in `/etc/NetworkManager/conf.d/shakerproxy-wifi.conf`. Also make sure the distribution `hostapd.service` is not running for the same adapter. |
| The device does not see the network | It may not support 5 GHz or WPA3. Use `2.4GHZ` and `WPA2_PSK`. Check that `hidden` is false. |
| The device joins but gets no address | Check `sudo journalctl -u shakerproxy-dhcp4` and that the DHCP range is inside the lab network. In the bridged layout, check `bridge link` shows the adapter in `lgbr0`. |
| Slow or unstable connection | Move away from busy channels: try 1, 6, or 11 on 2.4 GHz, or 36 to 48 on 5 GHz. USB adapters work better on a short USB extension cable away from the host. |

## Limitations

- One access point per ShakerProxy; one SSID.
- No WPA-Enterprise (802.1X), no radar-detection (DFS) channels, no 6 GHz, and
  20 MHz channel width only.
- Traffic sent directly between two Wi-Fi devices stays inside the access point
  and is not captured. Traffic to the Internet, to ShakerProxy, and between Wi-Fi
  and wired lab devices is. To observe device-to-device traffic, put one of the
  devices on the wired lab port in the bridged layout.
- IPv6 on the lab network follows the plan's IPv6 strategy; with a routed
  strategy the access point (or `lgbr0`) gets the lab IPv6 address and
  router advertisements. See [IPv6 in the lab](ipv6.md).
- Rendering, validation, apply ordering, rollback, and the command boundary are
  covered by automated tests. Radio behavior (driver quirks, regulatory
  enforcement, NetworkManager interaction) can only be proven on real adapters
  and is part of the physical acceptance runs.
