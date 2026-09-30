from __future__ import annotations

import time
from typing import Any

from shakerproxy_policy import DEVICE_ID_PATTERN, DynamicBypassStore, normalize_host


class StableDynamicBypassStore(DynamicBypassStore):
    """Durable probable-pinning bypasses keyed by ShakerProxy device identity.

    Older releases keyed dynamic bypass state by a DHCP address. That can bind a
    bypass to the wrong device after address reuse. This compatibility subclass
    prefers the stable local device ID and treats the current address only as
    evidence. Legacy address-keyed entries are deliberately discarded when a
    stable device identity is known; preserving an old bypass is less important
    than avoiding transfer to a new DHCP owner.
    """

    @staticmethod
    def stable_key(device_id: str, client_ip: str, host: str) -> str:
        normalized_host = normalize_host(host)
        normalized_device = (device_id or "").strip()
        if DEVICE_ID_PATTERN.fullmatch(normalized_device):
            return f"device:{normalized_device}|{normalized_host}"
        return f"ip:{client_ip}|{normalized_host}"

    @staticmethod
    def legacy_key(client_ip: str, host: str) -> str:
        return f"{client_ip}|{normalize_host(host)}"

    def contains(self, client_ip: str, host: str, device_id: str = "", now: float | None = None) -> bool:
        return self.lookup(client_ip, host, device_id=device_id, now=now) is not None

    def lookup(self, client_ip: str, host: str, device_id: str = "", now: float | None = None) -> dict[str, Any] | None:
        """Return the active bypass entry for this client and host, if any."""
        current = now or time.time()
        with self._lock:
            self._load_locked()
            changed = self._prune_locked(current)
            stable_device = DEVICE_ID_PATTERN.fullmatch((device_id or "").strip()) is not None
            stable_key = self.stable_key(device_id, client_ip, host)
            entry = self._entries.get(stable_key)

            if stable_device:
                # Never migrate an IP-only bypass to a device. The address may
                # have been reassigned since the legacy entry was created.
                legacy_key = self.legacy_key(client_ip, host)
                ip_key = self.stable_key("", client_ip, host)
                if legacy_key in self._entries:
                    self._entries.pop(legacy_key, None)
                    changed = True
                if ip_key in self._entries:
                    self._entries.pop(ip_key, None)
                    changed = True
            elif entry is None:
                # Unknown-device state remains scoped to the exact address. A
                # legacy entry is accepted only while identity is still unknown.
                entry = self._entries.get(self.legacy_key(client_ip, host))

            if changed:
                self._save_locked()
            if isinstance(entry, dict) and float(entry.get("expires_at", 0)) > current:
                return dict(entry)
            return None

    def add(
        self,
        client_ip: str,
        host: str,
        ttl_seconds: int,
        maximum: int,
        reason: str,
        device_id: str = "",
    ) -> None:
        current = time.time()
        with self._lock:
            self._load_locked()
            self._prune_locked(current)
            stable_device = DEVICE_ID_PATTERN.fullmatch((device_id or "").strip()) is not None
            key = self.stable_key(device_id, client_ip, host)
            previous = self._entries.get(key, {})
            created_at = previous.get("created_at", current) if isinstance(previous, dict) else current
            failures = int(previous.get("failures", 0)) + 1 if isinstance(previous, dict) else 1
            entry: dict[str, Any] = {
                "host": normalize_host(host),
                "created_at": created_at,
                "last_failure_at": current,
                "expires_at": current + ttl_seconds,
                "failures": failures,
                "reason": reason,
                "last_client_ip": client_ip,
            }
            if stable_device:
                entry["device_id"] = device_id
                entry["observed_client_ips"] = self._observed_ips(previous, client_ip)
                self._entries.pop(self.legacy_key(client_ip, host), None)
                self._entries.pop(self.stable_key("", client_ip, host), None)
            else:
                # Unknown-device state remains address-scoped for backward
                # compatibility and is deliberately not durable identity.
                entry["client_ip"] = client_ip
            self._entries[key] = entry

            if len(self._entries) > maximum:
                oldest = sorted(
                    self._entries,
                    key=lambda item: float(self._entries[item].get("last_failure_at", 0)),
                )
                for item in oldest[: len(self._entries) - maximum]:
                    self._entries.pop(item, None)
            self._save_locked()

    @staticmethod
    def _observed_ips(entry: Any, client_ip: str) -> list[str]:
        values: list[str] = []
        if isinstance(entry, dict):
            existing = entry.get("observed_client_ips", [])
            if isinstance(existing, list):
                values.extend(str(value) for value in existing if str(value).strip())
            last = str(entry.get("last_client_ip", "")).strip()
            if last:
                values.append(last)
        if client_ip:
            values.append(client_ip)
        # Retain only bounded evidence; identity remains the device ID.
        deduplicated = list(dict.fromkeys(values))
        return deduplicated[-8:]
