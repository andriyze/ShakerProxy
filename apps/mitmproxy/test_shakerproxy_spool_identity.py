"""Tests for audit fixes in shakerproxy_policy that run without mitmproxy."""

from __future__ import annotations

import json
import pathlib
import tempfile
import time
import unittest
from unittest import mock

import shakerproxy_policy
from shakerproxy_policy import (
    AsyncEventSpool,
    EventSpool,
    PolicyCache,
    is_private_destination,
    new_event_id,
    normalize_address,
)
from shakerproxy_stable_bypass import StableDynamicBypassStore

DEVICE_ID = "device-0123456789abcdef0123456789abcdef"


def write_policy(path: pathlib.Path, **extra) -> None:
    document = {
        "schema_version": 1,
        "revision": 3,
        "enabled": True,
        "encrypted_dns": {"mode": "observe"},
        "tls": {"mode": "all", "mobile_clients": [{"cidr": "10.44.0.0/24", "platform": "ios"}]},
        "device_by_ip": {"10.44.0.15": DEVICE_ID, "10.77.0.9": DEVICE_ID.replace("0123", "aaaa")},
        "device_platforms": {},
    }
    document.update(extra)
    path.write_text(json.dumps(document), encoding="utf-8")


class ClientIdentityTests(unittest.TestCase):
    def test_inventory_device_with_unknown_platform_uses_mobile_cidr(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            write_policy(path)
            snapshot = PolicyCache(str(path)).load()
            self.assertEqual(snapshot.client_identity("10.44.0.15"), (DEVICE_ID, "ios"))

    def test_desktop_and_unknown_platforms_are_never_mobile(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            desktop = DEVICE_ID.replace("0123", "aaaa")
            write_policy(path, device_platforms={desktop: "windows"})
            snapshot = PolicyCache(str(path)).load()
            self.assertEqual(snapshot.client_identity("10.77.0.9"), (desktop, ""))
            self.assertEqual(snapshot.client_identity("::ffff:10.77.0.9"), (desktop, ""))

    def test_declared_mobile_platform_wins(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            write_policy(path, device_platforms={DEVICE_ID: "android-tv"})
            self.assertEqual(PolicyCache(str(path)).load().client_identity("10.44.0.15"), (DEVICE_ID, "android-tv"))

    def test_policy_up_to_two_megabytes_loads(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            devices = {f"10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}": DEVICE_ID for index in range(8192)}
            write_policy(path, device_by_ip=devices)
            data = json.dumps(json.loads(path.read_text()), indent=2)
            path.write_text(data + " " * (300 * 1024), encoding="utf-8")
            self.assertGreater(path.stat().st_size, 256 * 1024)
            snapshot = PolicyCache(str(path)).load()
            self.assertEqual(len(snapshot.device_by_ip), 8192)

    def test_new_scope_fields_default_off(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            write_policy(path)
            snapshot = PolicyCache(str(path)).load()
            self.assertFalse(snapshot.intercept_private_destinations)
            self.assertFalse(snapshot.intercept_http)
            self.assertTrue(snapshot.in_scope(""))
            write_policy(path, tls={"mode": "selective", "selected_device_ids": [DEVICE_ID], "intercept_private_destinations": True, "intercept_http": True})
            snapshot = PolicyCache(str(path)).load()
            self.assertTrue(snapshot.intercept_private_destinations and snapshot.intercept_http)
            self.assertTrue(snapshot.in_scope(DEVICE_ID))
            self.assertFalse(snapshot.in_scope("device-ffffffffffffffffffffffffffffffff"))

    def test_private_destinations_and_address_normalization(self):
        for address in ("10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "fd00::1", "fe80::1", "::ffff:192.168.1.1"):
            self.assertTrue(is_private_destination(address), address)
        for address in ("8.8.8.8", "2606:4700::1111", "", "not-an-ip"):
            self.assertFalse(is_private_destination(address), address)
        self.assertEqual(normalize_address("::ffff:10.0.0.1"), "10.0.0.1")
        self.assertEqual(normalize_address("FE80::1%eth0"), "fe80::1")


class EventSpoolTests(unittest.TestCase):
    def test_event_ids_are_chronological_and_valid_for_ingest(self):
        first = new_event_id(1_700_000_000_000_000_000)
        second = new_event_id(1_700_000_000_001_000_000)
        self.assertLess(first, second)
        self.assertRegex(first, r"^[A-Za-z0-9_-]{16,128}$")

    def test_non_ascii_bodies_stay_compact_and_oversized_events_shrink(self):
        with tempfile.TemporaryDirectory() as root:
            spool = EventSpool(root, "test")
            emoji = "\U0001f600" * (16 * 1024)  # 64 KiB of UTF-8
            event_id = spool.emit("http_response", {"response_body": {"preview": emoji, "preview_encoding": "utf-8", "preview_bytes": 65536, "truncated": False}})
            path = pathlib.Path(root) / "pending" / f"{event_id}.json"
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), shakerproxy_policy.MAX_EVENT_BYTES)
            self.assertEqual(json.loads(raw)["payload"]["response_body"]["preview"], emoji)

            cyrillic = "ж" * 32768
            headers = {"items": [{"name": f"x-{index}", "value": "я" * 1000, "sensitive": False, "truncated": False} for index in range(60)], "bytes": 0, "truncated": False}
            payload = {
                "response_body": {"preview": cyrillic * 4, "preview_encoding": "utf-8", "preview_bytes": 262144, "truncated": False},
                "response_headers": headers,
                "http_url": "https://example.test/" + "a" * 4000,
            }
            event_id = spool.emit("http_response", payload)
            raw = (pathlib.Path(root) / "pending" / f"{event_id}.json").read_bytes()
            self.assertLessEqual(len(raw), shakerproxy_policy.MAX_EVENT_BYTES)
            body = json.loads(raw)["payload"]["response_body"]
            self.assertTrue(body["truncated"] and body["preview_shrunk_to_fit_event"])
            self.assertEqual(body["preview_bytes"], len(body["preview"].encode("utf-8")))

    def test_spool_bounds_are_enforced_without_scanning_every_event(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(shakerproxy_policy, "MAX_EVENT_FILES", 5):
            spool = EventSpool(root, "test")
            scans = []
            original = spool._rescan_locked

            def counting(now):
                scans.append(now)
                original(now)

            spool._rescan_locked = counting
            written = [spool.emit("tls_intercepted", {"sni": f"host{index}.example"}) for index in range(3)]
            self.assertEqual(len(scans), 1, "only the first write scans the spool")
            written += [spool.emit("tls_intercepted", {"sni": f"host{index}.example"}) for index in range(3, 12)]
            remaining = sorted(path.stem for path in (pathlib.Path(root) / "pending").glob("evt_*.json"))
            self.assertLessEqual(len(remaining), 5)
            self.assertEqual(remaining, sorted(written)[-len(remaining):], "pruning removes the oldest events first")

    def test_async_spool_writes_off_thread_and_flushes(self):
        with tempfile.TemporaryDirectory() as root:
            spool = AsyncEventSpool(EventSpool(root, "test"))
            ids = [spool.emit("tls_intercepted", {"device_id": DEVICE_ID}) for _ in range(20)]
            self.assertTrue(spool.flush(5))
            spool.close()
            names = {path.stem for path in (pathlib.Path(root) / "pending").glob("evt_*.json")}
            self.assertEqual(names, set(ids))
            event = json.loads((pathlib.Path(root) / "pending" / f"{ids[0]}.json").read_text(encoding="utf-8"))
            self.assertEqual(event["device_id"], DEVICE_ID)


class ReviewFixTests(unittest.TestCase):
    def test_async_queue_is_bounded_by_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            spool = AsyncEventSpool(EventSpool(root, "test"), capacity_bytes=200_000)
            gate = __import__("threading").Event()
            original = spool.spool.write

            def blocked_write(envelope):
                gate.wait(5)
                return original(envelope)

            spool.spool.write = blocked_write
            big = {"response_body": {"preview": "x" * 60_000}}
            for _ in range(5):
                spool.emit("http_response", big)
            self.assertGreaterEqual(spool.dropped, 2, "queue accepted far more bytes than its bound")
            gate.set()
            self.assertTrue(spool.flush(5))
            spool.close()

    def test_full_spool_prunes_to_low_water_mark(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(shakerproxy_policy, "MAX_EVENT_FILES", 20):
            spool = EventSpool(root, "test")
            for index in range(20):
                spool.emit("tls_intercepted", {"sni": f"host{index}.example"})
            spool.emit("tls_intercepted", {"sni": "overflow.example"})
            remaining = list((pathlib.Path(root) / "pending").glob("evt_*.json"))
            self.assertLessEqual(len(remaining), 18, "pruning stopped at the limit instead of the low-water mark")

    def test_only_lab_clients_may_use_the_proxy(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            write_policy(path, lab_sources=["2001:db8:1::/64", "not-a-prefix"])
            snapshot = PolicyCache(str(path)).load()
            for address in ("10.77.0.5", "127.0.0.1", "fd00::5", "fe80::1", "2001:db8:1::5", "::ffff:192.168.1.2"):
                self.assertTrue(snapshot.client_allowed(address), address)
            for address in ("8.8.8.8", "2001:db8:2::5", "", "junk"):
                self.assertFalse(snapshot.client_allowed(address), address)


class BypassLookupTests(unittest.TestCase):
    def test_lookup_returns_reason(self):
        with tempfile.TemporaryDirectory() as root:
            store = StableDynamicBypassStore(str(pathlib.Path(root) / "bypasses.json"))
            store.add("10.0.0.5", "lan.example", 300, 16, "upstream_certificate_untrusted", device_id=DEVICE_ID)
            entry = store.lookup("10.0.0.7", "lan.example", device_id=DEVICE_ID)
            self.assertEqual(entry["reason"], "upstream_certificate_untrusted")
            self.assertIsNone(store.lookup("10.0.0.7", "lan.example", now=time.time() + 600, device_id=DEVICE_ID))


if __name__ == "__main__":
    unittest.main()
