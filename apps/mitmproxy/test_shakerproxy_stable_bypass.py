from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from shakerproxy_stable_bypass import StableDynamicBypassStore


DEVICE_ID = "device-0123456789abcdef0123456789abcdef"


class StableDynamicBypassTests(unittest.TestCase):
    def test_device_scoped_bypass_survives_address_change(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "bypasses.json"
            store = StableDynamicBypassStore(str(path))
            store.add("10.0.0.5", "pinned.example", 300, 16, "probable_pin", device_id=DEVICE_ID)
            self.assertTrue(store.contains("10.0.0.5", "pinned.example", device_id=DEVICE_ID))
            self.assertTrue(store.contains("10.0.0.99", "pinned.example", device_id=DEVICE_ID))
            self.assertFalse(store.contains("10.0.0.5", "other.example", device_id=DEVICE_ID))

            saved = json.loads(path.read_text(encoding="utf-8"))
            keys = list(saved["entries"])
            self.assertEqual(keys, [f"device:{DEVICE_ID}|pinned.example"])
            entry = saved["entries"][keys[0]]
            self.assertEqual(entry["device_id"], DEVICE_ID)
            self.assertNotIn("client_ip", entry)

    def test_address_scoped_bypass_is_not_inherited_by_known_device(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "bypasses.json"
            store = StableDynamicBypassStore(str(path))
            store.add("10.0.0.5", "pinned.example", 300, 16, "probable_pin")
            self.assertTrue(store.contains("10.0.0.5", "pinned.example"))
            self.assertFalse(store.contains("10.0.0.6", "pinned.example"))
            self.assertFalse(store.contains("10.0.0.5", "pinned.example", device_id=DEVICE_ID))
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("10.0.0.5|pinned.example", saved["entries"])
            self.assertNotIn("ip:10.0.0.5|pinned.example", saved["entries"])

    def test_legacy_address_entry_is_discarded_for_known_device(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "bypasses.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "entries": {
                            "10.0.0.5|pinned.example": {
                                "client_ip": "10.0.0.5",
                                "host": "pinned.example",
                                "created_at": 1,
                                "last_failure_at": 1,
                                "expires_at": 4102444800,
                                "failures": 3,
                                "reason": "probable_pin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = StableDynamicBypassStore(str(path))
            self.assertFalse(store.contains("10.0.0.5", "pinned.example", device_id=DEVICE_ID, now=2))
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("10.0.0.5|pinned.example", saved["entries"])
            self.assertNotIn(f"device:{DEVICE_ID}|pinned.example", saved["entries"])


if __name__ == "__main__":
    unittest.main()
