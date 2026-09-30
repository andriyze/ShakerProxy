from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

from shakerproxy_content_policy import ContentRetentionPolicyCache


class ContentRetentionPolicyCacheTest(unittest.TestCase):
    def test_missing_policy_preserves_community_default(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cache = ContentRetentionPolicyCache(str(pathlib.Path(root) / "policy.json"))
            policy = cache.load()
            self.assertEqual(policy.revision, 1)
            self.assertTrue(policy.capture_http_content)

    def test_policy_reloads_after_atomic_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "policy.json"
            self.write(path, {"schema": 1, "revision": 2, "capture_http_content": False, "updated_by": "admin", "updated_at": "2026-09-03T18:00:00Z"})
            cache = ContentRetentionPolicyCache(str(path))
            self.assertFalse(cache.load().capture_http_content)

            replacement = pathlib.Path(root) / ".replacement"
            self.write(replacement, {"schema": 1, "revision": 3, "capture_http_content": True, "updated_by": "admin", "updated_at": "2026-09-03T18:01:00Z"})
            os.replace(replacement, path)
            policy = cache.load()
            self.assertEqual(policy.revision, 3)
            self.assertTrue(policy.capture_http_content)

    def test_policy_rejects_unknown_fields_wrong_types_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root_path = pathlib.Path(root)
            invalid = root_path / "invalid.json"
            self.write(invalid, {"schema": 1, "revision": 1, "capture_http_content": "yes"})
            with self.assertRaises(ValueError):
                ContentRetentionPolicyCache(str(invalid)).load()

            self.write(invalid, {"schema": 1, "revision": 1, "capture_http_content": True, "secret": "unexpected"})
            with self.assertRaises(ValueError):
                ContentRetentionPolicyCache(str(invalid)).load()

            target = root_path / "target.json"
            self.write(target, {"schema": 1, "revision": 1, "capture_http_content": True})
            link = root_path / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                ContentRetentionPolicyCache(str(link)).load()

    @staticmethod
    def write(path: pathlib.Path, value: dict[str, object]) -> None:
        path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        path.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
