#!/usr/bin/env python3
"""Hermetic publication/installer regressions; no Docker, network, or root needed.

Installer tests execute the real parser/preflight prefix in a temporary copy.
Only the root check and log/uninstaller locations are replaced. Execution is
cut off before dependency installation, even when a regression reaches there.
Release tests execute workflow shell blocks against a fake GitHub CLI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(os.environ.get("SHAKERPROXY_SAFETY_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
SCANNER = ROOT / "tests/security/public-repo-history-scan.sh"
TOKEN = "gh" + "p_" + "A" * 36  # Synthetic, deliberately assembled in source.


def run(args: list[str], cwd: Path, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30, **kwargs)


def workflow_block(name: str) -> str:
    lines = (ROOT / ".github/workflows/release.yml").read_text().splitlines()
    marker = "      - name: " + name
    if marker not in lines:
        raise AssertionError("missing workflow step: " + name)
    start = lines.index(marker) + 1
    step = []
    for line in lines[start:]:
        if line.startswith("      - "):
            break
        step.append(line)
    for index, line in enumerate(step):
        if not line.startswith("        run: "):
            continue
        value = line.removeprefix("        run: ")
        if value != "|":
            return value + "\n"
        result = []
        for content in step[index + 1:]:
            if content and not content.startswith("          "):
                break
            result.append(content[10:] if content else "")
        return "\n".join(result) + "\n"
    raise AssertionError("missing workflow run block: " + name)


class HistoryAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Synthetic Audit Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        result = run(["git", *args], self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def commit_file(self, name: str, content: bytes) -> None:
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        self.git("add", "--", name)
        self.git("commit", "-qm", "Synthetic audit fixture")

    def audit(self, expected: int = 1) -> str:
        result = run(["bash", str(SCANNER)], self.repo)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, expected, output)
        self.assertNotIn(TOKEN, output, "credential bytes must never be logged")
        return output

    def test_clean_repository_and_scanner_source_pass(self) -> None:
        self.commit_file("notes.txt", b"Harmless content\n")
        self.commit_file(".env.example", b"EXAMPLE=value\n")
        self.commit_file("tests/security/public-repo-history-scan.sh", SCANNER.read_bytes())
        self.audit(0)

    def test_large_text_marker_is_not_lost_to_sigpipe(self) -> None:
        self.commit_file("large.txt", (TOKEN + "\n" + "harmless filler\n" * 100000).encode())
        self.assertIn("credential", self.audit())

    def test_binary_embedded_marker_is_scanned(self) -> None:
        self.commit_file("blob.dat", b"\x00\xff\x01" + TOKEN.encode() + b"\x00\n")
        self.assertIn("credential", self.audit())

    def test_same_blob_renamed_from_sensitive_path_is_detected(self) -> None:
        self.commit_file("nested/.env", b"benign but prohibited artifact\n")
        self.git("mv", "nested/.env", "nested/notes.txt")
        self.git("commit", "-qm", "Rename without changing blob")
        self.assertIn("sensitive historical filename", self.audit())

    def test_all_alias_paths_in_one_tree_are_checked(self) -> None:
        self.commit_file("a.txt", b"identical\n")
        self.commit_file("z.HAR", b"identical\n")
        self.assertIn("sensitive historical filename", self.audit())

    def test_oversize_blob_fails_instead_of_silent_skip(self) -> None:
        self.commit_file("large.dat", b"x" * (5 * 1024 * 1024 + 1))
        self.assertIn("size limit", self.audit())

    def test_unusual_filename_is_nul_framed(self) -> None:
        self.commit_file("nested/line\nbreak\t.PCAP", b"fixture\n")
        self.assertIn("sensitive historical filename", self.audit())

    def test_tag_reachable_history_is_scanned(self) -> None:
        self.commit_file("safe.txt", b"safe\n")
        self.git("checkout", "-qb", "fixture")
        self.commit_file("tag-only.txt", TOKEN.encode())
        self.git("tag", "retained-fixture")
        self.git("checkout", "-q", "main")
        self.git("branch", "-D", "fixture")
        self.audit()

    def test_scanner_path_has_no_credential_exemption(self) -> None:
        self.commit_file("tests/security/public-repo-history-scan.sh", TOKEN.encode())
        self.audit()

    def test_empty_history_is_not_certified(self) -> None:
        self.audit(2)

    def test_shallow_history_is_rejected(self) -> None:
        self.commit_file("safe.txt", b"safe\n")
        shallow = self.repo.parent / "shallow"
        result = run(["git", "clone", "-q", "--depth=1", self.repo.as_uri(), str(shallow)], self.repo.parent)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run(["bash", str(SCANNER)], shallow)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


class InstallerPreviewTests(unittest.TestCase):
    def invoke(self, *args: str) -> tuple[subprocess.CompletedProcess[str], bool, bool]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = (ROOT / "packaging/install.sh").read_text()
            marker = "\nMISSING_BOOTSTRAP=0\n"
            self.assertEqual(source.count(marker), 1)
            source = source.split(marker)[0] + "\nexit 98\n"
            guard = '[[ "$EUID" -eq 0 ]] || die "run as root (for example: curl ... | sudo bash)"'
            self.assertEqual(source.count(guard), 1)
            source = source.replace(guard, ": # Test-copy-only root check substitution")
            source = source.replace("/var/log/shakerproxy", str(root / "logs"))
            source = source.replace("/usr/libexec/shakerproxy/shakerproxy-uninstall", str(root / "uninstall-stub"))
            stub = root / "uninstall-stub"
            stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" > "{root / "uninstall-called"}"\n')
            stub.chmod(0o700)
            script = root / "install-test-copy.sh"
            script.write_text(source)
            env = os.environ.copy()
            env.pop("SHAKERPROXY_INSTALL_VERIFY_ONLY", None)
            result = run(["bash", str(script), "--developer-unsupported", *args], root, env=env)
            return result, (root / "logs").exists(), (root / "uninstall-called").exists()

    def test_dry_run_never_writes_or_uninstalls(self) -> None:
        # Off Linux the preview stops at the OS check; either way nothing is written.
        result, logged, uninstalled = self.invoke("--dry-run")
        self.assertFalse(logged, "dry-run must not initialize persistent logs: " + result.stderr)
        self.assertFalse(uninstalled, "dry-run must not dispatch uninstall")

    def test_dry_run_refuses_lifecycle_modes(self) -> None:
        cases = [["--repair"], ["--rollback"], ["--uninstall"],
                 ["--uninstall", "--purge-data"], ["--purge-data", "--uninstall"]]
        for args in cases:
            for preview_first in (False, True):
                flags = ["--dry-run", *args] if preview_first else [*args, "--dry-run"]
                with self.subTest(flags=flags):
                    result, logged, uninstalled = self.invoke(*flags)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("--dry-run previews an install or update only", result.stderr)
                    self.assertFalse(logged, "a refused dry-run must not initialize persistent logs")
                    self.assertFalse(uninstalled, "a refused dry-run must not dispatch uninstall")

    def test_real_uninstall_dispatch_is_preserved(self) -> None:
        for flags in (["--uninstall"], ["--uninstall", "--purge-data"]):
            with self.subTest(flags=flags):
                result, logged, uninstalled = self.invoke(*flags)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(logged)
                self.assertTrue(uninstalled)

    def test_custom_data_directory_is_rejected_before_writes(self) -> None:
        for directory in ("/mnt/custom-shakerproxy", "/var/lib/shakerproxy"):
            with self.subTest(directory=directory):
                result, logged, uninstalled = self.invoke("--data-dir", directory, "--dry-run")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--data-dir is unsupported", result.stderr)
                self.assertFalse(logged or uninstalled)

    def test_proxy_flags_must_be_http_urls(self) -> None:
        for flag in ("--http-proxy", "--https-proxy"):
            with self.subTest(flag=flag):
                result, logged, uninstalled = self.invoke(flag, "ftp://proxy.example.invalid:3128", "--dry-run")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be an http:// or https:// URL", result.stderr)
                self.assertFalse(logged or uninstalled)
                result, logged, uninstalled = self.invoke(flag, "http://proxy.example.invalid:3128", "--dry-run")
                self.assertNotIn("must be an http:// or https:// URL", result.stderr)
                self.assertFalse(logged or uninstalled)

    def test_invalid_lifecycle_combinations_do_not_write(self) -> None:
        for flags in (["--purge-data"], ["--repair", "--rollback"], ["--uninstall", "--repair"]):
            with self.subTest(flags=flags):
                result, logged, uninstalled = self.invoke(*flags, "--dry-run")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(logged or uninstalled)


class ReleaseWorkflowTests(unittest.TestCase):
    def invoke(self, channel: str = "beta", failure: str = "", block: str = "Publish GitHub release assets",
               releases: str = "") -> tuple[subprocess.CompletedProcess[str], list[list[str]], str]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            version = "0.1.0" if channel == "stable" else "0.1.0-beta.test"
            bundle = root / "dist" / ("release-" + version)
            bundle.mkdir(parents=True)
            (bundle / "manifest.json").write_text("{}")
            (root / "dist/images.json").write_text("{}")
            cli = root / "gh"
            cli.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a") as handle:
    handle.write(json.dumps(args) + "\\n")
operation = args[1] if args[0] == "release" else args[0]
if operation == os.environ.get("FAKE_GH_FAIL"):
    sys.exit(1)
if operation == "api":
    print(os.environ.get("FAKE_RELEASES", ""))
''')
            cli.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       VERSION=version, CHANNEL=channel, GITHUB_SHA="a" * 40,
                       GITHUB_REPOSITORY="andriyze/ShakerProxy", RUNNER_TEMP=str(root),
                       FAKE_GH_LOG=str(root / "gh.jsonl"), FAKE_GH_FAIL=failure,
                       FAKE_RELEASES=releases)
            result = run(["bash", "-e", "-o", "pipefail", "-c", workflow_block(block)], root, env=env)
            log = root / "gh.jsonl"
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            notes = root / "beta-release-notes.md"
            return result, calls, notes.read_text() if notes.exists() else ""

    def test_beta_notes_preserve_literal_paths_and_sha(self) -> None:
        result, _, notes = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("`docs/tls-interception.md`", notes)
        self.assertIn("`docs/installation.md`", notes)
        self.assertIn("`" + "a" * 40 + "`", notes)
        self.assertIn("0.1.0-beta.test", notes)

    def test_create_draft_upload_then_publish_for_each_channel(self) -> None:
        for channel in ("beta", "stable", "nightly"):
            with self.subTest(channel=channel):
                result, calls, _ = self.invoke(channel)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call[:2] for call in calls], [["release", "create"], ["release", "upload"], ["release", "edit"]])
                self.assertIn("--draft", calls[0])
                self.assertNotIn("--clobber", calls[1])
                self.assertIn("--draft=false", calls[2])
                self.assertIn("--latest" if channel == "stable" else "--latest=false", calls[2])

    def test_failed_upload_does_not_publish(self) -> None:
        result, calls, _ = self.invoke(failure="upload")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[1] for call in calls], ["create", "upload"])

    def test_existing_release_is_not_modified(self) -> None:
        result, calls, _ = self.invoke(failure="create")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[1] for call in calls], ["create"])

    def test_version_guard_fails_closed(self) -> None:
        block = "Refuse an existing release version"
        for failure, releases, expected in (("", "", 0), ("api", "", 1), ("", "v0.1.0-beta.test", 1)):
            with self.subTest(failure=failure, releases=releases):
                result, _, _ = self.invoke(failure=failure, block=block, releases=releases)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_release_runs_history_audit_and_regressions_before_build(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        source_gate = workflow_block("Verify source before publishing")
        self.assertIn("group: signed-release\n", workflow)
        self.assertIn("python3 tests/security/test_beta_safety.py", source_gate)
        self.assertIn("bash tests/security/public-repo-history-scan.sh", source_gate)
        self.assertIn("make verify", source_gate)
        self.assertLess(workflow.index("Refuse an existing release version"), workflow.index("Build and publish immutable application images"))
        verify = (ROOT / ".github/workflows/verify.yml").read_text()
        self.assertIn("python3 tests/security/test_beta_safety.py", verify)


if __name__ == "__main__":
    unittest.main(verbosity=2)
