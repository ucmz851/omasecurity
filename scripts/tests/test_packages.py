"""Unit tests for package supply-chain checks. No root, no live pacman required."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from checks.packages import (  # noqa: E402
    OMARCHY_KEY_ID,
    check_arch_audit,
    check_pacman_inventory,
    check_pacman_keyring,
    check_pacman_trust,
    check_pacman_updates,
    parse_pacman_conf,
)


def _cp(argv, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(list(argv), rc, stdout=stdout, stderr=stderr)


class FakeRun:
    """Dispatch canned CompletedProcess values keyed by argv prefix/tuple."""

    def __init__(self, mapping=None, default=None):
        self.mapping = list(mapping or [])
        self.default = default
        self.calls = []

    def add(self, argv, rc=0, stdout="", stderr=""):
        self.mapping.append((tuple(argv), _cp(argv, rc, stdout, stderr)))

    def __call__(self, argv, timeout=1.0):
        argv = list(argv)
        self.calls.append((tuple(argv), timeout))
        key = tuple(argv)
        for prefix, result in self.mapping:
            if key == prefix or key[: len(prefix)] == prefix:
                return result
        if self.default is not None:
            return self.default(argv, timeout)
        return _cp(argv, 1, stderr="unexpected command: " + " ".join(argv))


TRUSTALL_CONF = """
[options]
HoldPkg = pacman glibc
SigLevel = Required DatabaseOptional
Architecture = auto

[core]
Include = {include}

[omarchy]
SigLevel = Optional TrustAll
Server = https://pkgs.omarchy.org/$repo/$arch

[local-file]
SigLevel = TrustAll
Server = file:///var/cache/pacman/pkg
"""

INCLUDE_OVERRIDE = """
SigLevel = Optional
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
"""


def _write_conf(root):
    pacman_d = Path(root) / "pacman.d"
    pacman_d.mkdir()
    include = pacman_d / "custom"
    include.write_text(INCLUDE_OVERRIDE)
    conf = Path(root) / "pacman.conf"
    conf.write_text(TRUSTALL_CONF.format(include=str(include)))
    return conf, pacman_d


class TestPacmanTrust(unittest.TestCase):
    def test_trustall_and_include_optional(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf, pacman_d = _write_conf(tmp)
            parsed = parse_pacman_conf(conf, include_root=pacman_d)
            names = {repo["name"]: repo for repo in parsed["repos"]}
            self.assertEqual(names["omarchy"]["siglevel"], "Optional TrustAll")
            self.assertEqual(names["omarchy"]["source"], "repo override")
            self.assertEqual(names["core"]["siglevel"], "Optional")
            self.assertTrue(names["core"]["source"].startswith("include "))
            self.assertFalse(names["local-file"]["network"])

            result = check_pacman_trust(conf_path=conf, include_root=pacman_d)
            self.assertTrue(result["applicable"])
            self.assertFalse(result["passed"])
            self.assertEqual(result["severity"], "high")
            self.assertEqual(result["score"], 2)  # high 5 + medium 3
            detail_text = "\n".join(result["details"])
            self.assertIn("omarchy: Optional TrustAll (repo override)", detail_text)
            self.assertIn("core: Optional (include ", detail_text)
            self.assertIn(str(pacman_d / "custom"), detail_text)
            self.assertIn("local-file: TrustAll (repo override)", detail_text)
            self.assertIn("pacman-stable.conf", result["fix_cmd"])
            self.assertNotIn("sudo", (result["fix_cmd"] or "").split())

    def test_file_url_trustall_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "pacman.conf"
            conf.write_text(
                "[options]\nSigLevel = Required DatabaseOptional\n\n"
                "[local]\nSigLevel = TrustAll\nServer = file:///repo\n"
            )
            result = check_pacman_trust(conf_path=conf, include_root=Path(tmp))
            self.assertTrue(result["passed"])
            self.assertEqual(result["score"], 10)
            self.assertEqual(result["severity"], "info")

    def test_options_weaker_than_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "pacman.conf"
            conf.write_text("[options]\nSigLevel = Optional TrustAll\n\n[core]\nServer = https://example/$repo\n")
            result = check_pacman_trust(conf_path=conf, include_root=Path(tmp))
            self.assertFalse(result["passed"])
            # options medium 3 + inherited TrustAll high 5
            self.assertEqual(result["score"], 2)
            self.assertIn("[options]", result["description"])

    def test_missing_conf_is_not_applicable(self):
        result = check_pacman_trust(conf_path="/no/such/pacman.conf")
        self.assertFalse(result["applicable"])
        self.assertEqual(result["severity"], "info")
        self.assertEqual(result["score"], 0)


class TestPacmanKeyring(unittest.TestCase):
    def test_missing_omarchy_keyring_and_key_is_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf, pacman_d = _write_conf(tmp)
            run = FakeRun()
            run.add(
                ["pacman", "-Q", "archlinux-keyring", "omarchy-keyring"],
                rc=1,
                stdout="archlinux-keyring 20260315-1\n",
                stderr="error: package 'omarchy-keyring' was not found\n",
            )
            run.add(["pacman", "-Q", "archlinuxarm-keyring"], rc=1, stderr="error: package 'archlinuxarm-keyring' was not found\n")
            run.add(["pacman-key", "--list-keys", OMARCHY_KEY_ID], rc=1, stderr="gpg: No public key\n")
            result = check_pacman_keyring(conf_path=conf, include_root=pacman_d, run=run)
            self.assertTrue(result["applicable"])
            self.assertFalse(result["passed"])
            self.assertEqual(result["severity"], "high")
            self.assertEqual(result["score"], 0)
            details = "\n".join(result["details"])
            self.assertIn("archlinux-keyring 20260315-1", details)
            self.assertIn("omarchy-keyring missing", details)
            self.assertNotIn("sk-", json.dumps(result))

    def test_unknown_key_when_listing_times_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf, pacman_d = _write_conf(tmp)
            run = FakeRun()
            run.add(
                ["pacman", "-Q", "archlinux-keyring", "omarchy-keyring"],
                stdout="archlinux-keyring 1-1\nomarchy-keyring 1-1\n",
            )
            run.add(["pacman", "-Q", "archlinuxarm-keyring"], rc=1)
            run.add(["pacman-key", "--list-keys", OMARCHY_KEY_ID], rc=124, stderr="timeout")
            run.add(["gpg", "--homedir", "/etc/pacman.d/gnupg", "--list-keys", OMARCHY_KEY_ID], rc=124, stderr="timeout")
            result = check_pacman_keyring(conf_path=conf, include_root=pacman_d, run=run)
            self.assertTrue(result["passed"])
            self.assertEqual(result["score"], 5)
            self.assertIn("pacman-key --list-keys " + OMARCHY_KEY_ID, "\n".join(result["details"]))

    def test_pacman_missing_is_not_applicable(self):
        run = FakeRun()
        run.add(["pacman", "-Q", "archlinux-keyring", "omarchy-keyring"], rc=127, stderr="not found")
        result = check_pacman_keyring(conf_path="/no/such/pacman.conf", run=run)
        self.assertFalse(result["applicable"])

    def test_patched_run_cmd_canned_pacman_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf, pacman_d = _write_conf(tmp)
            run = FakeRun()
            run.add(
                ["pacman", "-Q", "archlinux-keyring", "omarchy-keyring"],
                stdout="archlinux-keyring 20260315-1\nomarchy-keyring 1.0-1\n",
            )
            run.add(
                ["pacman", "-Q", "archlinuxarm-keyring"],
                stdout="archlinuxarm-keyring 20240101-1\n",
            )
            run.add(["pacman-key", "--list-keys", OMARCHY_KEY_ID], stdout="pub rsa4096\n")
            with patch("checks.packages.run_cmd", run):
                result = check_pacman_keyring(conf_path=conf, include_root=pacman_d)
            self.assertTrue(result["passed"])
            details = "\n".join(result["details"])
            self.assertIn("omarchy-keyring 1.0-1", details)
            self.assertIn("archlinuxarm-keyring 20240101-1", details)
            self.assertIn("present (pacman-key)", details)


class TestPacmanUpdates(unittest.TestCase):
    def test_forty_day_old_upgrade_is_high(self):
        now = datetime(2026, 9, 16, tzinfo=timezone.utc)
        ts = (now - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%S+0000")
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "pacman.log"
            log.write_text(
                "[2026-01-01T00:00:00+0000] [PACMAN] synchronizing package lists\n"
                f"[{ts}] [PACMAN] starting full system upgrade\n"
                "[2026-09-01T00:00:00+0000] [ALPM] upgraded linux (1-1 -> 1-2)\n"
            )
            result = check_pacman_updates(log_path=log, now=now)
            self.assertTrue(result["applicable"])
            self.assertFalse(result["passed"])
            self.assertEqual(result["severity"], "high")
            self.assertEqual(result["score"], 0)
            self.assertEqual(result["recommendation"], "run `omarchy update`")

    def test_missing_log_is_not_applicable(self):
        result = check_pacman_updates(log_path="/no/such/pacman.log")
        self.assertFalse(result["applicable"])
        self.assertEqual(result["score"], 0)

    def test_missing_upgrade_line_is_unknown_no_deduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "pacman.log"
            log.write_text("[2026-09-01T00:00:00+0000] [PACMAN] synchronizing package lists\n")
            result = check_pacman_updates(log_path=log)
            self.assertTrue(result["passed"])
            self.assertEqual(result["score"], 5)
            self.assertIn("unknown", result["description"].lower())


class TestPacmanInventory(unittest.TestCase):
    def _run_for(self, foreign_names, repos):
        run = FakeRun()
        installed = ["linux", "pacman"] + list(foreign_names)
        run.add(["pacman", "-Qq"], stdout="\n".join(installed) + "\n")
        run.add(["pacman", "-Qmq"], stdout="\n".join(foreign_names) + "\n")
        for repo, lines in repos.items():
            run.add(["pacman", "-Sl", repo], stdout=lines)
        return run

    def test_counts_and_foreign_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf, pacman_d = _write_conf(tmp)
            run = self._run_for(
                ["my-aur-pkg"],
                {
                    "core": "core linux 1-1 [installed]\ncore glibc 1-1\n",
                    "omarchy": "omarchy omarchy-chromium 1-1 [installed]\n",
                    "local-file": "local-file foo 1-1\n",
                },
            )
            result = check_pacman_inventory(conf_path=conf, include_root=pacman_d, run=run)
            self.assertTrue(result["passed"])
            self.assertEqual(result["score"], 5)
            details = "\n".join(result["details"])
            self.assertIn("core=1", details)
            self.assertIn("omarchy=1", details)
            self.assertIn("foreign=1", details)
            self.assertIn("my-aur-pkg", details)

    def test_many_foreign_packages_deduct(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf, pacman_d = _write_conf(tmp)
            foreign = ["foreign-%02d" % i for i in range(26)]
            run = self._run_for(
                foreign,
                {
                    "core": "",
                    "omarchy": "",
                    "local-file": "",
                },
            )
            result = check_pacman_inventory(conf_path=conf, include_root=pacman_d, run=run)
            self.assertFalse(result["passed"])
            self.assertEqual(result["score"], 3)
            self.assertIn("unsigned", result["description"].lower())
            details = "\n".join(result["details"])
            self.assertIn("foreign-00", details)
            self.assertIn("6 more foreign", details)


class TestArchAudit(unittest.TestCase):
    def test_not_installed_is_not_applicable(self):
        run = FakeRun()
        run.add(["arch-audit", "--help"], rc=127, stderr="No such file")
        result = check_arch_audit(run=run)
        self.assertFalse(result["applicable"])
        self.assertEqual(result["severity"], "info")
        self.assertEqual(result["score"], 0)
        self.assertIn("extra", result["description"])
        self.assertEqual(result["recommendation"], "sudo pacman -S arch-audit")

    def test_json_critical_entry(self):
        run = FakeRun()
        run.add(["arch-audit", "--help"], stdout="Usage: arch-audit\n  --json    JSON output\n")
        payload = [
            {
                "package": "openssl",
                "cve": "CVE-2024-1234",
                "severity": "Critical",
            }
        ]
        run.add(["arch-audit", "--json"], stdout=json.dumps(payload))
        result = check_arch_audit(run=run)
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["lane"], "slow")
        self.assertIn("openssl: CVE-2024-1234 Critical", result["details"])

    def test_network_failure_is_not_applicable(self):
        run = FakeRun()
        run.add(["arch-audit", "--help"], stdout="Usage: arch-audit\n  --json\n")
        run.add(
            ["arch-audit", "--json"],
            rc=1,
            stdout="",
            stderr="error sending request for url: failed to fetch advisory db\n",
        )
        result = check_arch_audit(run=run)
        self.assertFalse(result["applicable"])
        self.assertIn("failed to fetch", result["description"])


if __name__ == "__main__":
    unittest.main()
