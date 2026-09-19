"""Unit tests for LSM and audit-framework checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from checks.lsm import check_audit_framework, check_lsm_status


def _proc(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class CommandMap:
    def __init__(self, mapping, default=None):
        self.mapping = mapping
        self.default = default if default is not None else _proc(1, "")

    def __call__(self, argv, timeout=1.0):
        key = tuple(argv)
        if key in self.mapping:
            return self.mapping[key]
        for map_key, value in self.mapping.items():
            if key[: len(map_key)] == map_key:
                return value
        return self.default


class FileMap:
    def __init__(self, files):
        self.files = files

    def __call__(self, path, default=None):
        if path in self.files:
            return self.files[path]
        return default


LSM_WITH_LANDLOCK = "capability,yama,landlock\n"
LSM_WITHOUT_LANDLOCK = "capability,yama\n"
LSM_WITHOUT_YAMA = "capability,landlock\n"
LOCKDOWN_NONE = "none [integrity] confidentiality\n"


class TestLsmStatus(unittest.TestCase):
    def _runner(self, extra=None):
        mapping = {
            ("uname", "-r"): _proc(0, "6.16.8-1-aarch64\n"),
            ("pacman", "-Q", "apparmor"): _proc(1, ""),
            ("systemctl", "is-active", "apparmor"): _proc(3, "inactive\n"),
        }
        if extra:
            mapping.update(extra)
        return CommandMap(mapping)

    def test_yama_and_landlock_pass(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": LSM_WITH_LANDLOCK,
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner(),
        )
        self.assertTrue(result["passed"])
        self.assertTrue(result["applicable"])
        self.assertEqual(result["score"], 5)
        self.assertEqual(result["severity"], "info")
        self.assertIn("Lockdown:", " ".join(result["details"]))
        self.assertTrue(
            any("AppArmor is not installed and is optional on Omarchy" in line
                for line in result["details"])
        )

    def test_missing_landlock_is_medium(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": LSM_WITHOUT_LANDLOCK,
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner(),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["severity"], "medium")
        self.assertIn("landlock", result["description"])

    def test_missing_yama_and_landlock_deducts_each(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": "capability,bpf\n",
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner(),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 1)
        self.assertEqual(result["severity"], "medium")

    def test_hardened_kernel_mentioned(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": LSM_WITH_LANDLOCK,
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner({
                ("uname", "-r"): _proc(0, "6.12.8-hardened1-1-hardened\n"),
            }),
        )
        self.assertTrue(result["passed"])
        self.assertTrue(any("hardened" in line.lower() for line in result["details"]))

    def test_apparmor_installed_but_not_in_lsm(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": LSM_WITH_LANDLOCK,
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner({
                ("pacman", "-Q", "apparmor"): _proc(0, "apparmor 4.0.3-1\n"),
            }),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["severity"], "medium")
        self.assertIn("lsm=landlock,lockdown,yama,integrity,apparmor,bpf", result["recommendation"])

    def test_apparmor_in_lsm_but_inactive(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": "capability,yama,landlock,apparmor\n",
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner({
                ("pacman", "-Q", "apparmor"): _proc(0, "apparmor 4.0.3-1\n"),
                ("systemctl", "is-active", "apparmor"): _proc(3, "inactive\n"),
            }),
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["severity"], "medium")

    def test_not_applicable_without_lsm_file(self):
        result = check_lsm_status(
            reader=FileMap({}),
            runner=self._runner(),
        )
        self.assertTrue(result["applicable"] is False)
        self.assertEqual(result["severity"], "info")
        self.assertEqual(result["score"], 0)

    def test_apparmor_not_installed_does_not_penalise(self):
        result = check_lsm_status(
            reader=FileMap({
                "/sys/kernel/security/lsm": LSM_WITH_LANDLOCK,
                "/sys/kernel/security/lockdown": LOCKDOWN_NONE,
            }),
            runner=self._runner(),
        )
        self.assertEqual(result["score"], 5)
        self.assertTrue(result["passed"])


PACMAN_QI_EXPLICIT = """Name            : audit
Version         : 4.0.2-2
Description     : Userspace utilities for the audit daemon
Install Reason  : Explicitly installed
"""

PACMAN_QI_DEPENDENCY = """Name            : audit
Version         : 4.0.2-2
Description     : Userspace utilities for the audit daemon
Install Reason  : Installed as a dependency for another package
"""

AUDIT_OPTIONAL = "audit is installed only as a dependency; auditd is optional on Omarchy"


class TestAuditFramework(unittest.TestCase):
    def test_dependency_only_is_not_applicable(self):
        result = check_audit_framework(
            runner=CommandMap({
                ("pacman", "-Qi", "audit"): _proc(0, PACMAN_QI_DEPENDENCY),
                ("systemctl", "is-enabled", "auditd"): _proc(1, "disabled\n"),
            }),
        )
        self.assertFalse(result["applicable"])
        self.assertEqual(result["severity"], "info")
        self.assertEqual(result["description"], AUDIT_OPTIONAL)

    def test_not_installed_is_not_applicable(self):
        result = check_audit_framework(
            runner=CommandMap({
                ("pacman", "-Qi", "audit"): _proc(1, ""),
                ("systemctl", "is-enabled", "auditd"): _proc(1, "not-found\n"),
            }),
        )
        self.assertFalse(result["applicable"])
        self.assertEqual(result["description"], AUDIT_OPTIONAL)

    def test_explicit_inactive_auditd_deducts_all(self):
        result = check_audit_framework(
            runner=CommandMap({
                ("pacman", "-Qi", "audit"): _proc(0, PACMAN_QI_EXPLICIT),
                ("systemctl", "is-enabled", "auditd"): _proc(0, "enabled\n"),
                ("systemctl", "is-active", "auditd"): _proc(3, "inactive\n"),
            }),
            listdir_fn=lambda _path: (2, "ok"),
        )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["severity"], "medium")
        self.assertTrue(any("2 readable file" in line for line in result["details"]))

    def test_enabled_as_dependency_is_applicable(self):
        result = check_audit_framework(
            runner=CommandMap({
                ("pacman", "-Qi", "audit"): _proc(0, PACMAN_QI_DEPENDENCY),
                ("systemctl", "is-enabled", "auditd"): _proc(0, "enabled\n"),
                ("systemctl", "is-active", "auditd"): _proc(0, "active\n"),
            }),
            listdir_fn=lambda _path: (1, "ok"),
        )
        self.assertTrue(result["applicable"])
        self.assertTrue(result["passed"])

    def test_unreadable_rules_dir_mentions_sudo_auditctl(self):
        result = check_audit_framework(
            runner=CommandMap({
                ("pacman", "-Qi", "audit"): _proc(0, PACMAN_QI_EXPLICIT),
                ("systemctl", "is-enabled", "auditd"): _proc(1, "disabled\n"),
                ("systemctl", "is-active", "auditd"): _proc(0, "active\n"),
            }),
            listdir_fn=lambda _path: (0, "unreadable"),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 3)
        self.assertTrue(any("sudo auditctl -l" in line for line in result["details"]))

    def test_active_with_readable_rules(self):
        result = check_audit_framework(
            runner=CommandMap({
                ("pacman", "-Qi", "audit"): _proc(0, PACMAN_QI_EXPLICIT),
                ("systemctl", "is-enabled", "auditd"): _proc(0, "enabled\n"),
                ("systemctl", "is-active", "auditd"): _proc(0, "active\n"),
            }),
            listdir_fn=lambda _path: (4, "ok"),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["max_score"], 3)
        self.assertTrue(any("4 readable file" in line for line in result["details"]))


if __name__ == "__main__":
    unittest.main()
