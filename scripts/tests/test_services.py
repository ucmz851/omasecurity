"""Unit tests for service exposure, sshd_config, and user-unit checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from checks.services import (
    CANDIDATE_UNITS,
    check_service_exposure,
    check_sshd_config,
    check_user_services,
)


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


ANALYZE_JSON_UNSAFE_SSHD = """[
  {"unit": "sshd.service", "exposure": "9.6", "predicate": "UNSAFE", "happy": "🙁"},
  {"unit": "udisks2.service", "exposure": "9.6", "predicate": "UNSAFE", "happy": "🙁"},
  {"unit": "user@1000.service", "exposure": "9.6", "predicate": "UNSAFE", "happy": "🙁"}
]
"""

# systemd 261: exposure is a string; unit names include the .service suffix.
ANALYZE_JSON_SYSTEMD_261 = """[
  {"unit": "sshd.service", "exposure": "9.4", "predicate": "UNSAFE", "happy": "🙁"}
]
"""

ANALYZE_TABLE_UNSAFE_SSHD = """UNIT                                  EXPOSURE PREDICATE HAPPY
sshd.service                               9.6 UNSAFE     🙁
udisks2.service                            9.6 UNSAFE     🙁
user@1000.service                          9.6 UNSAFE     🙁
cups.service                               4.2 OK         🙂
"""

SSHD_MAIN_WITH_INCLUDE = """Include /etc/ssh/sshd_config.d/*.conf
PasswordAuthentication yes
PermitRootLogin prohibit-password
X11Forwarding no
"""

SSHD_DROPIN_DISABLE_PASSWORD = "PasswordAuthentication no\n"


def _is_active_stdout(active_names):
    lines = []
    for name in CANDIDATE_UNITS:
        lines.append("active" if name in active_names else "inactive")
    return "\n".join(lines) + "\n"


class TestServiceExposure(unittest.TestCase):
    def test_json_unsafe_sshd_deducts_and_ignores_udisks(self):
        runner = CommandMap({
            ("systemctl", "is-active"): _proc(3, _is_active_stdout({"sshd"})),
            ("systemd-analyze", "security", "--no-pager", "--json=short"): _proc(
                0, ANALYZE_JSON_UNSAFE_SSHD
            ),
        })
        result = check_service_exposure(runner=runner)
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 8)
        self.assertEqual(result["severity"], "medium")
        self.assertEqual(result["lane"], "slow")
        self.assertTrue(any("sshd exposure 9.6" in line for line in result["details"]))
        self.assertFalse(any("udisks2" in line for line in result["details"]))

    def test_systemd_261_json_string_exposure(self):
        runner = CommandMap({
            ("systemctl", "is-active"): _proc(3, _is_active_stdout({"sshd"})),
            ("systemd-analyze", "security", "--no-pager", "--json=short"): _proc(
                0, ANALYZE_JSON_SYSTEMD_261
            ),
        })
        result = check_service_exposure(runner=runner)
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 8)
        self.assertTrue(any("sshd exposure 9.4" in line for line in result["details"]))

    def test_table_fallback_unsafe_sshd(self):
        runner = CommandMap({
            ("systemctl", "is-active"): _proc(3, _is_active_stdout({"sshd"})),
            ("systemd-analyze", "security", "--no-pager", "--json=short"): _proc(
                1, "", "Unknown option --json=short\n"
            ),
            ("systemd-analyze", "security", "--no-pager"): _proc(
                0, ANALYZE_TABLE_UNSAFE_SSHD
            ),
        })
        result = check_service_exposure(runner=runner)
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 8)
        self.assertTrue(any("sshd exposure 9.6" in line for line in result["details"]))

    def test_nothing_active_passes(self):
        runner = CommandMap({
            ("systemctl", "is-active"): _proc(3, _is_active_stdout(set())),
        })
        result = check_service_exposure(runner=runner)
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 10)
        self.assertEqual(result["description"], "No network-facing services running")

    def test_timeout_is_not_applicable(self):
        runner = CommandMap({
            ("systemctl", "is-active"): _proc(3, _is_active_stdout({"sshd"})),
            ("systemd-analyze", "security", "--no-pager", "--json=short"): _proc(
                124, "", "timeout"
            ),
        })
        result = check_service_exposure(runner=runner)
        self.assertFalse(result["applicable"])
        self.assertEqual(result["severity"], "info")
        self.assertIn("timed out", result["description"])

    def test_systemctl_missing_is_not_applicable(self):
        result = check_service_exposure(runner=CommandMap({}, default=_proc(127, "")))
        self.assertFalse(result["applicable"])
        self.assertIn("systemctl is not available", result["description"])


class TestSshdConfig(unittest.TestCase):
    def _present_runner(self, enabled="enabled", active="inactive"):
        return CommandMap({
            ("systemctl", "is-enabled", "sshd"): _proc(0, enabled + "\n"),
            ("systemctl", "is-active", "sshd"): _proc(
                0 if active == "active" else 3, active + "\n"
            ),
        })

    def test_not_applicable_when_disabled_and_inactive(self):
        result = check_sshd_config(
            runner=CommandMap({
                ("systemctl", "is-enabled", "sshd"): _proc(1, "disabled\n"),
                ("systemctl", "is-active", "sshd"): _proc(3, "inactive\n"),
            }),
            reader=FileMap({}),
        )
        self.assertFalse(result["applicable"])
        self.assertIn("not enabled or active", result["description"])

    def test_dropin_overrides_passwordauthentication(self):
        files = {
            "/etc/ssh/sshd_config": SSHD_MAIN_WITH_INCLUDE,
            "/etc/ssh/sshd_config.d/50-harden.conf": SSHD_DROPIN_DISABLE_PASSWORD,
        }

        def glob_fn(pattern):
            if "sshd_config.d" in pattern:
                return ["/etc/ssh/sshd_config.d/50-harden.conf"]
            return []

        result = check_sshd_config(
            runner=self._present_runner(),
            reader=FileMap(files),
            glob_fn=glob_fn,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 5)
        self.assertTrue(any("PasswordAuthentication no" in line for line in result["details"]))

    def test_password_default_yes_when_unset(self):
        files = {
            "/etc/ssh/sshd_config": "PermitRootLogin prohibit-password\nX11Forwarding no\n",
        }
        result = check_sshd_config(
            runner=self._present_runner(),
            reader=FileMap(files),
            glob_fn=lambda _pattern: [],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["severity"], "medium")
        self.assertIn("90-omasecurity.conf", result["fix_cmd"])
        self.assertIn("sudo systemctl reload sshd", result["fix_cmd"])

    def test_permit_root_login_yes_is_high(self):
        files = {
            "/etc/ssh/sshd_config": (
                "PasswordAuthentication no\nPermitRootLogin yes\nX11Forwarding no\n"
            ),
        }
        result = check_sshd_config(
            runner=self._present_runner(active="active"),
            reader=FileMap(files),
            glob_fn=lambda _pattern: [],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 2)
        self.assertEqual(result["severity"], "high")

    def test_x11_forwarding_yes_is_low(self):
        files = {
            "/etc/ssh/sshd_config": (
                "PasswordAuthentication no\nPermitRootLogin no\nX11Forwarding yes\n"
            ),
        }
        result = check_sshd_config(
            runner=self._present_runner(),
            reader=FileMap(files),
            glob_fn=lambda _pattern: [],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["severity"], "low")

    def test_unreadable_dropin_is_reported(self):
        files = {
            "/etc/ssh/sshd_config": SSHD_MAIN_WITH_INCLUDE,
        }

        def glob_fn(pattern):
            if "sshd_config.d" in pattern:
                return ["/etc/ssh/sshd_config.d/secret.conf"]
            return []

        result = check_sshd_config(
            runner=self._present_runner(),
            reader=FileMap(files),
            glob_fn=glob_fn,
        )
        self.assertTrue(any("Unreadable:" in line for line in result["details"]))


class TestUserServices(unittest.TestCase):
    def test_execstart_under_tmp_is_high(self):
        unit_path = "/home/oma/.config/systemd/user/evil.service"
        unit_text = "[Service]\nExecStart=/tmp/payload.sh\n"

        result = check_user_services(
            runner=CommandMap({
                ("systemctl", "--user", "list-units"): _proc(
                    0, "dbus.service loaded active running D-Bus\n"
                ),
            }),
            reader=FileMap({unit_path: unit_text}),
            home="/home/oma",
            units_dir="/home/oma/.config/systemd/user",
            walk_fn=lambda _root: [Path(unit_path)],
        )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["severity"], "high")
        self.assertTrue(any("1 running user service" in line for line in result["details"]))

    def test_safe_execstart_passes(self):
        unit_path = "/home/oma/.config/systemd/user/app.service"
        unit_text = "[Service]\nExecStart=/usr/bin/syncthing serve\n"

        result = check_user_services(
            runner=CommandMap({
                ("systemctl", "--user", "list-units"): _proc(0, ""),
            }),
            reader=FileMap({unit_path: unit_text}),
            home="/home/oma",
            units_dir="/home/oma/.config/systemd/user",
            walk_fn=lambda _root: [Path(unit_path)],
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 2)
        self.assertTrue(any("0 running user service" in line for line in result["details"]))

    def test_downloads_path_is_high(self):
        unit_path = "/home/oma/.config/systemd/user/dl.service"
        unit_text = '[Service]\nExecStart=/home/oma/Downloads/bin/agent\n'

        result = check_user_services(
            runner=CommandMap({
                ("systemctl", "--user", "list-units"): _proc(0, ""),
            }),
            reader=FileMap({unit_path: unit_text}),
            home="/home/oma",
            units_dir="/home/oma/.config/systemd/user",
            walk_fn=lambda _root: [Path(unit_path)],
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["severity"], "high")

    def test_not_applicable_without_user_systemd(self):
        result = check_user_services(
            runner=CommandMap({}, default=_proc(127, "")),
            reader=FileMap({}),
            home="/home/oma",
            walk_fn=lambda _root: [],
        )
        self.assertFalse(result["applicable"])
        self.assertIn("not available", result["description"])


if __name__ == "__main__":
    unittest.main()
