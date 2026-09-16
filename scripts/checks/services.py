"""Network-facing service exposure, sshd_config, and user-unit checks."""

from __future__ import annotations

import json
import os
import re
import shlex
from glob import glob
from pathlib import Path

from . import FAST_CHECKS, SLOW_CHECKS, make_result, read_text, register_check, run_cmd

CANDIDATE_UNITS = [
    "sshd",
    "cups",
    "avahi-daemon",
    "smb",
    "nmb",
    "nfs-server",
    "rpcbind",
    "docker",
    "libvirtd",
    "tailscaled",
    "syncthing",
    "bluetooth",
    "transmission",
    "minidlna",
    "plexmediaserver",
    "jellyfin",
    "nginx",
    "httpd",
    "caddy",
]

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d"
EXPOSURE_THRESHOLD = 8.0
SECURITY_TIMEOUT_S = 10.0

SSHD_FIX_CMD = (
    "printf '%s\\n' 'PasswordAuthentication no' 'PermitRootLogin no' "
    "'X11Forwarding no' | sudo tee /etc/ssh/sshd_config.d/90-omasecurity.conf "
    ">/dev/null && sudo systemctl reload sshd"
)

SERVICE_REFS = [
    "https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html",
]
SSHD_REFS = [
    "https://wiki.archlinux.org/title/OpenSSH",
    "https://man.archlinux.org/man/sshd_config.5",
]
USER_REFS = [
    "https://wiki.archlinux.org/title/Systemd/User",
]

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TABLE_ROW = re.compile(
    r"^\s*(\S+)\s+([0-9]+(?:\.[0-9]+)?)\s+(\S+)"
)
_UNIT_NAME = re.compile(r"^[A-Za-z0-9@:_.\\-]+$")


def _worse(current, candidate):
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


def _unit_aliases(name):
    name = name.strip()
    if name.endswith(".service"):
        return (name, name[: -len(".service")])
    return (name + ".service", name)


def _lookup_exposure(scores, name):
    for alias in _unit_aliases(name):
        if alias in scores:
            return scores[alias]
    return None


def _parse_security_json(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None

    scores = {}
    if isinstance(data, dict):
        items = data.items()
        for key, value in items:
            if isinstance(value, dict) and "exposure" in value:
                try:
                    scores[key] = float(value["exposure"])
                except (TypeError, ValueError):
                    continue
            elif isinstance(value, (int, float)):
                scores[key] = float(value)
            elif isinstance(value, str):
                try:
                    scores[key] = float(value)
                except ValueError:
                    continue
        return scores or None

    if not isinstance(data, list) or not data:
        return None

    has_unit = any(isinstance(item, dict) and "unit" in item for item in data)
    if not has_unit:
        return None

    for item in data:
        if not isinstance(item, dict):
            continue
        unit = item.get("unit")
        exposure = item.get("exposure")
        if unit is None or exposure is None:
            continue
        try:
            scores[str(unit)] = float(exposure)
        except (TypeError, ValueError):
            continue
    return scores or None


def _parse_security_table(text):
    scores = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("unit"):
            continue
        match = _TABLE_ROW.match(line)
        if not match:
            continue
        unit, exposure, _predicate = match.groups()
        if not _UNIT_NAME.match(unit):
            continue
        try:
            scores[unit] = float(exposure)
        except ValueError:
            continue
    return scores


def _collect_exposure_scores(runner):
    json_proc = runner(
        ["systemd-analyze", "security", "--no-pager", "--json=short"],
        timeout=SECURITY_TIMEOUT_S,
    )
    if json_proc.returncode == 124:
        return None, "timeout"
    if json_proc.returncode == 127:
        return None, "missing"

    scores = None
    if json_proc.returncode == 0 and json_proc.stdout:
        scores = _parse_security_json(json_proc.stdout)

    if scores:
        return scores, "ok"

    table_proc = json_proc
    if json_proc.returncode != 0 or not _parse_security_table(json_proc.stdout or ""):
        table_proc = runner(
            ["systemd-analyze", "security", "--no-pager"],
            timeout=SECURITY_TIMEOUT_S,
        )
        if table_proc.returncode == 124:
            return None, "timeout"
        if table_proc.returncode == 127:
            return None, "missing"

    scores = _parse_security_table(table_proc.stdout or "")
    if scores:
        return scores, "ok"
    if table_proc.returncode != 0:
        return None, "error"
    return {}, "ok"


@register_check(
    SLOW_CHECKS,
    check_id="service_exposure",
    category="Services",
    title="Network-Facing Service Exposure",
    max_score=10,
    lane="slow",
)
def check_service_exposure(*, runner=None):
    runner = run_cmd if runner is None else runner

    active_proc = runner(
        ["systemctl", "is-active", *CANDIDATE_UNITS],
        timeout=2.0,
    )
    if active_proc.returncode == 127:
        return make_result(
            id="service_exposure",
            category="Services",
            title="Network-Facing Service Exposure",
            passed=True,
            applicable=False,
            score=0,
            max_score=10,
            description="systemctl is not available.",
            lane="slow",
            refs=list(SERVICE_REFS),
        )
    if active_proc.returncode == 124:
        return make_result(
            id="service_exposure",
            category="Services",
            title="Network-Facing Service Exposure",
            passed=True,
            applicable=False,
            score=0,
            max_score=10,
            description="systemctl is-active timed out after 2s.",
            lane="slow",
            refs=list(SERVICE_REFS),
        )

    lines = [line.strip() for line in (active_proc.stdout or "").splitlines()]
    active = []
    for index, name in enumerate(CANDIDATE_UNITS):
        state = lines[index] if index < len(lines) else "unknown"
        if state == "active":
            active.append(name)

    if not active:
        return make_result(
            id="service_exposure",
            category="Services",
            title="Network-Facing Service Exposure",
            passed=True,
            applicable=True,
            score=10,
            max_score=10,
            description="No network-facing services running",
            details=[],
            lane="slow",
            refs=list(SERVICE_REFS),
        )

    scores, status = _collect_exposure_scores(runner)
    if status == "timeout":
        return make_result(
            id="service_exposure",
            category="Services",
            title="Network-Facing Service Exposure",
            passed=True,
            applicable=False,
            score=0,
            max_score=10,
            description="systemd-analyze security timed out after 10s.",
            lane="slow",
            refs=list(SERVICE_REFS),
        )
    if status == "missing":
        return make_result(
            id="service_exposure",
            category="Services",
            title="Network-Facing Service Exposure",
            passed=True,
            applicable=False,
            score=0,
            max_score=10,
            description="systemd-analyze is not available.",
            lane="slow",
            refs=list(SERVICE_REFS),
        )
    if status != "ok" or scores is None:
        return make_result(
            id="service_exposure",
            category="Services",
            title="Network-Facing Service Exposure",
            passed=True,
            applicable=False,
            score=0,
            max_score=10,
            description="systemd-analyze security output could not be parsed.",
            lane="slow",
            refs=list(SERVICE_REFS),
        )

    details = []
    unsafe = []
    for name in active:
        exposure = _lookup_exposure(scores, name)
        if exposure is None:
            details.append(name + " is active; exposure score unknown.")
            continue
        details.append(name + " exposure " + format(exposure, ".1f"))
        if exposure >= EXPOSURE_THRESHOLD:
            unsafe.append((name, exposure))

    score = max(0, 10 - 2 * len(unsafe))
    passed = not unsafe
    if passed:
        description = "Network-facing services are running with exposure below 8.0."
        severity = "info"
        recommendation = None
    else:
        names = ", ".join(item[0] for item in unsafe)
        description = "Network-facing services have high exposure scores (" + names + ")."
        severity = "medium"
        recommendation = (
            "Restrict or sandbox network-facing units (see systemd-analyze security). "
            "Disable services you do not need."
        )

    return make_result(
        id="service_exposure",
        category="Services",
        title="Network-Facing Service Exposure",
        passed=passed,
        applicable=True,
        score=score,
        max_score=10,
        severity=severity,
        description=description,
        details=details,
        recommendation=recommendation,
        lane="slow",
        refs=list(SERVICE_REFS),
    )


def _sshd_is_present(runner):
    enabled = runner(["systemctl", "is-enabled", "sshd"], timeout=1.0)
    active = runner(["systemctl", "is-active", "sshd"], timeout=1.0)
    if enabled.returncode == 127 and active.returncode == 127:
        return False
    enabled_state = (enabled.stdout or "").strip().lower()
    active_state = (active.stdout or "").strip().lower()
    if enabled_state in {"enabled", "enabled-runtime"}:
        return True
    if active_state == "active":
        return True
    return False


def _iter_sshd_lines(text):
    in_match = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        key = parts[0]
        value = parts[1] if len(parts) > 1 else ""
        if key.lower() == "match":
            in_match = True
            continue
        if in_match:
            continue
        yield key, value


def _parse_sshd_file(path, reader, glob_fn, seen, details, first_wins):
    text = reader(path)
    if text is None:
        details.append("Unreadable: " + str(path))
        return
    for key, value in _iter_sshd_lines(text):
        if key.lower() == "include":
            pattern = value.strip().split()[0] if value.strip() else ""
            if pattern:
                for included in sorted(glob_fn(pattern)):
                    _parse_sshd_file(included, reader, glob_fn, seen, details, first_wins)
            continue
        lowered = key.lower()
        if lowered in first_wins and lowered not in seen:
            token = value.split()[0] if value.split() else ""
            seen[lowered] = token


def _effective_sshd(reader, glob_fn, main_path, dropin_dir):
    seen = {}
    details = []
    first_wins = {
        "passwordauthentication": "PasswordAuthentication",
        "permitrootlogin": "PermitRootLogin",
        "x11forwarding": "X11Forwarding",
    }

    main_text = reader(main_path)
    has_include = False
    if main_text is not None:
        for key, _value in _iter_sshd_lines(main_text):
            if key.lower() == "include":
                has_include = True
                break

    if not has_include:
        pattern = str(Path(dropin_dir) / "*.conf")
        for included in sorted(glob_fn(pattern)):
            _parse_sshd_file(included, reader, glob_fn, seen, details, first_wins)

    if main_text is None:
        details.append("Unreadable: " + str(main_path))
    else:
        _parse_sshd_file(main_path, reader, glob_fn, seen, details, first_wins)

    return seen, details


@register_check(
    FAST_CHECKS,
    check_id="sshd_config",
    category="Services",
    title="OpenSSH Daemon Configuration",
    max_score=5,
)
def check_sshd_config(
    *,
    runner=None,
    reader=None,
    glob_fn=None,
    config_path=SSHD_CONFIG,
    dropin_dir=SSHD_DROPIN_DIR,
):
    runner = run_cmd if runner is None else runner
    reader = read_text if reader is None else reader
    glob_fn = glob if glob_fn is None else glob_fn

    if not _sshd_is_present(runner):
        return make_result(
            id="sshd_config",
            category="Services",
            title="OpenSSH Daemon Configuration",
            passed=True,
            applicable=False,
            score=0,
            max_score=5,
            description="sshd is not enabled or active.",
            lane="fast",
            refs=list(SSHD_REFS),
        )

    seen, details = _effective_sshd(reader, glob_fn, config_path, dropin_dir)
    score = 5
    severity = "info"
    issues = []

    password = seen.get("passwordauthentication", "yes")
    if password.lower() == "yes":
        score -= 2
        severity = _worse(severity, "medium")
        issues.append("PasswordAuthentication yes")
        details.append("PasswordAuthentication is yes (or unset; default yes).")
    else:
        details.append("PasswordAuthentication " + password)

    root_login = seen.get("permitrootlogin")
    if root_login is not None and root_login.lower() == "yes":
        score -= 3
        severity = _worse(severity, "high")
        issues.append("PermitRootLogin yes")
        details.append("PermitRootLogin is yes.")
    elif root_login is not None:
        details.append("PermitRootLogin " + root_login)
    else:
        details.append("PermitRootLogin is unset (default is not yes).")

    x11 = seen.get("x11forwarding")
    if x11 is not None and x11.lower() == "yes":
        score -= 1
        severity = _worse(severity, "low")
        issues.append("X11Forwarding yes")
        details.append("X11Forwarding is yes.")
    elif x11 is not None:
        details.append("X11Forwarding " + x11)
    else:
        details.append("X11Forwarding is unset (default no).")

    score = max(0, score)
    passed = not issues
    if passed:
        description = "sshd password, root, and X11 settings are hardened."
        recommendation = None
        fix_cmd = None
    else:
        description = "sshd allows weak authentication (" + ", ".join(issues) + ")."
        recommendation = (
            "Disable password logins, root login, and X11 forwarding in a drop-in file."
        )
        fix_cmd = SSHD_FIX_CMD

    return make_result(
        id="sshd_config",
        category="Services",
        title="OpenSSH Daemon Configuration",
        passed=passed,
        applicable=True,
        score=score,
        max_score=5,
        severity=severity,
        description=description,
        details=details,
        recommendation=recommendation,
        fix_cmd=fix_cmd,
        lane="fast",
        refs=list(SSHD_REFS),
    )


def _strip_exec_prefix(token):
    while token and token[0] in "-@+!":
        token = token[1:]
    return token


def _unsafe_exec_path(token, home):
    token = _strip_exec_prefix(token)
    if not token:
        return False
    if token.startswith("~/"):
        token = str(Path(home) / token[2:])
    token = os.path.expanduser(token)
    roots = (
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        str(Path(home) / "Downloads"),
    )
    for root in roots:
        if token == root or token.startswith(root + "/"):
            return True
    return False


def _execstart_tokens(value):
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        tokens = value.split()
    return tokens


def _iter_user_unit_files(root):
    root_path = Path(root)
    if not root_path.is_dir():
        return []
    files = []
    try:
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            dirnames[:] = [name for name in dirnames if name not in {".git"}]
            for name in filenames:
                if name.endswith(".service"):
                    files.append(Path(dirpath) / name)
    except OSError:
        return []
    return files


@register_check(
    FAST_CHECKS,
    check_id="user_services",
    category="Services",
    title="User Systemd Services",
    max_score=2,
)
def check_user_services(
    *,
    runner=None,
    reader=None,
    home=None,
    units_dir=None,
    walk_fn=None,
):
    runner = run_cmd if runner is None else runner
    reader = read_text if reader is None else reader
    home = str(Path.home()) if home is None else str(home)
    units_dir = (
        str(Path(home) / ".config" / "systemd" / "user")
        if units_dir is None
        else str(units_dir)
    )
    walk_fn = _iter_user_unit_files if walk_fn is None else walk_fn

    listed = runner(
        [
            "systemctl",
            "--user",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
        ],
        timeout=1.5,
    )
    if listed.returncode == 127:
        return make_result(
            id="user_services",
            category="Services",
            title="User Systemd Services",
            passed=True,
            applicable=False,
            score=0,
            max_score=2,
            description="User systemd instance is not available.",
            lane="fast",
            refs=list(USER_REFS),
        )
    if listed.returncode == 124:
        return make_result(
            id="user_services",
            category="Services",
            title="User Systemd Services",
            passed=True,
            applicable=False,
            score=0,
            max_score=2,
            description="systemctl --user list-units timed out.",
            lane="fast",
            refs=list(USER_REFS),
        )

    running_lines = [
        line for line in (listed.stdout or "").splitlines() if line.strip()
    ]
    details = [str(len(running_lines)) + " running user service(s)."]

    unsafe = []
    for unit_path in walk_fn(units_dir):
        text = reader(str(unit_path))
        if text is None:
            details.append("Unreadable unit: " + str(unit_path))
            continue
        for raw in text.splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if stripped.split("=", 1)[0].strip() != "ExecStart":
                continue
            value = stripped.split("=", 1)[1].strip()
            for token in _execstart_tokens(value):
                if _unsafe_exec_path(token, home):
                    unsafe.append(str(unit_path))
                    details.append(
                        Path(unit_path).name + " ExecStart lives under a world-writable path."
                    )
                    break

    score = 0 if unsafe else 2
    passed = not unsafe
    if passed:
        description = "No user units execute from temporary or Downloads paths."
        severity = "info"
        recommendation = None
    else:
        description = "A user unit ExecStart path is under /tmp, /var/tmp, /dev/shm, or ~/Downloads."
        severity = "high"
        recommendation = "Move user service binaries out of temporary directories and ~/Downloads."

    return make_result(
        id="user_services",
        category="Services",
        title="User Systemd Services",
        passed=passed,
        applicable=True,
        score=score,
        max_score=2,
        severity=severity,
        description=description,
        details=details,
        recommendation=recommendation,
        lane="fast",
        refs=list(USER_REFS),
    )

