"""Idle screen lock via hypridle listener blocks and shell.json (id: desktop_lock, weight 10)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import FAST_CHECKS, make_result, register_check, read_text

HOME = Path.home()
LOCK_MARKERS = ("hyprlock", "loginctl lock-session", "omarchy-lock-screen")
REFS = ["https://wiki.hypr.land/Hypr-Ecosystem/hypridle/"]


def parse_hypridle_listeners(text):
    """Return list of {timeout: int|None, on-timeout: str} from listener { } blocks."""
    listeners = []
    current = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^listener\b", stripped, re.IGNORECASE):
            current = {"timeout": None, "on-timeout": ""}
            if "}" in stripped and "{" in stripped:
                listeners.append(current)
                current = None
            continue
        if current is None:
            continue
        if stripped.startswith("}"):
            listeners.append(current)
            current = None
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip().lower()
        value = value.split("#", 1)[0].strip().strip("\"'")
        if key == "timeout":
            try:
                current["timeout"] = int(value.split()[0])
            except (ValueError, IndexError):
                current["timeout"] = None
        elif key == "on-timeout":
            current["on-timeout"] = value
    return listeners


def _lock_timeouts(listeners):
    timeouts = []
    for listener in listeners:
        timeout = listener.get("timeout")
        cmd = listener.get("on-timeout") or ""
        if timeout is None or timeout <= 0:
            continue
        if any(marker in cmd for marker in LOCK_MARKERS):
            timeouts.append(timeout)
    return timeouts


@register_check(
    FAST_CHECKS,
    check_id="desktop_lock",
    category="Desktop Security",
    title="Screen Lock & Idle Protection",
    max_score=10,
)
def check_desktop_lock(*, hypridle_path=None, shell_json_path=None):
    hypridle_path = Path(hypridle_path) if hypridle_path else HOME / ".config" / "hypr" / "hypridle.conf"
    shell_json_path = Path(shell_json_path) if shell_json_path else HOME / ".config" / "omarchy" / "shell.json"

    hypridle_text = read_text(hypridle_path) if hypridle_path.exists() else None
    shell_text = read_text(shell_json_path) if shell_json_path.exists() else None
    if hypridle_text is None and shell_text is None:
        return make_result(
            id="desktop_lock",
            category="Desktop Security",
            title="Screen Lock & Idle Protection",
            passed=False,
            applicable=False,
            score=0,
            max_score=10,
            description="No hypridle.conf or shell.json idle configuration is present.",
            details=["Neither Hyprland hypridle nor Omarchy shell idle.lock was found."],
            refs=REFS,
        )

    details = []
    lock_seconds = []

    if hypridle_text is not None:
        timeouts = _lock_timeouts(parse_hypridle_listeners(hypridle_text))
        if timeouts:
            effective = min(timeouts)
            lock_seconds.append(effective)
            details.append(f"hypridle lock timeout: {effective}s")
        else:
            details.append("hypridle has no lock listener with timeout > 0")
    else:
        details.append("hypridle.conf not present")

    if shell_text is not None:
        try:
            data = json.loads(shell_text)
            idle_lock = data.get("idle", {}).get("lock", 0) if isinstance(data, dict) else 0
            try:
                idle_lock = int(idle_lock)
            except (TypeError, ValueError):
                idle_lock = 0
            if idle_lock > 0:
                lock_seconds.append(idle_lock)
                details.append(f"shell idle.lock: {idle_lock}s")
            else:
                details.append("shell.json idle.lock is 0 or unset")
        except json.JSONDecodeError:
            details.append("shell.json is not valid JSON")
    else:
        details.append("shell.json not present")

    if lock_seconds:
        effective = min(lock_seconds)
        return make_result(
            id="desktop_lock",
            category="Desktop Security",
            title="Screen Lock & Idle Protection",
            passed=True,
            score=10,
            max_score=10,
            description=f"Automated screen locking is active (effective lock timeout {effective}s).",
            details=details,
            refs=REFS,
        )

    return make_result(
        id="desktop_lock",
        category="Desktop Security",
        title="Screen Lock & Idle Protection",
        passed=False,
        score=0,
        max_score=10,
        severity="medium",
        description="No automated screen lock timeout configured in hypridle or shell.json.",
        details=details,
        recommendation="Configure automatic session locking to secure your desktop when away from your PC.",
        refs=REFS,
    )
