"""PATH integrity and sudo NOPASSWD (id: privileges_path, weight 15).

Never calls sudo. `sudo -n -l` on this development host printed
"sudo: a password is required" (and on systemd hosts that failed probe
is recorded in the journal as _COMM=sudo). NOPASSWD is therefore reported
as unknown with the manual command `sudo -l | grep NOPASSWD`.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import FAST_CHECKS, make_result, register_check

REFS = [
    "https://wiki.archlinux.org/title/Sudo",
    "https://man.archlinux.org/man/sudoers.5",
]
NOPASSWD_HINT = "sudo -l | grep NOPASSWD"


@register_check(
    FAST_CHECKS,
    check_id="privileges_path",
    category="Authentication",
    title="Privilege Boundaries & PATH",
    max_score=15,
)
def check_privileges_and_path(*, path_value=None):
    path_value = os.environ.get("PATH", "") if path_value is None else path_value
    issues = []
    details = []
    score = 15

    for entry in path_value.split(":"):
        if entry in ("", "."):
            issues.append("Current directory (.) in PATH (binary hijacking risk)")
            score -= 8
            details.append("PATH contains an empty or '.' component")
            break
        path_obj = Path(entry)
        try:
            if path_obj.exists() and (path_obj.stat().st_mode & 0o002):
                issues.append(f"World-writable directory in PATH: {entry}")
                score -= 8
                details.append(f"world-writable PATH entry: {entry}")
                break
        except OSError:
            continue

    # Do not run `sudo -n -l`: a failed non-interactive sudo writes
    # "a password is required" to the journal on every scan.
    details.append("NOPASSWD status unknown; run: " + NOPASSWD_HINT)

    score = max(0, score)
    passed = len(issues) == 0
    if passed:
        desc = "System execution PATH is clean. Passwordless sudo was not probed (requires an interactive sudo -l)."
        rec = None
        severity = "info"
    else:
        desc = "; ".join(issues)
        rec = "Remove unneeded NOPASSWD entries from sudoers and ensure PATH does not contain relative directories."
        severity = "high" if score < 10 else "medium"

    return make_result(
        id="privileges_path",
        category="Authentication",
        title="Privilege Boundaries & PATH",
        passed=passed,
        score=score,
        max_score=15,
        severity=severity,
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS,
    )
