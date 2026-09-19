"""Host firewall state (id: firewall, weight 15). Never calls sudo."""

from __future__ import annotations

from pathlib import Path

from . import FAST_CHECKS, make_result, register_check, run_cmd

UFW_CONF = Path("/etc/ufw/ufw.conf")
SERVICES = ("ufw", "nftables", "firewalld", "iptables")
REFS = [
    "https://wiki.archlinux.org/title/Uncomplicated_Firewall",
    "https://wiki.archlinux.org/title/Nftables",
]


def _ufw_enabled(path):
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip().upper() != "ENABLED":
            continue
        token = value.split("#", 1)[0].strip().lower()
        return token in {"yes", "true", "1"}
    return False


@register_check(
    FAST_CHECKS,
    check_id="firewall",
    category="Network",
    title="Host Firewall",
    max_score=15,
)
def check_firewall(*, ufw_conf=None, run=None):
    ufw_conf = Path(ufw_conf) if ufw_conf else UFW_CONF
    run = run or run_cmd
    details = []
    active = None

    for srv in SERVICES:
        res = run(["systemctl", "is-active", srv], timeout=1.0)
        if res.returncode == 127:
            continue
        if res.stdout.strip() == "active":
            active = srv
            details.append(f"{srv} service is active.")
            break

    if _ufw_enabled(ufw_conf):
        details.append("UFW ENABLED=yes in " + str(ufw_conf))
        if active is None:
            active = "ufw"

    if active:
        return make_result(
            id="firewall",
            category="Network",
            title="Host Firewall",
            passed=True,
            score=15,
            max_score=15,
            description=details[0] if details else "Firewall protection is active.",
            details=details,
            refs=REFS,
        )

    return make_result(
        id="firewall",
        category="Network",
        title="Host Firewall",
        passed=False,
        score=0,
        max_score=15,
        severity="high",
        description="No active host firewall detected (UFW/nftables/firewalld is inactive).",
        details=["Checked systemctl is-active for ufw, nftables, firewalld, iptables."],
        recommendation="Enable a host firewall (like UFW) to prevent unauthorized incoming network connections.",
        fix_cmd="sudo ufw enable && sudo ufw default deny incoming",
        refs=REFS,
    )
