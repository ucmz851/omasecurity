"""Public TCP listeners and sshd PermitRootLogin (id: network_ports, weight 5).

Only TCP LISTEN sockets count as public listeners. UDP unconnected sockets
bound to wildcard addresses are reported in details without penalty.
Uses `ss -tlnH` and `ss -ulnH` separately.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import FAST_CHECKS, make_result, register_check, read_text, run_cmd

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
REFS = [
    "https://man.archlinux.org/man/ss.8",
    "https://man.archlinux.org/man/sshd_config.5",
]


def _is_wildcard_local(addr):
    host = addr.rsplit(":", 1)[0]
    host = host.strip("[]")
    return host in {"0.0.0.0", "*", "::", ""}


def _parse_ss_locals(stdout):
    addrs = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # ss -tlnH / -ulnH: State Recv-Q Send-Q Local Peer
        addrs.append(parts[3])
    return addrs


def _ports_of(addrs):
    ports = []
    for addr in addrs:
        if not _is_wildcard_local(addr):
            continue
        port = addr.rsplit(":", 1)[-1]
        if port and port not in ports:
            ports.append(port)
    return ports


@register_check(
    FAST_CHECKS,
    check_id="network_ports",
    category="Network",
    title="Public Ports & SSH Hardening",
    max_score=5,
)
def check_network_ports(*, sshd_config=None, run=None):
    sshd_config = Path(sshd_config) if sshd_config else SSHD_CONFIG
    run = run or run_cmd
    details = []
    issues = []
    score = 5
    tcp_res = run(["ss", "-tlnH"], timeout=1.0)
    udp_res = run(["ss", "-ulnH"], timeout=1.0)
    ss_missing = tcp_res.returncode == 127 and udp_res.returncode == 127
    sshd_text = read_text(sshd_config) if sshd_config.exists() else None

    if ss_missing and sshd_text is None:
        return make_result(
            id="network_ports",
            category="Network",
            title="Public Ports & SSH Hardening",
            passed=False,
            applicable=False,
            score=0,
            max_score=5,
            description="ss is not installed and sshd_config is not present.",
            details=["Install iproute2 (ss) to enumerate listeners, or inspect sshd_config by hand."],
            refs=REFS,
        )

    public_tcp = []
    if tcp_res.returncode == 127:
        details.append("ss not installed; TCP listeners unknown")
    else:
        public_tcp = _ports_of(_parse_ss_locals(tcp_res.stdout))
        if public_tcp:
            details.append("public TCP LISTEN ports: " + ", ".join(public_tcp))
        else:
            details.append("no public TCP LISTEN sockets")
        if len(public_tcp) > 6:
            shown = ", ".join(public_tcp[:6]) + "..."
            issues.append(f"Multiple services bound to public interfaces ({shown})")
            score -= 2

    if udp_res.returncode == 127:
        details.append("ss not installed; UDP sockets unknown")
    else:
        public_udp = _ports_of(_parse_ss_locals(udp_res.stdout))
        if public_udp:
            details.append(
                "UDP unconnected wildcard sockets (no score penalty): " + ", ".join(public_udp)
            )
        else:
            details.append("no public UDP unconnected sockets")

    if sshd_text is None:
        details.append("sshd_config not present (skipped)")
    else:
        match = re.search(
            r"^\s*PermitRootLogin\s+(yes|prohibit-password|without-password|no)",
            sshd_text,
            re.MULTILINE | re.IGNORECASE,
        )
        if match and match.group(1).lower() == "yes":
            issues.append("SSH server allows direct root login (PermitRootLogin yes)")
            score -= 3
            details.append("PermitRootLogin yes")
        else:
            value = match.group(1) if match else "default"
            details.append(f"PermitRootLogin {value}")

    score = max(0, score)
    passed = len(issues) == 0
    if passed:
        desc = (
            f"Network ports are minimal ({len(public_tcp)} public TCP: "
            f"{', '.join(public_tcp) if public_tcp else 'none'}) and SSH daemon is secure."
        )
        rec = None
        severity = "info"
    else:
        desc = "; ".join(issues)
        rec = "Bind unneeded local services to 127.0.0.1 and disable SSH root password authentication."
        severity = "medium"

    return make_result(
        id="network_ports",
        category="Network",
        title="Public Ports & SSH Hardening",
        passed=passed,
        score=score,
        max_score=5,
        severity=severity,
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS,
    )
