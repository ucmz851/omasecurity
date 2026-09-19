"""Kernel memory protection sysctls, cmdline mitigations, and CPU vulnerability files.

id: kernel_hardening, weight 15 (rebalanced: ptrace -4, dmesg -2, kptr -4,
mitigations=off -3, Vulnerable* files -2).
"""

from __future__ import annotations

from pathlib import Path

from . import FAST_CHECKS, make_result, register_check, read_text

PTRACE = Path("/proc/sys/kernel/yama/ptrace_scope")
DMESG = Path("/proc/sys/kernel/dmesg_restrict")
KPTR = Path("/proc/sys/kernel/kptr_restrict")
CMDLINE = Path("/proc/cmdline")
VULNS = Path("/sys/devices/system/cpu/vulnerabilities")
REFS = [
    "https://docs.kernel.org/admin-guide/sysctl/kernel.html",
    "https://docs.kernel.org/admin-guide/kernel-parameters.html",
    "https://docs.kernel.org/admin-guide/hw-vuln/index.html",
    "https://wiki.archlinux.org/title/Security",
]


def _int_file(path):
    text = read_text(path)
    if text is None:
        return None
    try:
        return int(text.strip().split()[0])
    except (ValueError, IndexError):
        return None


@register_check(
    FAST_CHECKS,
    check_id="kernel_hardening",
    category="System Security",
    title="Kernel & Memory Protection",
    max_score=15,
)
def check_kernel_hardening(
    *,
    ptrace_path=None,
    dmesg_path=None,
    kptr_path=None,
    cmdline_path=None,
    vulns_dir=None,
):
    ptrace_path = Path(ptrace_path) if ptrace_path else PTRACE
    dmesg_path = Path(dmesg_path) if dmesg_path else DMESG
    kptr_path = Path(kptr_path) if kptr_path else KPTR
    cmdline_path = Path(cmdline_path) if cmdline_path else CMDLINE
    vulns_dir = Path(vulns_dir) if vulns_dir else VULNS

    sources_exist = any(p.exists() for p in (ptrace_path, dmesg_path, kptr_path, cmdline_path, vulns_dir))
    if not sources_exist:
        return make_result(
            id="kernel_hardening",
            category="System Security",
            title="Kernel & Memory Protection",
            passed=False,
            applicable=False,
            score=0,
            max_score=15,
            description="Kernel sysctl, cmdline, and CPU vulnerability files are not available.",
            details=["No /proc sysctls, /proc/cmdline, or CPU vulnerability files were readable."],
            refs=REFS,
        )

    issues = []
    details = []
    score = 15

    ptrace = _int_file(ptrace_path)
    if ptrace is None and not ptrace_path.exists():
        details.append("yama.ptrace_scope not present (skipped).")
    elif ptrace is None or ptrace < 1:
        issues.append("Process memory inspection unrestricted (yama.ptrace_scope = 0)")
        score -= 4
    else:
        details.append(f"yama.ptrace_scope={ptrace}")

    dmesg = _int_file(dmesg_path)
    if dmesg is None and not dmesg_path.exists():
        details.append("dmesg_restrict not present (skipped).")
    elif dmesg is None or dmesg < 1:
        issues.append("Kernel logs exposed to non-root users (dmesg_restrict = 0)")
        score -= 2
    else:
        details.append(f"dmesg_restrict={dmesg}")

    kptr = _int_file(kptr_path)
    if kptr is None and not kptr_path.exists():
        details.append("kptr_restrict not present (skipped).")
    elif kptr is None or kptr < 1:
        issues.append("Kernel addresses exposed in /proc/kallsyms (kptr_restrict = 0)")
        score -= 4
    else:
        details.append(f"kptr_restrict={kptr}")

    cmdline = read_text(cmdline_path)
    if cmdline is None:
        details.append("/proc/cmdline not present (skipped).")
    else:
        tokens = cmdline.split()
        if "mitigations=off" in tokens:
            issues.append("CPU vulnerability mitigations disabled (mitigations=off)")
            score -= 3
            details.append("cmdline contains mitigations=off")
        else:
            details.append("cmdline does not disable mitigations")

    if not vulns_dir.exists():
        details.append("CPU vulnerability sysfs not present (skipped).")
    else:
        vulnerable = []
        try:
            entries = sorted(vulns_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for entry in entries:
            if not entry.is_file():
                continue
            text = (read_text(entry) or "").lstrip()
            if text.startswith("Vulnerable"):
                vulnerable.append(entry.name)
        if vulnerable:
            issues.append("CPU vulnerability sysfs reports Vulnerable: " + ", ".join(vulnerable))
            score -= 2
            details.append("Vulnerable: " + ", ".join(vulnerable))
        else:
            details.append("No CPU vulnerability files start with Vulnerable")

    score = max(0, score)
    passed = len(issues) == 0
    if passed:
        desc = "Kernel memory, cmdline mitigations, and CPU vulnerability state are hardened."
        rec = None
        fix = None
        severity = "info"
    else:
        desc = "; ".join(issues)
        rec = "Enable YAMA ptrace, hide kernel pointers, and do not boot with mitigations=off."
        fix = (
            "echo -e 'kernel.yama.ptrace_scope=1\\nkernel.dmesg_restrict=1\\n"
            "kernel.kptr_restrict=1' | sudo tee /etc/sysctl.d/99-security.conf "
            "&& sudo sysctl --system"
        )
        severity = "high" if score < 10 else "medium"

    return make_result(
        id="kernel_hardening",
        category="System Security",
        title="Kernel & Memory Protection",
        passed=passed,
        score=score,
        max_score=15,
        severity=severity,
        description=desc,
        details=details,
        recommendation=rec,
        fix_cmd=fix,
        refs=REFS,
    )
