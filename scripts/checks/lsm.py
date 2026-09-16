"""LSM presence and Linux audit-framework checks (fast lane)."""

from __future__ import annotations

from pathlib import Path

from . import FAST_CHECKS, make_result, read_text, register_check, run_cmd

LSM_PATH = "/sys/kernel/security/lsm"
LOCKDOWN_PATH = "/sys/kernel/security/lockdown"
AUDIT_RULES_DIR = "/etc/audit/rules.d"

LSM_REFS = [
    "https://wiki.archlinux.org/title/Security#Kernel_hardening",
    "https://wiki.archlinux.org/title/Security#Mandatory_access_control",
    "https://wiki.archlinux.org/title/AppArmor",
    "https://docs.kernel.org/admin-guide/lsm/index.html",
]
AUDIT_REFS = [
    "https://wiki.archlinux.org/title/Audit_framework",
]
APPARMOR_CMDLINE = "lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _worse(current, candidate):
    if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0):
        return candidate
    return current


def _pkg_installed(runner, name):
    proc = runner(["pacman", "-Q", name], timeout=1.0)
    return proc.returncode == 0


def _audit_explicitly_installed(runner):
    proc = runner(["pacman", "-Qi", "audit"], timeout=1.0)
    if proc.returncode != 0:
        return False
    for line in (proc.stdout or "").splitlines():
        if "Install Reason" in line and "Explicitly installed" in line:
            return True
    return False


def _auditd_enabled(runner):
    proc = runner(["systemctl", "is-enabled", "auditd"], timeout=1.0)
    return (proc.stdout or "").strip().lower() in {"enabled", "enabled-runtime"}


def _list_readable_files(path):
    """Return (readable_count, status) where status is ok, missing, or unreadable."""
    directory = Path(path)
    try:
        entries = list(directory.iterdir())
    except FileNotFoundError:
        return 0, "missing"
    except PermissionError:
        return 0, "unreadable"
    except OSError:
        return 0, "unreadable"

    readable = 0
    for entry in entries:
        try:
            if not entry.is_file():
                continue
            with entry.open("r"):
                readable += 1
        except OSError:
            continue
    return readable, "ok"


@register_check(
    FAST_CHECKS,
    check_id="lsm_status",
    category="System Security",
    title="Linux Security Modules",
    max_score=5,
)
def check_lsm_status(
    *,
    reader=None,
    runner=None,
    lsm_path=LSM_PATH,
    lockdown_path=LOCKDOWN_PATH,
):
    reader = read_text if reader is None else reader
    runner = run_cmd if runner is None else runner

    lsm_raw = reader(lsm_path)
    if lsm_raw is None:
        return make_result(
            id="lsm_status",
            category="System Security",
            title="Linux Security Modules",
            passed=True,
            applicable=False,
            score=0,
            max_score=5,
            description="LSM list is not available (/sys/kernel/security/lsm is missing).",
            lane="fast",
            refs=list(LSM_REFS),
        )

    modules = [part.strip() for part in lsm_raw.strip().split(",") if part.strip()]
    details = ["LSM list: " + ",".join(modules)]
    score = 5
    severity = "info"
    issues = []

    if "yama" not in modules:
        score -= 2
        severity = _worse(severity, "medium")
        issues.append("yama")
        details.append("Yama is missing from the LSM list.")
    if "landlock" not in modules:
        score -= 2
        severity = _worse(severity, "medium")
        issues.append("landlock")
        details.append("Landlock is missing from the LSM list.")

    uname = runner(["uname", "-r"], timeout=1.0)
    release = (uname.stdout or "").strip()
    if uname.returncode == 0 and "hardened" in release.lower():
        details.append("Kernel flavour is hardened (" + release + ").")

    lockdown = reader(lockdown_path)
    if lockdown is None:
        details.append("Lockdown sysfs is not available.")
    else:
        details.append("Lockdown: " + lockdown.strip())

    recommendation = None
    if _pkg_installed(runner, "apparmor"):
        if "apparmor" in modules:
            active = runner(["systemctl", "is-active", "apparmor"], timeout=1.0)
            if (active.stdout or "").strip() != "active":
                score -= 1
                severity = _worse(severity, "medium")
                issues.append("apparmor inactive")
                details.append("AppArmor package is installed and in the LSM list, but the service is inactive.")
                recommendation = "Enable and start the AppArmor service: systemctl enable --now apparmor."
        else:
            score -= 1
            severity = _worse(severity, "medium")
            issues.append("apparmor not in LSM list")
            details.append("AppArmor is installed but not in the LSM list.")
            recommendation = "Add " + APPARMOR_CMDLINE + " to the kernel cmdline."
    else:
        details.append("AppArmor is not installed and is optional on Omarchy.")

    score = max(0, score)
    passed = score == 5
    if passed:
        description = "Yama and Landlock are present in the LSM list."
        severity = "info"
    elif issues:
        description = "LSM baseline is incomplete (" + ", ".join(issues) + ")."
    else:
        description = "Linux Security Modules baseline is incomplete."

    return make_result(
        id="lsm_status",
        category="System Security",
        title="Linux Security Modules",
        passed=passed,
        applicable=True,
        score=score,
        max_score=5,
        severity=severity,
        description=description,
        details=details,
        recommendation=recommendation,
        lane="fast",
        refs=list(LSM_REFS),
    )


@register_check(
    FAST_CHECKS,
    check_id="audit_framework",
    category="System Security",
    title="Linux Audit Framework",
    max_score=3,
)
def check_audit_framework(
    *,
    runner=None,
    listdir_fn=None,
    rules_dir=AUDIT_RULES_DIR,
):
    runner = run_cmd if runner is None else runner
    listdir_fn = _list_readable_files if listdir_fn is None else listdir_fn

    if not (
        _audit_explicitly_installed(runner) or _auditd_enabled(runner)
    ):
        return make_result(
            id="audit_framework",
            category="System Security",
            title="Linux Audit Framework",
            passed=True,
            applicable=False,
            score=0,
            max_score=3,
            description=(
                "audit is installed only as a dependency; auditd is optional on Omarchy"
            ),
            lane="fast",
            refs=list(AUDIT_REFS),
        )

    details = []
    score = 3
    severity = "info"
    recommendation = None
    active = runner(["systemctl", "is-active", "auditd"], timeout=1.0)
    auditd_active = (active.stdout or "").strip() == "active"
    if not auditd_active:
        score = 0
        severity = "medium"
        details.append("auditd is inactive.")
        recommendation = "Install audit rules and enable the daemon: systemctl enable --now auditd."
    else:
        details.append("auditd is active.")

    readable, status = listdir_fn(rules_dir)
    if status == "unreadable":
        details.append(
            "Audit rules could not be inspected without root. Run: sudo auditctl -l"
        )
    elif status == "missing":
        details.append("/etc/audit/rules.d is missing.")
    else:
        details.append(str(readable) + " readable file(s) in /etc/audit/rules.d")

    passed = score == 3
    if passed:
        description = "auditd is active."
    else:
        description = "auditd is inactive."

    return make_result(
        id="audit_framework",
        category="System Security",
        title="Linux Audit Framework",
        passed=passed,
        applicable=True,
        score=score,
        max_score=3,
        severity=severity,
        description=description,
        details=details,
        recommendation=recommendation,
        lane="fast",
        refs=list(AUDIT_REFS),
    )

