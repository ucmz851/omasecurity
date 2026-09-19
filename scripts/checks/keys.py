"""SSH and GnuPG permission checks (id: ssh_gpg_perms, weight 15)."""

from __future__ import annotations

from pathlib import Path

from . import FAST_CHECKS, make_result, register_check

HOME = Path.home()
REFS = [
    "https://wiki.archlinux.org/title/SSH_keys",
    "https://wiki.archlinux.org/title/GnuPG",
]


def check_file_mode(path, max_allowed):
    try:
        mode = path.stat().st_mode & 0o777
        return (mode & ~max_allowed) == 0
    except OSError:
        return False


def get_mode_str(path):
    try:
        return oct(path.stat().st_mode & 0o777)[2:]
    except OSError:
        return "unknown"


@register_check(
    FAST_CHECKS,
    check_id="ssh_gpg_perms",
    category="Authentication",
    title="SSH & GPG Key Permissions",
    max_score=15,
)
def check_ssh_gpg_perms(*, home=None):
    home = Path(home) if home else HOME
    ssh_dir = home / ".ssh"
    gnupg_dir = home / ".gnupg"
    if not ssh_dir.exists() and not gnupg_dir.exists():
        return make_result(
            id="ssh_gpg_perms",
            category="Authentication",
            title="SSH & GPG Key Permissions",
            passed=False,
            applicable=False,
            score=0,
            max_score=15,
            description="No ~/.ssh or ~/.gnupg directories are present.",
            details=["Neither SSH nor GnuPG home directories exist in the checked home."],
            refs=REFS,
        )

    issues = []
    details = []
    score = 15

    if ssh_dir.exists():
        if not check_file_mode(ssh_dir, 0o700):
            issues.append(f"~/.ssh is mode {get_mode_str(ssh_dir)} (expected 700)")
            score -= 5
        else:
            details.append("~/.ssh mode is 700 or stricter")
        try:
            for item in sorted(ssh_dir.iterdir(), key=lambda p: p.name):
                if not item.is_file():
                    continue
                name = item.name
                if (name.startswith("id_") or name.endswith(".pem")) and not name.endswith(".pub"):
                    # Report key names only; never file contents.
                    if not check_file_mode(item, 0o600):
                        issues.append(f"Private key {name} is mode {get_mode_str(item)} (expected 600)")
                        score -= 5
                    else:
                        details.append(f"private key {name} mode is 600 or stricter")
        except OSError:
            details.append("~/.ssh could not be listed")
    else:
        details.append("~/.ssh not present (skipped)")

    if gnupg_dir.exists():
        if not check_file_mode(gnupg_dir, 0o700):
            issues.append(f"~/.gnupg is mode {get_mode_str(gnupg_dir)} (expected 700)")
            score -= 5
        else:
            details.append("~/.gnupg mode is 700 or stricter")
    else:
        details.append("~/.gnupg not present (skipped)")

    score = max(0, score)
    passed = len(issues) == 0
    if passed:
        desc = "~/.ssh keys and ~/.gnupg keyring directories have strict permissions (700/600)."
        rec = None
        fix = None
        severity = "info"
    else:
        desc = "; ".join(issues)
        rec = "Restrict read permissions on SSH private keys and keyring folders so other users cannot access them."
        fix = "chmod 700 ~/.ssh ~/.gnupg 2>/dev/null; chmod 600 ~/.ssh/id_* ~/.ssh/*.pem 2>/dev/null"
        severity = "high" if score < 10 else "medium"

    return make_result(
        id="ssh_gpg_perms",
        category="Authentication",
        title="SSH & GPG Key Permissions",
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
