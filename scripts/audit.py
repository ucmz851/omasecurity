#!/usr/bin/env python3
"""
OmaSecurity Comprehensive Audit Engine
Performs fast, non-blocking, deep security & plugin code health checks for Omarchy Linux / Quattro shell.
Outputs JSON format for consumption by Quickshell QML.
"""

import os
import sys
import json
import re
import stat
import subprocess
from pathlib import Path

HOME = Path.home()

def check_file_mode(path: Path, max_allowed: int) -> bool:
    try:
        st = path.stat()
        mode = st.st_mode & 0o777
        return (mode & ~max_allowed) == 0
    except Exception:
        return False

def get_mode_str(path: Path) -> str:
    try:
        return oct(path.stat().st_mode & 0o777)[2:]
    except Exception:
        return "unknown"

# ----------------------------------------------------------------------
# 1. DEEP PLUGIN CODE & SAFETY AUDIT
# ----------------------------------------------------------------------
def audit_plugins_deep():
    plugins_dir = HOME / ".config" / "omarchy" / "plugins"
    if not plugins_dir.exists():
        return {
            "id": "plugins_deep",
            "category": "Plugin Health",
            "title": "Shell Plugin Code Health & Safety",
            "passed": True,
            "score": 25,
            "max_score": 25,
            "severity": "info",
            "description": "No user shell plugins installed.",
            "recommendation": None,
            "fix_cmd": None,
            "scanned_count": 0,
            "files_count": 0,
            "flagged_items": []
        }

    rules = [
        {
            "id": "pipe_to_shell",
            "severity": "CRITICAL",
            "regex": re.compile(r'(curl|wget)\s+[^|\n]+?\|\s*(ba)?sh', re.IGNORECASE),
            "title": "Pipes remote download directly to shell execution",
            "explanation": "Executes unverified remote web content directly in bash."
        },
        {
            "id": "obfuscated_exec",
            "severity": "CRITICAL",
            "regex": re.compile(r'(eval\s*\(|new\s+Function\s*\(|base64\s+-d\s*\|\s*(ba)?sh|exec\s*\(\s*bytes\.fromhex)', re.IGNORECASE),
            "title": "Dynamic / Obfuscated Code Execution",
            "explanation": "Executes dynamically compiled or encoded strings in memory."
        },
        {
            "id": "private_key",
            "severity": "CRITICAL",
            "regex": re.compile(r'-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----'),
            "title": "Hardcoded Private Key",
            "explanation": "Unencrypted private cryptographic key found inside source."
        },
        {
            "id": "api_secret",
            "severity": "HIGH",
            "regex": re.compile(r'(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|AKIA[0-9A-Z]{16})'),
            "title": "Hardcoded Cloud/API Token",
            "explanation": "Live cloud access token or GitHub PAT found in plaintext."
        },
        {
            "id": "sensitive_credential_access",
            "severity": "HIGH",
            "regex": re.compile(r'(\.ssh/id_|\.gnupg/|\.local/share/keyrings|/etc/shadow|\.config/google-chrome)', re.IGNORECASE),
            "title": "Accesses Protected Credentials Path",
            "explanation": "Accesses private SSH keys, GPG rings, or browser authentication databases."
        },
        {
            "id": "silent_sudo",
            "severity": "MEDIUM",
            "regex": re.compile(r'^\s*(sudo\s+|pkexec\s+|doas\s+)', re.MULTILINE | re.IGNORECASE),
            "title": "Privilege Escalation (sudo/pkexec)",
            "explanation": "Plugin executes commands with root privileges."
        }
    ]

    scanned_plugins = 0
    total_files = 0
    flagged_items = []

    for plugin in plugins_dir.iterdir():
        if not plugin.is_dir() or plugin.name.startswith(".") or plugin.name in ["omasecurity", "ucmz851.omasecurity", "local.omasecurity"]:
            continue
        scanned_plugins += 1

        for root, dirs, files in os.walk(plugin):
            if ".git" in dirs:
                dirs.remove(".git")
            # Skip test suites to avoid mock test false positives
            if "test" in dirs:
                dirs.remove("test")
            if "tests" in dirs:
                dirs.remove("tests")

            for f in files:
                ext = Path(f).suffix.lower()
                if ext in [".qml", ".js", ".sh", ".py", ".json", ".toml"]:
                    total_files += 1
                    filepath = Path(root) / f
                    try:
                        lines = filepath.read_text(errors="ignore").splitlines()
                        for line_no, line in enumerate(lines, 1):
                            sline = line.strip()
                            # Skip comment lines
                            if sline.startswith("//") or sline.startswith("#") or sline.startswith("*") or sline.startswith("/*"):
                                continue
                            for rule in rules:
                                if rule["regex"].search(sline):
                                    rel = filepath.relative_to(plugins_dir)
                                    flagged_items.append({
                                        "plugin": plugin.name,
                                        "file": str(rel),
                                        "line": line_no,
                                        "severity": rule["severity"],
                                        "title": rule["title"],
                                        "explanation": rule["explanation"],
                                        "snippet": sline[:80]
                                    })
                                    break
                    except Exception:
                        pass

    critical_count = sum(1 for x in flagged_items if x["severity"] == "CRITICAL")
    high_count = sum(1 for x in flagged_items if x["severity"] == "HIGH")
    med_count = sum(1 for x in flagged_items if x["severity"] == "MEDIUM")

    score_deduction = (critical_count * 15) + (high_count * 8) + (med_count * 3)
    final_score = max(0, 25 - score_deduction)
    passed = len(flagged_items) == 0

    if passed:
        desc = f"All {scanned_plugins} installed plugins ({total_files} files) passed deep static security analysis."
    else:
        desc = f"Scanned {scanned_plugins} plugins ({total_files} files): {len(flagged_items)} risk(s) flagged ({critical_count} critical, {high_count} high, {med_count} medium)."

    return {
        "id": "plugins_deep",
        "category": "Plugin Health",
        "title": "Shell Plugin Code Health & Safety",
        "passed": passed,
        "score": final_score,
        "max_score": 25,
        "severity": "critical" if critical_count > 0 else ("high" if high_count > 0 else ("medium" if med_count > 0 else "info")),
        "description": desc,
        "recommendation": "Inspect flagged plugin source files and remove unescaped shell executions, hardcoded tokens, or unneeded sudo commands." if not passed else None,
        "fix_cmd": None,
        "scanned_count": scanned_plugins,
        "files_count": total_files,
        "flagged_items": flagged_items
    }

# ----------------------------------------------------------------------
# 2. KERNEL & MEMORY PROTECTION (SYSCTL / YAMA)
# ----------------------------------------------------------------------
def audit_kernel_hardening():
    issues = []
    score = 15

    # 1. Yama ptrace scope (prevents process memory dumping)
    ptrace_path = Path("/proc/sys/kernel/yama/ptrace_scope")
    if ptrace_path.exists():
        try:
            val = int(ptrace_path.read_text().strip())
            if val < 1:
                issues.append("Process memory inspection unrestricted (yama.ptrace_scope = 0)")
                score -= 6
        except Exception:
            pass

    # 2. dmesg restriction
    dmesg_path = Path("/proc/sys/kernel/dmesg_restrict")
    if dmesg_path.exists():
        try:
            val = int(dmesg_path.read_text().strip())
            if val < 1:
                issues.append("Kernel logs exposed to non-root users (dmesg_restrict = 0)")
                score -= 4
        except Exception:
            pass

    # 3. Kernel pointer restriction
    kptr_path = Path("/proc/sys/kernel/kptr_restrict")
    if kptr_path.exists():
        try:
            val = int(kptr_path.read_text().strip())
            if val < 1:
                issues.append("Kernel addresses exposed in /proc/kallsyms (kptr_restrict = 0)")
                score -= 5
        except Exception:
            pass

    score = max(0, score)
    passed = len(issues) == 0

    if passed:
        desc = "Kernel memory & process isolation parameters are hardened (ptrace_scope, dmesg_restrict, kptr_restrict)."
        fix = None
    else:
        desc = "; ".join(issues)
        fix = "echo -e 'kernel.yama.ptrace_scope=1\\nkernel.dmesg_restrict=1\\nkernel.kptr_restrict=1' | sudo tee /etc/sysctl.d/99-security.conf && sudo sysctl --system"

    return {
        "id": "kernel_hardening",
        "category": "System Security",
        "title": "Kernel & Memory Protection",
        "passed": passed,
        "score": score,
        "max_score": 15,
        "severity": "high" if score < 10 else "medium",
        "description": desc,
        "recommendation": "Restrict process memory snooping (YAMA ptrace) and hide kernel pointers from unprivileged users." if not passed else None,
        "fix_cmd": fix
    }

# ----------------------------------------------------------------------
# 3. PRIVILEGES, SUDOERS & PATH INTEGRITY
# ----------------------------------------------------------------------
def audit_privileges_and_path():
    issues = []
    score = 15

    # Check PATH for insecure directories
    path_dirs = os.environ.get("PATH", "").split(":")
    for p in path_dirs:
        if p in ["", "."]:
            issues.append("Current directory (.) in PATH (binary hijacking risk)")
            score -= 8
            break
        else:
            p_obj = Path(p)
            try:
                if p_obj.exists() and (p_obj.stat().st_mode & 0o002):
                    issues.append(f"World-writable directory in PATH: {p}")
                    score -= 8
                    break
            except Exception:
                pass

    # Check for sudo NOPASSWD: ALL
    try:
        res = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=1.0)
        out = res.stdout
        if "NOPASSWD: ALL" in out or "(ALL : ALL) NOPASSWD: ALL" in out:
            issues.append("Passwordless root escalation enabled for all commands (NOPASSWD: ALL)")
            score -= 10
    except Exception:
        pass

    score = max(0, score)
    passed = len(issues) == 0

    if passed:
        desc = "System execution PATH is clean and passwordless root escalation is restricted."
    else:
        desc = "; ".join(issues)

    return {
        "id": "privileges_path",
        "category": "Authentication",
        "title": "Privilege Boundaries & PATH",
        "passed": passed,
        "score": score,
        "max_score": 15,
        "severity": "high" if score < 10 else "medium",
        "description": desc,
        "recommendation": "Remove unneeded NOPASSWD entries from sudoers and ensure PATH does not contain relative directories." if not passed else None,
        "fix_cmd": None
    }

# ----------------------------------------------------------------------
# 4. HOST FIREWALL & EXPOSURE
# ----------------------------------------------------------------------
def audit_firewall():
    is_active = False
    details = ""
    
    try:
        res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=1.5)
        if "Status: active" in res.stdout:
            is_active = True
            details = "UFW firewall is active."
    except Exception:
        pass

    if not is_active:
        for srv in ["nftables", "firewalld", "iptables"]:
            try:
                res = subprocess.run(["systemctl", "is-active", srv], capture_output=True, text=True, timeout=1.0)
                if res.stdout.strip() == "active":
                    is_active = True
                    details = f"{srv} service is active."
                    break
            except Exception:
                pass

    if is_active:
        return {
            "id": "firewall",
            "category": "Network",
            "title": "Host Firewall",
            "passed": True,
            "score": 15,
            "max_score": 15,
            "severity": "info",
            "description": details or "Firewall protection is active.",
            "recommendation": None,
            "fix_cmd": None
        }
    else:
        return {
            "id": "firewall",
            "category": "Network",
            "title": "Host Firewall",
            "passed": False,
            "score": 0,
            "max_score": 15,
            "severity": "high",
            "description": "No active host firewall detected (UFW/nftables/firewalld is inactive).",
            "recommendation": "Enable a host firewall (like UFW) to prevent unauthorized incoming network connections.",
            "fix_cmd": "sudo ufw enable && sudo ufw default deny incoming"
        }

# ----------------------------------------------------------------------
# 5. AUTHENTICATION & KEY PERMISSIONS
# ----------------------------------------------------------------------
def audit_ssh_and_gpg_permissions():
    issues = []
    score = 15

    ssh_dir = HOME / ".ssh"
    if ssh_dir.exists():
        if not check_file_mode(ssh_dir, 0o700):
            issues.append(f"~/.ssh is mode {get_mode_str(ssh_dir)} (expected 700)")
            score -= 5

        for item in ssh_dir.iterdir():
            if item.is_file():
                name = item.name
                if (name.startswith("id_") or name.endswith(".pem")) and not name.endswith(".pub"):
                    if not check_file_mode(item, 0o600):
                        issues.append(f"Private key {name} is mode {get_mode_str(item)} (expected 600)")
                        score -= 5

    gnupg_dir = HOME / ".gnupg"
    if gnupg_dir.exists():
        if not check_file_mode(gnupg_dir, 0o700):
            issues.append(f"~/.gnupg is mode {get_mode_str(gnupg_dir)} (expected 700)")
            score -= 5

    score = max(0, score)
    passed = len(issues) == 0

    if passed:
        desc = "~/.ssh keys and ~/.gnupg keyring directories have strict permissions (700/600)."
        fix = None
    else:
        desc = "; ".join(issues)
        fix = "chmod 700 ~/.ssh ~/.gnupg 2>/dev/null; chmod 600 ~/.ssh/id_* ~/.ssh/*.pem 2>/dev/null"

    return {
        "id": "ssh_gpg_perms",
        "category": "Authentication",
        "title": "SSH & GPG Key Permissions",
        "passed": passed,
        "score": score,
        "max_score": 15,
        "severity": "high" if score < 10 else "medium",
        "description": desc,
        "recommendation": "Restrict read permissions on SSH private keys and keyring folders so other users cannot access them." if not passed else None,
        "fix_cmd": fix
    }

# ----------------------------------------------------------------------
# 6. DESKTOP SESSION & LOCKSCREEN
# ----------------------------------------------------------------------
def audit_desktop_security():
    hypridle_conf = HOME / ".config" / "hypr" / "hypridle.conf"
    shell_json = HOME / ".config" / "omarchy" / "shell.json"
    
    has_lock = False
    lock_details = []

    if hypridle_conf.exists():
        try:
            content = hypridle_conf.read_text(errors="ignore")
            if "lock" in content.lower() or "hyprlock" in content.lower() or "timeout" in content.lower():
                has_lock = True
                lock_details.append("hypridle configured")
        except Exception:
            pass

    if shell_json.exists():
        try:
            data = json.loads(shell_json.read_text())
            idle_cfg = data.get("idle", {})
            if idle_cfg.get("lock", 0) > 0:
                has_lock = True
                lock_details.append(f"shell idle lock: {idle_cfg['lock']}s")
        except Exception:
            pass

    if has_lock:
        return {
            "id": "desktop_lock",
            "category": "Desktop Security",
            "title": "Screen Lock & Idle Protection",
            "passed": True,
            "score": 10,
            "max_score": 10,
            "severity": "info",
            "description": f"Automated screen locking is active ({', '.join(lock_details)}).",
            "recommendation": None,
            "fix_cmd": None
        }
    else:
        return {
            "id": "desktop_lock",
            "category": "Desktop Security",
            "title": "Screen Lock & Idle Protection",
            "passed": False,
            "score": 0,
            "max_score": 10,
            "severity": "medium",
            "description": "No automated screen lock timeout configured in hypridle or shell.json.",
            "recommendation": "Configure automatic session locking to secure your desktop when away from your PC.",
            "fix_cmd": None
        }

# ----------------------------------------------------------------------
# 7. NETWORK PORTS & SSHD HARDENING
# ----------------------------------------------------------------------
def audit_network_ports_and_sshd():
    issues = []
    score = 5

    # Check listening ports
    public_listeners = []
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=1.0)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                state = parts[0]
                local_addr = parts[4]
                if "LISTEN" in state or state == "UNCONN":
                    if local_addr.startswith("0.0.0.0:") or local_addr.startswith("[::]:") or local_addr.startswith("*:") or local_addr.startswith(":::"):
                        port = local_addr.rsplit(":", 1)[-1]
                        if port not in public_listeners:
                            public_listeners.append(port)
    except Exception:
        pass

    if len(public_listeners) > 6:
        issues.append(f"Multiple services bound to public interfaces ({', '.join(public_listeners[:6])}...)")
        score -= 2

    # Check SSH server root login
    sshd_conf = Path("/etc/ssh/sshd_config")
    if sshd_conf.exists():
        try:
            content = sshd_conf.read_text(errors="ignore")
            root_login_match = re.search(r"^\s*PermitRootLogin\s+(yes|prohibit-password|without-password|no)", content, re.MULTILINE | re.IGNORECASE)
            if root_login_match and root_login_match.group(1).lower() == "yes":
                issues.append("SSH server allows direct root login (PermitRootLogin yes)")
                score -= 3
        except Exception:
            pass

    score = max(0, score)
    passed = len(issues) == 0

    if passed:
        desc = f"Network ports are minimal ({len(public_listeners)} public: {', '.join(public_listeners) if public_listeners else 'none'}) and SSH daemon is secure."
    else:
        desc = "; ".join(issues)

    return {
        "id": "network_ports",
        "category": "Network",
        "title": "Public Ports & SSH Hardening",
        "passed": passed,
        "score": score,
        "max_score": 5,
        "severity": "medium" if not passed else "info",
        "description": desc,
        "recommendation": "Bind unneeded local services to 127.0.0.1 and disable SSH root password authentication." if not passed else None,
        "fix_cmd": None
    }

# ----------------------------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------------------------
def main():
    import datetime

    audits = [
        audit_plugins_deep(),
        audit_firewall(),
        audit_kernel_hardening(),
        audit_privileges_and_path(),
        audit_ssh_and_gpg_permissions(),
        audit_desktop_security(),
        audit_network_ports_and_sshd()
    ]

    total_score = sum(a["score"] for a in audits)
    max_possible = sum(a["max_score"] for a in audits)
    
    pct = int((total_score / max_possible) * 100) if max_possible > 0 else 100

    if pct >= 90:
        grade = "A"
        status_label = "System Hardened"
        status_color = "good"
    elif pct >= 75:
        grade = "B"
        status_label = "Good Security"
        status_color = "normal"
    elif pct >= 60:
        grade = "C"
        status_label = "Warnings Detected"
        status_color = "warning"
    else:
        grade = "F"
        status_label = "Critical Action Required"
        status_color = "urgent"

    failed_count = sum(1 for a in audits if not a["passed"])

    output = {
        "score": pct,
        "grade": grade,
        "statusLabel": status_label,
        "statusColor": status_color,
        "failedCount": failed_count,
        "totalChecks": len(audits),
        "audits": audits,
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
    }

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
