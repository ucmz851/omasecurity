#!/usr/bin/env python3
"""
OmaSecurity Audit Engine
Performs fast, non-blocking local security & code health checks for Omarchy Quattro shell.
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

def audit_ssh_permissions():
    ssh_dir = HOME / ".ssh"
    if not ssh_dir.exists():
        return {
            "id": "ssh_perms",
            "category": "Authentication",
            "title": "SSH Directory & Keys",
            "passed": True,
            "score": 15,
            "max_score": 15,
            "description": "No ~/.ssh directory found (nothing exposed).",
            "recommendation": None,
            "fix_cmd": None
        }

    issues = []
    if not check_file_mode(ssh_dir, 0o700):
        issues.append(f"~/.ssh has permission {get_mode_str(ssh_dir)} (recommended: 700)")

    for item in ssh_dir.iterdir():
        if item.is_file():
            name = item.name
            if name.startswith("id_") and not name.endswith(".pub"):
                if not check_file_mode(item, 0o600):
                    issues.append(f"Private key {name} is {get_mode_str(item)} (recommended: 600)")

    if issues:
        return {
            "id": "ssh_perms",
            "category": "Authentication",
            "title": "SSH Key Permissions",
            "passed": False,
            "score": 5,
            "max_score": 15,
            "description": "; ".join(issues),
            "recommendation": "Restrict permissions on ~/.ssh and private keys so other users cannot read them.",
            "fix_cmd": "chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* 2>/dev/null"
        }
    
    return {
        "id": "ssh_perms",
        "category": "Authentication",
        "title": "SSH Directory & Keys",
        "passed": True,
        "score": 15,
        "max_score": 15,
        "description": "~/.ssh directory and private keys have strict permissions (700/600).",
        "recommendation": None,
        "fix_cmd": None
    }

def audit_gnupg_permissions():
    gnupg_dir = HOME / ".gnupg"
    if not gnupg_dir.exists():
        return {
            "id": "gnupg_perms",
            "category": "Authentication",
            "title": "GnuPG Directory Permissions",
            "passed": True,
            "score": 10,
            "max_score": 10,
            "description": "No ~/.gnupg directory found.",
            "recommendation": None,
            "fix_cmd": None
        }

    if not check_file_mode(gnupg_dir, 0o700):
        return {
            "id": "gnupg_perms",
            "category": "Authentication",
            "title": "GnuPG Directory Permissions",
            "passed": False,
            "score": 0,
            "max_score": 10,
            "description": f"~/.gnupg directory has permissive mode {get_mode_str(gnupg_dir)} (expected 700).",
            "recommendation": "Restrict ~/.gnupg permissions to prevent unauthorized key access.",
            "fix_cmd": "chmod 700 ~/.gnupg && chmod 600 ~/.gnupg/* 2>/dev/null"
        }

    return {
        "id": "gnupg_perms",
        "category": "Authentication",
        "title": "GnuPG Directory Permissions",
        "passed": True,
        "score": 10,
        "max_score": 10,
        "description": "~/.gnupg directory is properly restricted (700).",
        "recommendation": None,
        "fix_cmd": None
    }

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
            "score": 20,
            "max_score": 20,
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
            "max_score": 20,
            "description": "No active firewall detected (UFW/nftables/firewalld is inactive).",
            "recommendation": "Enable a host firewall (like UFW) to protect local listening ports.",
            "fix_cmd": "sudo ufw enable"
        }

def audit_idle_lock():
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
                lock_details.append(f"shell lock: {idle_cfg['lock']}s")
        except Exception:
            pass

    if has_lock:
        return {
            "id": "idle_lock",
            "category": "Desktop Security",
            "title": "Screen Lock & Idle",
            "passed": True,
            "score": 15,
            "max_score": 15,
            "description": f"Automated screen locking is configured ({', '.join(lock_details)}).",
            "recommendation": None,
            "fix_cmd": None
        }
    else:
        return {
            "id": "idle_lock",
            "category": "Desktop Security",
            "title": "Screen Lock & Idle",
            "passed": False,
            "score": 0,
            "max_score": 15,
            "description": "No automated screen lock timeout configured.",
            "recommendation": "Configure idle timeout and lock command in ~/.config/omarchy/shell.json.",
            "fix_cmd": None
        }

def audit_sshd():
    sshd_conf = Path("/etc/ssh/sshd_config")
    if not sshd_conf.exists():
        return {
            "id": "sshd_config",
            "category": "Network",
            "title": "SSH Server Hardening",
            "passed": True,
            "score": 10,
            "max_score": 10,
            "description": "SSH server is not configured or disabled.",
            "recommendation": None,
            "fix_cmd": None
        }

    try:
        content = sshd_conf.read_text(errors="ignore")
        root_login_match = re.search(r"^\s*PermitRootLogin\s+(yes|prohibit-password|without-password|no)", content, re.MULTILINE | re.IGNORECASE)
        if root_login_match and root_login_match.group(1).lower() == "yes":
            return {
                "id": "sshd_config",
                "category": "Network",
                "title": "SSH Server Hardening",
                "passed": False,
                "score": 2,
                "max_score": 10,
                "description": "PermitRootLogin is set to 'yes' in /etc/ssh/sshd_config.",
                "recommendation": "Disable root SSH login by setting 'PermitRootLogin no' in sshd_config.",
                "fix_cmd": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
            }
    except Exception:
        pass

    return {
        "id": "sshd_config",
        "category": "Network",
        "title": "SSH Server Hardening",
        "passed": True,
        "score": 10,
        "max_score": 10,
        "description": "SSH server configuration does not permit direct root password login.",
        "recommendation": None,
        "fix_cmd": None
    }

def audit_listening_ports():
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
        return {
            "id": "listening_ports",
            "category": "Network",
            "title": "Public Listening Ports",
            "passed": False,
            "score": 5,
            "max_score": 10,
            "description": f"Multiple services listening on 0.0.0.0 (ports: {', '.join(public_listeners[:6])}...).",
            "recommendation": "Ensure unneeded network daemons are bound to localhost (127.0.0.1) or firewalled.",
            "fix_cmd": None
        }

    return {
        "id": "listening_ports",
        "category": "Network",
        "title": "Public Listening Ports",
        "passed": True,
        "score": 10,
        "max_score": 10,
        "description": f"Minimal exposed listeners ({len(public_listeners)} public ports: {', '.join(public_listeners) if public_listeners else 'none'}).",
        "recommendation": None,
        "fix_cmd": None
    }

def audit_plugins_code_health():
    plugins_dir = HOME / ".config" / "omarchy" / "plugins"
    if not plugins_dir.exists():
        return {
            "id": "plugins_health",
            "category": "Plugin Health",
            "title": "Omarchy Shell Plugins",
            "passed": True,
            "score": 20,
            "max_score": 20,
            "description": "No user shell plugins installed.",
            "recommendation": None,
            "fix_cmd": None,
            "scanned_count": 0,
            "flagged_items": []
        }

    flagged = []
    scanned_count = 0

    patterns = [
        (re.compile(r"curl\s+[^\|]+\|\s*(ba)?sh", re.IGNORECASE), "Pipe curl to shell execution"),
        (re.compile(r"wget\s+[^\|]+\|\s*(ba)?sh", re.IGNORECASE), "Pipe wget to shell execution"),
        (re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"), "Hardcoded private key detected"),
        (re.compile(r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})"), "Hardcoded GitHub Personal Access Token"),
        (re.compile(r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9_\-]{24,}['\"]", re.IGNORECASE), "Suspicious hardcoded API key")
    ]

    for plugin in plugins_dir.iterdir():
        if not plugin.is_dir() or plugin.name.startswith(".") or plugin.name in ["omasecurity", "local.omasecurity", "ucmz851.omasecurity"]:
            continue
        scanned_count += 1

        for root, dirs, files in os.walk(plugin):
            if ".git" in dirs:
                dirs.remove(".git")
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in [".qml", ".js", ".sh", ".py", ".json"]:
                    filepath = Path(root) / file
                    try:
                        text = filepath.read_text(errors="ignore")
                        for pat, reason in patterns:
                            m = pat.search(text)
                            if m:
                                rel = filepath.relative_to(plugins_dir)
                                flagged.append({
                                    "plugin": plugin.name,
                                    "file": str(rel),
                                    "reason": reason
                                })
                                break
                    except Exception:
                        pass

    if flagged:
        return {
            "id": "plugins_health",
            "category": "Plugin Health",
            "title": "Omarchy Shell Plugins",
            "passed": False,
            "score": max(5, 20 - (len(flagged) * 5)),
            "max_score": 20,
            "description": f"Scanned {scanned_count} plugins: {len(flagged)} potential security risk(s) flagged.",
            "recommendation": "Review flagged plugin files for unescaped shell commands or hardcoded credentials.",
            "fix_cmd": None,
            "scanned_count": scanned_count,
            "flagged_items": flagged
        }

    return {
        "id": "plugins_health",
        "category": "Plugin Health",
        "title": "Omarchy Shell Plugins",
        "passed": True,
        "score": 20,
        "max_score": 20,
        "description": f"All {scanned_count} installed shell plugins passed code health & security checks.",
        "recommendation": None,
        "fix_cmd": None,
        "scanned_count": scanned_count,
        "flagged_items": []
    }

def main():
    import datetime
    audits = [
        audit_firewall(),
        audit_plugins_code_health(),
        audit_ssh_permissions(),
        audit_idle_lock(),
        audit_sshd(),
        audit_listening_ports(),
        audit_gnupg_permissions()
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
        status_label = "Action Required"
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
