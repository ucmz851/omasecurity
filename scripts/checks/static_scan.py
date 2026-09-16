"""Static plugin/source tree scanner. Other checks can reuse DEFAULT_RULES or scan_tree."""

from __future__ import annotations

import os
import re
from pathlib import Path

SECRET_RULE_IDS = frozenset({"private_key", "api_secret"})
DEFAULT_SKIP_DIRS = (".git", "node_modules", "test", "tests")

DEFAULT_RULES = [
    {
        "id": "pipe_to_shell",
        "severity": "CRITICAL",
        "regex": re.compile(r"(curl|wget)\s+[^|\r\n]+?\|\s*(ba)?sh", re.IGNORECASE),
        "title": "Pipes remote download directly to shell execution",
        "explanation": "Executes unverified remote web content directly in bash.",
    },
    {
        "id": "obfuscated_exec",
        "severity": "CRITICAL",
        "regex": re.compile(
            r"(eval\s*\(|new\s+Function\s*\(|base64\s+-d\s*\|\s*(ba)?sh|exec\s*\(\s*bytes\.fromhex)",
            re.IGNORECASE,
        ),
        "title": "Dynamic / Obfuscated Code Execution",
        "explanation": "Executes dynamically compiled or encoded strings in memory.",
    },
    {
        "id": "private_key",
        "severity": "CRITICAL",
        "regex": re.compile(r"-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----"),
        "title": "Hardcoded Private Key",
        "explanation": "Unencrypted private cryptographic key found inside source.",
    },
    {
        "id": "api_secret",
        "severity": "HIGH",
        "regex": re.compile(r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|AKIA[0-9A-Z]{16})"),
        "title": "Hardcoded Cloud/API Token",
        "explanation": "Live cloud access token or GitHub PAT found in plaintext.",
    },
    {
        "id": "sensitive_credential_access",
        "severity": "HIGH",
        "regex": re.compile(
            r"(\.ssh/id_|\.gnupg/|\.local/share/keyrings|/etc/shadow|\.config/google-chrome)",
            re.IGNORECASE,
        ),
        "title": "Accesses Protected Credentials Path",
        "explanation": "Accesses private SSH keys, GPG rings, or browser authentication databases.",
    },
    {
        "id": "silent_sudo",
        "severity": "MEDIUM",
        "regex": re.compile(r"^\s*(sudo\s+|pkexec\s+|doas\s+)", re.MULTILINE | re.IGNORECASE),
        "title": "Privilege Escalation (sudo/pkexec)",
        "explanation": "Plugin executes commands with root privileges.",
    },
]


def sanitize_snippet(text, max_len=80):
    clean = "".join(c if c.isprintable() else " " for c in text).strip()
    return clean[:max_len]


def _is_comment(line):
    sline = line.strip()
    return (
        sline.startswith("//")
        or sline.startswith("#")
        or sline.startswith("*")
        or sline.startswith("/*")
    )


def scan_tree(
    root,
    exts,
    rules,
    max_files,
    max_bytes,
    follow_symlinks=False,
    skip_dirs=DEFAULT_SKIP_DIRS,
):
    """Walk root and return (flagged_items, files_scanned). Never follows symlinks by default."""
    root = Path(root)
    flagged = []
    files_scanned = 0
    skip = set(skip_dirs)
    ext_set = {e.lower() if str(e).startswith(".") else "." + str(e).lower() for e in exts}

    if not root.exists() or max_files <= 0:
        return flagged, files_scanned

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        kept = []
        for name in dirnames:
            if name in skip or name.startswith("."):
                continue
            child = Path(dirpath) / name
            if not follow_symlinks and child.is_symlink():
                continue
            kept.append(name)
        dirnames[:] = kept

        for filename in filenames:
            if files_scanned >= max_files:
                return flagged, files_scanned
            ext = Path(filename).suffix.lower()
            if ext not in ext_set:
                continue
            filepath = Path(dirpath) / filename
            if not follow_symlinks and filepath.is_symlink():
                continue
            try:
                size = filepath.stat().st_size
            except OSError:
                continue
            if size > max_bytes:
                continue
            files_scanned += 1
            try:
                lines = filepath.read_text(errors="ignore").splitlines()
            except Exception:
                continue
            rel = str(filepath.relative_to(root))
            for line_no, line in enumerate(lines, 1):
                if _is_comment(line):
                    continue
                for rule in rules:
                    if rule["regex"].search(line):
                        snippet = (
                            "[redacted]"
                            if rule.get("id") in SECRET_RULE_IDS
                            else sanitize_snippet(line.strip(), 80)
                        )
                        flagged.append({
                            "file": rel,
                            "line": line_no,
                            "severity": rule["severity"],
                            "title": rule["title"],
                            "explanation": rule["explanation"],
                            "snippet": snippet,
                            "rule_id": rule.get("id"),
                        })
                        break
    return flagged, files_scanned
