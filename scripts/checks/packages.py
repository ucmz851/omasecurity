"""Package supply-chain checks (category: Packages).

Never runs pacman -Sy, yay, or any command that writes. Never calls sudo.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import FAST_CHECKS, SLOW_CHECKS, make_result, register_check, run_cmd

CATEGORY = "Packages"
PACMAN_CONF = Path("/etc/pacman.conf")
PACMAN_D = Path("/etc/pacman.d")
PACMAN_LOG = Path("/var/log/pacman.log")
LOG_TAIL_BYTES = 65536
OMARCHY_KEY_ID = "40DFB630FF42BCFFB047046CF0134EE680CAC571"
DEFAULT_SIGLEVEL = "Required DatabaseOptional"
SHIPPED_DEFAULT = "/usr/share/omarchy/default/pacman/pacman-stable.conf"
GPG_HOMEDIR = "/etc/pacman.d/gnupg"
FOREIGN_WARN_THRESHOLD = 25
HIGH_DEDUCT = 5
MEDIUM_DEDUCT = 3
KEY_LIST_TIMEOUT_S = 0.15
GPG_LIST_TIMEOUT_S = 0.3
ARCH_AUDIT_TIMEOUT_S = 20.0

REFS_SIGNING = [
    "https://man.archlinux.org/man/pacman.conf.5#PACKAGE_AND_DATABASE_SIGNATURE_CHECKING",
    "https://wiki.archlinux.org/title/Pacman/Package_signing",
]
REFS_UPDATES = [
    "https://wiki.archlinux.org/title/System_maintenance#Upgrading_the_system",
]
REFS_AUDIT = [
    "https://wiki.archlinux.org/title/Arch_Security_Team",
    "https://wiki.archlinux.org/title/Pacman/Package_signing",
]

_SECTION_RE = re.compile(r"^\[([^\]]+)\]\s*$")
_UPGRADE_RE = re.compile(
    r"starting full system upgrade",
    re.IGNORECASE,
)
_LOG_TS_ISO = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)\]"
)
_LOG_TS_SPACE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)\]"
)
_NETWORK_HINTS = (
    "could not resolve",
    "name resolution",
    "temporary failure",
    "network is unreachable",
    "connection refused",
    "connection reset",
    "connection timed out",
    "timed out",
    "timeout",
    "failed to fetch",
    "failed to download",
    "unable to connect",
    "error sending",
    "tls handshake",
    "ssl certificate",
    "no route to host",
)


def _strip_comment(line):
    return line.split("#", 1)[0].strip()


def _tokens(siglevel):
    if not siglevel:
        return []
    return [tok for tok in siglevel.split() if tok]


def _package_sig_level(tokens):
    if "Never" in tokens:
        return "Never"
    if "Optional" in tokens:
        return "Optional"
    if "Required" in tokens:
        return "Required"
    return "Required"


def _options_weaker_than_default(siglevel):
    """True when [options] SigLevel is weaker than Required DatabaseOptional."""
    tokens = _tokens(siglevel)
    if not tokens:
        return False
    pkg = _package_sig_level(tokens)
    if pkg in ("Optional", "Never"):
        return True
    if "TrustAll" in tokens:
        return True
    if "DatabaseNever" in tokens:
        return True
    return False


def _weak_network_kind(tokens):
    """Return 'high', 'medium', or None for a network repo's SigLevel tokens."""
    if "Never" in tokens or "TrustAll" in tokens:
        return "high"
    if "Optional" in tokens:
        return "medium"
    return None


def _is_file_server(server):
    return server.strip().lower().startswith("file://")


def _under_root(path, root):
    try:
        resolved = Path(path).resolve()
        base = Path(root).resolve()
    except OSError:
        return False
    return resolved == base or base in resolved.parents


def _read_include_file(path):
    try:
        return Path(path).read_text(errors="ignore")
    except OSError:
        return ""


def _parse_kv_lines(text, into):
    """Parse SigLevel / Server / Include lines into a section dict."""
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line or "=" not in line or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        lowered = key.lower()
        if lowered == "siglevel":
            into["siglevel"] = value
            into["siglevel_from_include"] = True
        elif lowered == "server":
            into.setdefault("servers", []).append(value)
        elif lowered == "include":
            into.setdefault("includes", []).append(value)


def parse_pacman_conf(conf_path, include_root=None):
    """Parse pacman.conf repo sections and effective SigLevel values.

    Include files are followed only when their path is under include_root
    (default /etc/pacman.d), and only to collect SigLevel / Server lines.
    """
    conf_path = Path(conf_path)
    include_root = Path(include_root) if include_root else PACMAN_D
    try:
        text = conf_path.read_text(errors="ignore")
    except OSError:
        return None

    options_siglevel = None
    current = None
    sections = []

    def finish(section):
        if section is None:
            return
        if section["name"].lower() == "options":
            return
        sections.append(section)

    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        match = _SECTION_RE.match(line)
        if match:
            finish(current)
            name = match.group(1).strip()
            current = {
                "name": name,
                "siglevel": None,
                "siglevel_from_include": False,
                "servers": [],
                "includes": [],
            }
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if current is None:
            continue
        lowered = key.lower()
        if current["name"].lower() == "options":
            if lowered == "siglevel":
                options_siglevel = value
            continue
        if lowered == "siglevel":
            current["siglevel"] = value
            current["siglevel_from_include"] = False
        elif lowered == "server":
            current["servers"].append(value)
        elif lowered == "include":
            current["includes"].append(value)

    finish(current)

    repos = []
    for section in sections:
        include_siglevel_path = None
        for include_path in section["includes"]:
            if not _under_root(include_path, include_root):
                continue
            extra = {"siglevel": None, "siglevel_from_include": False, "servers": [], "includes": []}
            _parse_kv_lines(_read_include_file(include_path), extra)
            section["servers"].extend(extra.get("servers") or [])
            if extra.get("siglevel") and section["siglevel"] is None:
                section["siglevel"] = extra["siglevel"]
                section["siglevel_from_include"] = True
                include_siglevel_path = include_path

        if section["siglevel"]:
            effective = section["siglevel"]
            if section["siglevel_from_include"] and include_siglevel_path:
                source = "include " + include_siglevel_path
            else:
                source = "repo override"
        else:
            effective = options_siglevel or DEFAULT_SIGLEVEL
            source = "[options]" if options_siglevel else "pacman default"

        servers = section["servers"]
        if servers:
            network = any(not _is_file_server(s) for s in servers)
        else:
            # Mirrorlist Include with no readable Server lines: treat as network.
            network = True

        recorded = section["servers"][0] if section["servers"] else None
        if recorded is None and section["includes"]:
            recorded = "Include " + section["includes"][0]

        repos.append({
            "name": section["name"],
            "siglevel": effective,
            "source": source,
            "servers": servers,
            "includes": list(section["includes"]),
            "recorded": recorded,
            "network": network,
        })

    return {
        "options_siglevel": options_siglevel,
        "repos": repos,
    }


def _conf_or_na(conf_path, include_root, check_id, title, max_score, lane="fast"):
    parsed = parse_pacman_conf(conf_path, include_root=include_root)
    if parsed is None:
        return None, make_result(
            id=check_id,
            category=CATEGORY,
            title=title,
            passed=False,
            applicable=False,
            score=0,
            max_score=max_score,
            lane=lane,
            description="pacman.conf is not present; package checks do not apply.",
            details=["Missing " + str(conf_path)],
            refs=REFS_SIGNING,
        )
    return parsed, None


def _has_omarchy_repo(parsed):
    return any(repo["name"].lower() == "omarchy" for repo in parsed["repos"])


def _severity_for_deduction(high, medium, low=0):
    if high:
        return "high"
    if medium:
        return "medium"
    if low:
        return "low"
    return "info"


def _read_log_tail(path, nbytes=LOG_TAIL_BYTES):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - nbytes), os.SEEK_SET)
            return handle.read().decode("utf-8", "ignore")
    except OSError:
        return None


def _parse_log_timestamp(line):
    match = _LOG_TS_ISO.match(line)
    if match:
        raw = match.group(1)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        elif re.search(r"[+-]\d{4}$", raw):
            raw = raw[:-2] + ":" + raw[-2:]
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    match = _LOG_TS_SPACE.match(line)
    if match:
        raw = match.group(1)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _newest_upgrade(text):
    newest = None
    newest_line = None
    for line in text.splitlines():
        if not _UPGRADE_RE.search(line):
            continue
        ts = _parse_log_timestamp(line)
        if ts is None:
            continue
        if newest is None or ts > newest:
            newest = ts
            newest_line = line.strip()
    return newest, newest_line


def _pacman_query_versions(run, names):
    res = run(["pacman", "-Q", *names], timeout=1.0)
    versions = {}
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].lower().startswith("error"):
            versions[parts[0]] = parts[1]
    missing = [name for name in names if name not in versions]
    return versions, missing, res


def _lookup_omarchy_key(run):
    """Return (status, source) where status is present|missing|unknown."""
    res = run(["pacman-key", "--list-keys", OMARCHY_KEY_ID], timeout=KEY_LIST_TIMEOUT_S)
    if res.returncode == 0:
        return "present", "pacman-key"
    if res.returncode not in (124, 127):
        return "missing", "pacman-key"
    res = run(
        ["gpg", "--homedir", GPG_HOMEDIR, "--list-keys", OMARCHY_KEY_ID],
        timeout=GPG_LIST_TIMEOUT_S,
    )
    if res.returncode == 0:
        return "present", "gpg"
    if res.returncode not in (124, 127):
        return "missing", "gpg"
    return "unknown", None


def _installed_arch_audit_flag(help_text):
    if re.search(r"--json\b", help_text):
        return ["arch-audit", "--json"], True
    if re.search(r"--format\b", help_text) or re.search(r"(?m)^\s*-f\b", help_text):
        if "--format" in help_text:
            return ["arch-audit", "--format", "%n: %c %s"], False
        return ["arch-audit", "-f", "%n: %c %s"], False
    return ["arch-audit"], False


def _looks_like_network_error(res):
    blob = ((res.stderr or "") + "\n" + (res.stdout or "")).lower()
    if res.returncode == 124:
        return True
    return any(hint in blob for hint in _NETWORK_HINTS)


def _norm_severity(value):
    token = str(value or "").strip().lower()
    if token in ("critical", "crit"):
        return "Critical"
    if token in ("high", "important"):
        return "High"
    if token in ("medium", "med", "moderate"):
        return "Medium"
    if token in ("low",):
        return "Low"
    if token:
        return str(value).strip()
    return "Unknown"


def _parse_arch_audit_json(stdout):
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        for key in ("packages", "vulnerabilities", "advisories", "data", "issues"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            return []
    if not isinstance(data, list):
        return None
    entries = []
    for item in data:
        if not isinstance(item, dict):
            continue
        pkg = item.get("package") or item.get("name") or item.get("pkgname") or ""
        cve = item.get("cve") or item.get("cves") or item.get("advisory") or ""
        if isinstance(cve, list):
            cve = ", ".join(str(part) for part in cve)
        sev = _norm_severity(item.get("severity") or item.get("status") or "")
        if pkg or cve:
            entries.append((str(pkg), str(cve), sev))
    return entries


def _parse_arch_audit_text(stdout):
    entries = []
    machine = re.compile(
        r"^(\S+):\s+(\S+)\s+(Critical|High|Medium|Low)\s*$",
        re.IGNORECASE,
    )
    prose = re.compile(
        r"^(\S+)\s+is affected by\s+(CVE-\S+).*?\b(Critical|High|Medium|Low)",
        re.IGNORECASE,
    )
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        match = machine.match(text) or prose.match(text)
        if not match:
            continue
        entries.append((match.group(1), match.group(2).rstrip("."), _norm_severity(match.group(3))))
    return entries


@register_check(
    FAST_CHECKS,
    check_id="pacman_trust",
    category=CATEGORY,
    title="Pacman repository trust",
    max_score=10,
)
def check_pacman_trust(*, conf_path=None, include_root=None):
    conf_path = Path(conf_path) if conf_path else PACMAN_CONF
    parsed, na = _conf_or_na(
        conf_path, include_root, "pacman_trust", "Pacman repository trust", 10
    )
    if na:
        return na

    details = []
    high = 0
    medium = 0
    flagged_sections = []
    options_siglevel = parsed["options_siglevel"]
    if options_siglevel:
        details.append("options: " + options_siglevel + " ([options])")
        if _options_weaker_than_default(options_siglevel):
            medium += 1
            flagged_sections.append("[options]")
    else:
        details.append("options: " + DEFAULT_SIGLEVEL + " (pacman default)")

    for repo in parsed["repos"]:
        details.append(repo["name"] + ": " + repo["siglevel"] + " (" + repo["source"] + ")")
        if not repo["network"]:
            continue
        kind = _weak_network_kind(_tokens(repo["siglevel"]))
        if kind == "high":
            high += 1
            flagged_sections.append(repo["name"])
        elif kind == "medium":
            medium += 1
            flagged_sections.append(repo["name"])

    score = max(0, 10 - HIGH_DEDUCT * high - MEDIUM_DEDUCT * medium)
    passed = high == 0 and medium == 0
    if passed:
        desc = "All configured pacman repositories use Required signatures (DatabaseOptional)."
        rec = None
    else:
        names = ", ".join(flagged_sections) if flagged_sections else "named sections"
        desc = (
            "Weak SigLevel on network pacman repositories: "
            + names
            + "."
        )
        rec = (
            "In the "
            + names
            + " section(s) of /etc/pacman.conf, set "
            "`SigLevel = Required DatabaseOptional`. See the shipped Omarchy "
            "default at "
            + SHIPPED_DEFAULT
            + "."
        )
    return make_result(
        id="pacman_trust",
        category=CATEGORY,
        title="Pacman repository trust",
        passed=passed,
        score=score,
        max_score=10,
        severity=_severity_for_deduction(high, medium),
        description=desc,
        details=details,
        recommendation=rec,
        fix_cmd=None,
        refs=REFS_SIGNING,
    )


@register_check(
    FAST_CHECKS,
    check_id="pacman_keyring",
    category=CATEGORY,
    title="Pacman keyrings",
    max_score=5,
)
def check_pacman_keyring(*, conf_path=None, include_root=None, run=None):
    conf_path = Path(conf_path) if conf_path else PACMAN_CONF
    run = run or run_cmd
    parsed = parse_pacman_conf(conf_path, include_root=include_root)
    omarchy_repo = _has_omarchy_repo(parsed) if parsed else False

    names = ["archlinux-keyring", "omarchy-keyring"]
    versions, missing, query = _pacman_query_versions(run, names)
    if query.returncode == 127:
        return make_result(
            id="pacman_keyring",
            category=CATEGORY,
            title="Pacman keyrings",
            passed=False,
            applicable=False,
            score=0,
            max_score=5,
            description="pacman is not installed; keyring checks do not apply.",
            details=["pacman -Q returned command-not-found."],
            refs=REFS_SIGNING,
        )

    arm_versions, _, arm_query = _pacman_query_versions(run, ["archlinuxarm-keyring"])
    if arm_query.returncode != 127 and "archlinuxarm-keyring" in arm_versions:
        versions["archlinuxarm-keyring"] = arm_versions["archlinuxarm-keyring"]

    details = []
    for name in ("archlinux-keyring", "omarchy-keyring", "archlinuxarm-keyring"):
        if name in versions:
            details.append(name + " " + versions[name])
        elif name in names or name in arm_versions:
            details.append(name + " missing")
        elif name == "omarchy-keyring":
            details.append(name + " missing")

    key_status, key_source = _lookup_omarchy_key(run)
    if key_status == "present":
        details.append("Omarchy key " + OMARCHY_KEY_ID + " present (" + key_source + ")")
    elif key_status == "missing":
        details.append("Omarchy key " + OMARCHY_KEY_ID + " missing (" + key_source + ")")
    else:
        details.append(
            "Omarchy key status unknown. Run: pacman-key --list-keys " + OMARCHY_KEY_ID
        )

    high = 0
    if omarchy_repo and "omarchy-keyring" in missing:
        high += 1
    if omarchy_repo and key_status == "missing":
        high += 1

    score = max(0, 5 - HIGH_DEDUCT * high)
    passed = high == 0
    if parsed is None:
        details.append("pacman.conf not present; Omarchy repo not confirmed.")
    if passed:
        desc = "Required pacman keyring packages and the Omarchy signing key are present."
        rec = None
    else:
        parts = []
        if "omarchy-keyring" in missing:
            parts.append("omarchy-keyring is not installed")
        if key_status == "missing":
            parts.append("Omarchy signing key is not in the pacman keyring")
        desc = (
            "Omarchy [omarchy] repository is configured but "
            + (" and ".join(parts) if parts else "keyring trust is incomplete")
            + "."
        )
        rec = "Install omarchy-keyring and import the Omarchy key via /usr/share/omarchy/bin/omarchy-update-keyring."
    return make_result(
        id="pacman_keyring",
        category=CATEGORY,
        title="Pacman keyrings",
        passed=passed,
        score=score,
        max_score=5,
        severity=_severity_for_deduction(high, 0),
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS_SIGNING,
    )


@register_check(
    FAST_CHECKS,
    check_id="pacman_updates",
    category=CATEGORY,
    title="System update recency",
    max_score=5,
)
def check_pacman_updates(*, log_path=None, now=None):
    log_path = Path(log_path) if log_path else PACMAN_LOG
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    text = _read_log_tail(log_path)
    if text is None:
        return make_result(
            id="pacman_updates",
            category=CATEGORY,
            title="System update recency",
            passed=False,
            applicable=False,
            score=0,
            max_score=5,
            description="pacman.log is not present; update recency does not apply.",
            details=["Missing or unreadable " + str(log_path)],
            refs=REFS_UPDATES,
        )

    newest, newest_line = _newest_upgrade(text)
    if newest is None:
        return make_result(
            id="pacman_updates",
            category=CATEGORY,
            title="System update recency",
            passed=True,
            score=5,
            max_score=5,
            description="Last full system upgrade is unknown; no upgrade line in pacman.log.",
            details=["No 'starting full system upgrade' line in the last 64KB of " + str(log_path)],
            recommendation="run `omarchy update`",
            refs=REFS_UPDATES,
        )

    delta = now - newest.astimezone(now.tzinfo)
    days = delta.total_seconds() / 86400.0
    days_i = int(days)
    details = [
        "Last full system upgrade: " + newest.date().isoformat() + " (" + str(days_i) + " days ago)",
    ]
    if newest_line:
        details.append("log: " + newest_line[:120])

    high = 0
    medium = 0
    if days > 30:
        high = 1
        desc = "Last full system upgrade was more than 30 days ago (" + str(days_i) + " days)."
        severity = "high"
    elif days > 14:
        medium = 1
        desc = "Last full system upgrade was more than 14 days ago (" + str(days_i) + " days)."
        severity = "medium"
    else:
        desc = "A full system upgrade ran " + str(days_i) + " days ago."
        severity = "info"

    score = max(0, 5 - HIGH_DEDUCT * high - MEDIUM_DEDUCT * medium)
    passed = high == 0 and medium == 0
    rec = None if passed else "run `omarchy update`"
    return make_result(
        id="pacman_updates",
        category=CATEGORY,
        title="System update recency",
        passed=passed,
        score=score,
        max_score=5,
        severity=severity,
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS_UPDATES,
    )


def _sl_installed_counts(run):
    """One `pacman -Sl` (all repos); group installed counts by the first column."""
    res = run(["pacman", "-Sl"], timeout=1.5)
    if res.returncode == 127:
        return None, res
    counts = {}
    if res.returncode == 0:
        for line in (res.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            repo = parts[0]
            counts.setdefault(repo, 0)
            if "[installed]" in line:
                counts[repo] += 1
    return counts, res


@register_check(
    SLOW_CHECKS,
    check_id="pacman_inventory",
    category=CATEGORY,
    title="Package inventory",
    max_score=5,
    lane="slow",
)
def check_pacman_inventory(*, conf_path=None, include_root=None, run=None):
    conf_path = Path(conf_path) if conf_path else PACMAN_CONF
    run = run or run_cmd
    parsed = parse_pacman_conf(conf_path, include_root=include_root)

    installed_res = run(["pacman", "-Qq"], timeout=1.5)
    if installed_res.returncode == 127:
        return make_result(
            id="pacman_inventory",
            category=CATEGORY,
            title="Package inventory",
            passed=False,
            applicable=False,
            score=0,
            max_score=5,
            lane="slow",
            description="pacman is not installed; package inventory does not apply.",
            details=["pacman -Qq returned command-not-found."],
            refs=REFS_SIGNING,
        )

    installed = [line.strip() for line in (installed_res.stdout or "").splitlines() if line.strip()]
    foreign_res = run(["pacman", "-Qmq"], timeout=1.5)
    foreign = [line.strip() for line in (foreign_res.stdout or "").splitlines() if line.strip()]

    repo_names = [repo["name"] for repo in parsed["repos"]] if parsed else []
    counts, sl_res = _sl_installed_counts(run)
    if sl_res.returncode == 127:
        return make_result(
            id="pacman_inventory",
            category=CATEGORY,
            title="Package inventory",
            passed=False,
            applicable=False,
            score=0,
            max_score=5,
            lane="slow",
            description="pacman is not installed; package inventory does not apply.",
            details=["pacman -Sl returned command-not-found."],
            refs=REFS_SIGNING,
        )
    counts = counts or {}

    omarchy_count = sum(n for name, n in counts.items() if name.lower() == "omarchy")

    details = ["installed=" + str(len(installed))]
    for name in repo_names:
        details.append(name + "=" + str(counts.get(name, 0)))
    details.append("foreign=" + str(len(foreign)))
    if foreign:
        shown = foreign[:20]
        details.append("foreign packages: " + ", ".join(shown))
        if len(foreign) > 20:
            details.append("(" + str(len(foreign) - 20) + " more foreign packages omitted)")

    deduct = 0
    severity = "info"
    if len(foreign) > FOREIGN_WARN_THRESHOLD:
        deduct = 2
        severity = "low"
        desc = (
            str(len(foreign))
            + " foreign packages are installed; unsigned local or AUR builds widen the supply chain."
        )
        rec = "Review foreign packages from pacman -Qmq and prefer signed repository packages."
    else:
        desc = (
            str(len(installed))
            + " packages installed ("
            + str(len(foreign))
            + " foreign); omarchy repo provides "
            + str(omarchy_count)
            + "."
        )
        rec = None

    score = max(0, 5 - deduct)
    return make_result(
        id="pacman_inventory",
        category=CATEGORY,
        title="Package inventory",
        passed=deduct == 0,
        score=score,
        max_score=5,
        severity=severity,
        lane="slow",
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS_SIGNING,
    )


@register_check(
    SLOW_CHECKS,
    check_id="arch_audit",
    category=CATEGORY,
    title="arch-audit vulnerabilities",
    max_score=10,
    lane="slow",
)
def check_arch_audit(*, run=None):
    run = run or run_cmd
    help_res = run(["arch-audit", "--help"], timeout=2.0)
    if help_res.returncode == 127:
        return make_result(
            id="arch_audit",
            category=CATEGORY,
            title="arch-audit vulnerabilities",
            passed=False,
            applicable=False,
            score=0,
            max_score=10,
            lane="slow",
            description="arch-audit is not installed; it is available in the extra repository.",
            details=["arch-audit is in the extra repo."],
            recommendation="sudo pacman -S arch-audit",
            refs=REFS_AUDIT,
        )

    argv, want_json = _installed_arch_audit_flag(help_res.stdout or "")
    scan = run(argv, timeout=ARCH_AUDIT_TIMEOUT_S)
    if _looks_like_network_error(scan) and not (scan.stdout or "").strip():
        err = (scan.stderr or scan.stdout or "network error").strip().splitlines()
        err_line = err[0] if err else "network error"
        return make_result(
            id="arch_audit",
            category=CATEGORY,
            title="arch-audit vulnerabilities",
            passed=False,
            applicable=False,
            score=0,
            max_score=10,
            lane="slow",
            description="arch-audit did not complete (network or timeout): " + err_line[:200],
            details=[err_line[:200]],
            recommendation="Retry `arch-audit` when the network is available.",
            refs=REFS_AUDIT,
        )

    entries = None
    if want_json:
        entries = _parse_arch_audit_json(scan.stdout or "")
    if entries is None:
        entries = _parse_arch_audit_text(scan.stdout or "")

    if scan.returncode not in (0, 1) and not entries:
        err = (scan.stderr or scan.stdout or "arch-audit failed").strip().splitlines()
        err_line = err[0] if err else "arch-audit failed"
        if _looks_like_network_error(scan):
            return make_result(
                id="arch_audit",
                category=CATEGORY,
                title="arch-audit vulnerabilities",
                passed=False,
                applicable=False,
                score=0,
                max_score=10,
                lane="slow",
                description="arch-audit did not complete (network or timeout): " + err_line[:200],
                details=[err_line[:200]],
                recommendation="Retry `arch-audit` when the network is available.",
                refs=REFS_AUDIT,
            )

    by_pkg = {}
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    for pkg, cve, sev in entries:
        key = pkg or cve
        prev = by_pkg.get(key)
        if prev is None or rank.get(sev, 0) > rank.get(prev[2], 0):
            by_pkg[key] = (pkg or key, cve, sev)

    ranked = list(by_pkg.values())
    crit_high = sum(1 for _, _, sev in ranked if sev in ("Critical", "High"))
    medium = sum(1 for _, _, sev in ranked if sev == "Medium")
    low = sum(1 for _, _, sev in ranked if sev == "Low")

    details = []
    for pkg, cve, sev in ranked[:15]:
        label = (cve or "advisory").strip()
        details.append(pkg + ": " + label + " " + sev)
    if len(ranked) > 15:
        details.append("(" + str(len(ranked) - 15) + " more vulnerable packages omitted)")

    deduct = 0
    severity = "info"
    if crit_high:
        deduct = 6
        severity = "high"
        desc = (
            str(len(ranked))
            + " vulnerable packages; "
            + str(crit_high)
            + " are Critical or High."
        )
    elif medium:
        deduct = 3
        severity = "medium"
        desc = str(medium) + " packages have Medium-severity advisories."
    elif low:
        deduct = 1
        severity = "low"
        desc = str(low) + " packages have Low-severity advisories."
    else:
        desc = "arch-audit reported no vulnerable packages."

    score = max(0, 10 - deduct)
    rec = None
    if deduct:
        rec = "Update affected packages and review advisories from the Arch Security Team."
    return make_result(
        id="arch_audit",
        category=CATEGORY,
        title="arch-audit vulnerabilities",
        passed=deduct == 0,
        score=score,
        max_score=10,
        severity=severity,
        lane="slow",
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS_AUDIT,
    )
