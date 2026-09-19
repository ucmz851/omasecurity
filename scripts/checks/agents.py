"""Agent Surface checks: skill inventory (agent_skills) and MCP/hooks (agent_mcp)."""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

from . import FAST_CHECKS, SLOW_CHECKS, make_result, register_check
from .static_scan import DEFAULT_RULES, SECRET_RULE_IDS, sanitize_snippet

CATEGORY = "Agent Surface"
MAX_SKILL_FILES = 2000
MAX_SKILL_BYTES = 512 * 1024

OMARCHY_USR = Path("/usr/share/omarchy")
AGENT_BINARIES = (
    "claude",
    "opencode",
    "gemini",
    "copilot",
    "crush",
    "agy",
    "grok",
    "codex",
    "cursor-agent",
    "cursor",
    "hermes",
    "muse",
    "omp",
    "ori",
    "pi",
    "openclaw",
)
_AGENT_ALT = "|".join(re.escape(name) for name in AGENT_BINARIES)
_SKIP_FLAGS = r"--dangerously-skip-permissions|--yolo|--allow-all"

def _copy_rule(rule, severity=None):
    copied = dict(rule)
    if severity is not None:
        copied["severity"] = severity
    return copied


def _default_rule(rule_id):
    for rule in DEFAULT_RULES:
        if rule["id"] == rule_id:
            return rule
    raise KeyError(rule_id)


AGENT_AUTO_APPROVE = {
    "id": "agent_auto_approve",
    "severity": "CRITICAL",
    "regex": re.compile(
        r"(?:(?:%s)\b[^\n]*(?:%s)|(?:%s)[^\n]*\b(?:%s)\b)"
        % (_AGENT_ALT, _SKIP_FLAGS, _SKIP_FLAGS, _AGENT_ALT)
    ),
    "title": "Agent launched with auto-approve / skip-permissions flag",
    "explanation": (
        "A skill script invokes an agent binary with --yolo, --allow-all, "
        "or --dangerously-skip-permissions."
    ),
}
PROMPT_INJECTION = {
    "id": "prompt_injection",
    "severity": "LOW",
    "regex": re.compile(
        r"ignore (all )?(previous|prior|above) instructions"
        r"|do not (tell|inform|show) the user(?!\s+to\s)"
        r"|without (telling|asking) the user"
        r"|exfiltrat",
        re.IGNORECASE,
    ),
    "title": "Prompt-injection phrasing in skill markdown",
    "explanation": (
        "Skill instructions tell the agent to hide actions from the user "
        "or to ignore prior instructions."
    ),
}
SKILL_SENSITIVE_WRITE = {
    "id": "skill_sensitive_write",
    "severity": "HIGH",
    "regex": re.compile(
        r"(?:~|\$\{?HOME\}?)/\.ssh\b"
        r"|(?:~|\$\{?HOME\}?)/\.bashrc\b"
        r"|(?:~|\$\{?HOME\}?)/\.zshrc\b"
        r"|(?:~|\$\{?HOME\}?)/\.config/omarchy/hooks"
        r"|(?:~|\$\{?HOME\}?)/\.claude/settings[^/\s\"']*\.json"
        r"|(?<![A-Za-z0-9_])/etc/"
    ),
    "title": "Skill script writes to a sensitive path",
    "explanation": (
        "Script content references ~/.ssh, shell rc files, Omarchy hooks, "
        "Claude settings, or /etc."
    ),
}
INSECURE_FETCH = {
    "id": "insecure_fetch",
    "severity": "HIGH",
    "regex": re.compile(
        r"(?:curl|wget)\b[^\n]*"
        r"(?:https?://\d{1,3}(?:\.\d{1,3}){3}\b|http://|"
        r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}\b)",
        re.IGNORECASE,
    ),
    "title": "curl/wget to a bare IPv4 address or non-https URL",
    "explanation": "Downloads from cleartext HTTP or a literal IP address.",
}
# `python -c` on its own is ordinary shell glue (version probes, path lookups).
# Only treat it as obfuscation when the inline payload decodes or executes.
_OBFUSCATED_PAYLOAD = (
    r"base64|b64decode|b64encode|exec\s*\(|eval\s*\(|compile\s*\("
    r"|__import__|marshal|pickle|fromhex|codecs\.decode|\.decode\s*\("
)
SKILL_OBFUSCATION = {
    "id": "skill_obfuscation",
    "severity": "MEDIUM",
    "regex": re.compile(
        r"base64\s+-d\b|python(?:3)?\s+-c\b[^\n]*(?:%s)" % _OBFUSCATED_PAYLOAD,
        re.IGNORECASE,
    ),
    "title": "Obfuscated or inline code in a skill script",
    "explanation": "Skill script uses base64 -d, or python -c with a decoding or exec payload.",
}

# Scripts: DEFAULT_RULES plus agent extras, but obfuscated_exec is MEDIUM here.
# In skill trees that rule is a heuristic with a high false-positive rate on
# tooling code; pipe_to_shell, private_key, and agent_auto_approve stay CRITICAL.
# Markdown never uses silent_sudo, obfuscated_exec, or skill_sensitive_write.
SCRIPT_RULES = [
    (
        _copy_rule(rule, "MEDIUM")
        if rule["id"] == "obfuscated_exec"
        else rule
    )
    for rule in DEFAULT_RULES
] + [
    AGENT_AUTO_APPROVE,
    SKILL_SENSITIVE_WRITE,
    INSECURE_FETCH,
    SKILL_OBFUSCATION,
]
INSTRUCTION_RULES = [
    AGENT_AUTO_APPROVE,
    _copy_rule(_default_rule("pipe_to_shell"), "HIGH"),
    _copy_rule(INSECURE_FETCH, "MEDIUM"),
    PROMPT_INJECTION,
]
CONFIG_RULES = [
    _default_rule("private_key"),
    _default_rule("api_secret"),
]

SKIP_SCAN_DIRS = frozenset({
    ".git", "node_modules", "test", "tests", "references", "examples", "docs",
})
SKIP_FILE_PREFIXES = ("README", "CHANGELOG", "LICENSE")
MARKETPLACE_SUBDIRS = ("plugins", "external_plugins")
INSTRUCTION_ROOTS = frozenset({".claude/commands", ".claude/agents"})
VENDOR_ROOTS = frozenset({".cursor/skills-cursor"})

SKILL_ROOT_RELS = (
    ".agents/skills",
    ".claude/skills",
    ".codex/skills",
    ".pi/agent/skills",
    ".cursor/skills-cursor",
    ".claude/commands",
    ".claude/agents",
    ".claude/plugins/marketplaces",
)

MCP_FILE_RELS = (
    ".claude.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".config/opencode/opencode.json",
    ".copilot/mcp-config.json",
)

UNPINNED_LAUNCHERS = frozenset({"npx", "uvx", "bunx"})
CRED_MARKERS = ("sk-", "ghp_", "github_pat_", "xoxb-", "AKIA", "Bearer ")
DANGEROUS_ALLOW = frozenset({"Bash", "Bash(*)", "*", "Bash(sudo:*)"})
PIN_RE = re.compile(r"@\d+\.\d+|==")
_SECRET_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|xoxb-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{8,}|Bearer\s+\S+)",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

AUTO_APPROVE_FLAGS = {
    "claude": "--permission-mode auto",
    "opencode": "--auto",
    "gemini": "--yolo",
    "copilot": "--allow-all",
    "crush": "--yolo",
    "agy": "--dangerously-skip-permissions",
    "grok": "--permission-mode bypassPermissions",
    "codex": "--approve-for-me",
    "cursor-agent": "--yolo --trust",
    "hermes": "--yolo",
    "muse": "--approval-mode never",
    "omp": "--auto-approve",
    "pi": "(none; pi has no approval prompt to skip)",
    "ori": "(none; ori has no approval prompt to skip)",
    "openclaw": "(none; openclaw has no approval prompt to skip)",
}

REFS = [
    "https://github.com/omacom/omarchy/blob/quattro/migrations/1786539345.sh",
    "https://github.com/omacom/omarchy/blob/quattro/bin/omarchy-agent",
]


def _home(home):
    return Path(home) if home is not None else Path.home()


def _is_under(path, parent):
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except (ValueError, OSError):
        return False


def _display(path, home):
    path = Path(path)
    try:
        return "~/" + str(path.resolve().relative_to(Path(home).resolve()))
    except (ValueError, OSError):
        return str(path)


def _redact(text):
    if text is None:
        return text
    return _SECRET_RE.sub("[redacted]", str(text))


def _flag(
    plugin,
    file,
    severity,
    title,
    explanation,
    snippet="",
    line=0,
):
    return {
        "plugin": plugin,
        "file": str(file),
        "line": int(line),
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "snippet": sanitize_snippet(_redact(snippet), 80),
    }


def _skip_named_file(path):
    upper = Path(path).name.upper()
    return any(upper.startswith(prefix) for prefix in SKIP_FILE_PREFIXES)


def _is_instruction_file(filepath, skill_dir, root_rel):
    filepath = Path(filepath)
    skill_dir = Path(skill_dir)
    name = filepath.name
    if name == "SKILL.md" or name.lower() == "skill.md":
        return True
    if root_rel in INSTRUCTION_ROOTS:
        return True
    try:
        base = skill_dir if skill_dir.is_dir() else skill_dir.parent
        rel_parts = filepath.resolve().relative_to(base.resolve()).parts
    except (ValueError, OSError):
        rel_parts = filepath.parts
    if "commands" in rel_parts or "agents" in rel_parts:
        return True
    if filepath.suffix.lower() != ".md":
        return False
    parent = filepath.parent
    if skill_dir.is_file():
        return parent == skill_dir.parent
    return parent == skill_dir


def _rules_for(filepath, skill_dir, root_rel):
    filepath = Path(filepath)
    if _skip_named_file(filepath):
        return None
    if _is_instruction_file(filepath, skill_dir, root_rel):
        return INSTRUCTION_RULES
    ext = filepath.suffix.lower()
    if ext in {".sh", ".py", ".js"}:
        return SCRIPT_RULES
    if ext in {".json", ".toml", ".yaml", ".yml"}:
        return CONFIG_RULES
    return None


def _entry_display(entry, home):
    """Display a skill entry by its own location, without resolving symlinks."""
    entry = Path(entry)
    try:
        return "~/" + str(entry.relative_to(Path(home)))
    except ValueError:
        return str(entry)


def _format_items(items, skill_name, base_path, home):
    """Build each finding's path from the directory actually scanned.

    skill_name is a label ("marketplace:plugin" under .claude/plugins/
    marketplaces), so joining it onto the root produced a path that does not
    exist on disk. base_path is the real scanned target.
    """
    base = Path(base_path)
    is_dir = base.is_dir()
    kept = []
    for item in items:
        rel = item["file"]
        full = base / rel if is_dir else base
        kept.append(
            _flag(
                skill_name,
                _display(full, home),
                item["severity"],
                item["title"],
                item["explanation"],
                item.get("snippet") or "",
                item.get("line") or 0,
            )
        )
    return kept


def _inside_string_literal(line, index):
    """Odd quotes before index means the match sits inside a same-line string."""
    prefix = line[:index]
    return (prefix.count("'") + prefix.count('"')) % 2 == 1


_QUOTE_CHARS = "\"'`\u201c\u201d\u2018\u2019"

# Prose that cites an injection phrase in order to defend against it.
_DEFENSIVE_RE = re.compile(
    r"never follow|do not follow|don't follow|ignore such|disregard such"
    r"|refuse|reject|do not comply|must not|should not|don't go along"
    r"|prompt.?injection|injection attempt|treat .{0,20}as data"
    r"|untrusted|attacker|malicious|adversar",
    re.IGNORECASE,
)


def _is_cited(line, start, end):
    """True when the matched phrase is wrapped in quotes, i.e. quoted as an example."""
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    return before in _QUOTE_CHARS and after in _QUOTE_CHARS


def _suppress_injection(line, match):
    """Skip injection phrasing that is being quoted or warned about, not issued."""
    if _is_cited(line, match.start(), match.end()):
        return True
    return bool(_DEFENSIVE_RE.search(line))


_TRIPLE_RE = re.compile(r'"""|\'\'\'')


def _docstring_mask(lines):
    """Mark lines that sit inside a Python triple-quoted block.

    Prose in a docstring is documentation, not executed code; the line-leading
    comment skip cannot see it because the block opens on an earlier line.
    """
    mask = [False] * len(lines)
    delim = None
    for i, line in enumerate(lines):
        if delim is None:
            pos = 0
            opened = None
            while True:
                found = _TRIPLE_RE.search(line, pos)
                if not found:
                    break
                token = found.group(0)
                if opened is None:
                    opened = token
                elif token == opened:
                    opened = None
                pos = found.end()
            # The opening line may hold real code before the quotes, so scan it.
            delim = opened
        else:
            mask[i] = True
            if delim in line:
                delim = None
    return mask


def _apply_rules(filepath, rel, rules, max_bytes):
    filepath = Path(filepath)
    if not rules:
        return [], 0
    try:
        size = filepath.stat().st_size
    except OSError:
        return [], 0
    if size > max_bytes:
        return [], 0
    try:
        lines = filepath.read_text(errors="ignore").splitlines()
    except Exception:
        return [], 0
    flagged = []
    in_docstring = (
        _docstring_mask(lines)
        if filepath.suffix.lower() == ".py"
        else [False] * len(lines)
    )
    for line_no, line in enumerate(lines, 1):
        sline = line.strip()
        if (
            sline.startswith("//")
            or sline.startswith("#")
            or sline.startswith("*")
            or sline.startswith("/*")
        ):
            continue
        if in_docstring[line_no - 1]:
            continue
        for rule in rules:
            match = rule["regex"].search(line)
            if not match:
                continue
            if rule.get("id") == "obfuscated_exec" and _inside_string_literal(
                line, match.start()
            ):
                continue
            if rule.get("id") == "prompt_injection" and _suppress_injection(
                line, match
            ):
                continue
            snippet = (
                "[redacted]"
                if rule.get("id") in SECRET_RULE_IDS
                else sanitize_snippet(sline, 80)
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
    return flagged, 1


def _scan_one_file(filepath, skill_dir, root_rel, max_bytes):
    filepath = Path(filepath)
    rules = _rules_for(filepath, skill_dir, root_rel)
    if not rules:
        return [], 0
    try:
        rel = str(filepath.relative_to(skill_dir if Path(skill_dir).is_dir() else filepath.parent))
    except ValueError:
        rel = filepath.name
    return _apply_rules(filepath, rel, rules, max_bytes)


def _scan_entry(path, remaining, root_rel):
    path = Path(path)
    if remaining <= 0:
        return [], 0
    if path.is_file():
        return _scan_one_file(path, path, root_rel, MAX_SKILL_BYTES)
    if not path.is_dir():
        return [], 0
    flagged = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        kept = []
        for name in dirnames:
            if name in SKIP_SCAN_DIRS or name.startswith("."):
                continue
            child = Path(dirpath) / name
            if child.is_symlink():
                continue
            kept.append(name)
        dirnames[:] = kept
        for filename in filenames:
            if scanned >= remaining:
                return flagged, scanned
            filepath = Path(dirpath) / filename
            if filepath.is_symlink():
                continue
            items, n = _scan_one_file(filepath, path, root_rel, MAX_SKILL_BYTES)
            scanned += n
            flagged.extend(items)
    return flagged, scanned


def _iter_skill_entries(rel, root):
    root = Path(root)
    if rel == ".claude/plugins/marketplaces":
        try:
            markets = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for market in markets:
            if market.name.startswith(".") or not market.is_dir():
                continue
            for sub in MARKETPLACE_SUBDIRS:
                folder = market / sub
                if not folder.is_dir():
                    continue
                try:
                    plugins = sorted(folder.iterdir(), key=lambda p: p.name)
                except OSError:
                    continue
                for plugin in plugins:
                    if plugin.name.startswith("."):
                        continue
                    yield "%s:%s" % (market.name, plugin.name), plugin
        return
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError:
        return
    for entry in entries:
        if entry.name.startswith("."):
            if rel == ".codex/skills" and entry.name == ".system":
                yield entry.name, entry
            continue
        yield entry.name, entry


def _is_vendor(rel, name):
    if rel in VENDOR_ROOTS:
        return True
    return rel == ".codex/skills" and name == ".system"


def _classify(entry, home):
    """Return (kind, target_path). kind is omarchy-shipped, vendor-shipped, third-party, outside, broken."""
    home = Path(home)
    if entry.is_symlink():
        raw = Path(os.path.join(str(entry.parent), os.readlink(str(entry))))
        if not entry.exists():
            return "broken", raw
        try:
            target = entry.resolve()
        except OSError:
            return "broken", raw
    else:
        try:
            target = entry.resolve()
        except OSError:
            return "third-party", entry

    local_omarchy = home / ".local" / "share" / "omarchy"
    if _is_under(target, OMARCHY_USR) or _is_under(target, local_omarchy):
        return "omarchy-shipped", target
    if not _is_under(target, home) and not _is_under(target, OMARCHY_USR):
        return "outside", target
    return "third-party", target


def _dedupe_flags(flagged):
    seen = set()
    out = []
    for item in flagged:
        key = (item.get("file"), item.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _severity_from_flags(flagged):
    if any(x["severity"] == "CRITICAL" for x in flagged):
        return "critical"
    if any(x["severity"] == "HIGH" for x in flagged):
        return "high"
    if any(x["severity"] == "MEDIUM" for x in flagged):
        return "medium"
    if any(x["severity"] == "LOW" for x in flagged):
        return "low"
    return "info"


def _deduct(flagged, *, critical=8, high=4, medium=2, max_score=15, cap=None):
    c = sum(1 for x in flagged if x["severity"] == "CRITICAL")
    h = sum(1 for x in flagged if x["severity"] == "HIGH")
    m = sum(1 for x in flagged if x["severity"] == "MEDIUM")
    if cap is not None:
        c = min(cap, c)
        h = min(cap, h)
        m = min(cap, m)
    return max(0, max_score - c * critical - h * high - m * medium)


@register_check(
    SLOW_CHECKS,
    check_id="agent_skills",
    category=CATEGORY,
    title="Agent Skills Inventory",
    max_score=15,
    lane="slow",
)
def check_agent_skills(*, home=None):
    home = _home(home)
    roots = []
    for rel in SKILL_ROOT_RELS:
        path = home / rel
        if path.exists():
            roots.append((rel, path))

    if not roots:
        return make_result(
            id="agent_skills",
            category=CATEGORY,
            title="Agent Skills Inventory",
            passed=False,
            applicable=False,
            score=0,
            max_score=15,
            description="No agent skill directories are present.",
            details=["None of the known agent skill roots exist under $HOME."],
            refs=REFS,
            lane="slow",
        )

    flagged = []
    details = []
    total_skills = 0
    shipped = 0
    vendor = 0
    third = 0
    remaining = MAX_SKILL_FILES
    per_root = []

    for rel, root in roots:
        root_label = "~/" + rel
        count = 0
        for name, entry in _iter_skill_entries(rel, root):
            count += 1
            total_skills += 1
            kind, target = _classify(entry, home)
            if kind not in {"broken", "outside"} and _is_vendor(rel, name):
                kind = "vendor-shipped"
            if kind == "omarchy-shipped":
                shipped += 1
            elif kind == "vendor-shipped":
                vendor += 1
            else:
                third += 1
                details.append(
                    "%s in %s -> %s"
                    % (name, root_label, _display(target, home) if kind != "broken" else str(target))
                )
            if kind == "outside":
                flagged.append(
                    _flag(
                        name,
                        _entry_display(entry, home),
                        "HIGH",
                        "skill symlink points outside home and Omarchy",
                        "Top-level skill symlink resolves outside $HOME and /usr/share/omarchy.",
                        str(target),
                    )
                )
            elif kind == "broken":
                flagged.append(
                    _flag(
                        name,
                        _entry_display(entry, home),
                        "MEDIUM",
                        "Broken skill symlink",
                        "Top-level skill entry is a symlink whose target does not exist.",
                        str(target),
                    )
                )
            scan_path = target if kind != "broken" else None
            if scan_path is not None and remaining > 0:
                items, n = _scan_entry(scan_path, remaining, rel)
                remaining -= n
                flagged.extend(_format_items(items, name, scan_path, home))
        per_root.append("%s: %d" % (root_label, count))

    flagged = _dedupe_flags(flagged)
    low_hits = [item for item in flagged if item["severity"] == "LOW"]
    scored = [item for item in flagged if item["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}]
    details = per_root + details
    if low_hits:
        details.append(
            "prompt-injection notes (LOW, no score impact): %d"
            % len(low_hits)
        )
    score = _deduct(scored, critical=6, high=3, medium=1, max_score=15, cap=2)
    passed = len(scored) == 0
    desc = (
        "%d skills: %d omarchy-shipped, %d vendor-shipped, %d third-party"
        % (total_skills, shipped, vendor, third)
    )
    rec = None
    if not passed:
        rec = (
            "Review third-party agent skills and remove symlinks that point "
            "outside home, plus any skills that auto-approve tools or hide work from you."
        )
    return make_result(
        id="agent_skills",
        category=CATEGORY,
        title="Agent Skills Inventory",
        passed=passed,
        applicable=True,
        score=score,
        max_score=15,
        severity=_severity_from_flags(flagged),
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS,
        flagged_items=flagged,
        lane="slow",
    )


def _load_toml(text):
    try:
        import tomllib
    except ImportError:
        return _minimal_toml(text)
    return tomllib.loads(text)


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    return value


def _minimal_toml(text):
    """Parse enough TOML for [mcp_servers.name] tables when tomllib is absent."""
    data = {}
    section = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            section = [p.strip() for p in name.split(".") if p.strip()]
            cursor = data
            for part in section:
                cursor = cursor.setdefault(part, {})
            continue
        if "=" not in line or not section:
            continue
        key, _, rest = line.partition("=")
        key = key.strip()
        rest = rest.strip()
        cursor = data
        for part in section:
            cursor = cursor.setdefault(part, {})
        if rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            if not inner:
                cursor[key] = []
            else:
                cursor[key] = [_unquote(item.strip()) for item in inner.split(",")]
        else:
            cursor[key] = _unquote(rest)
    return data


def _load_json(path):
    text = Path(path).read_text(errors="ignore")
    return json.loads(text)


def _command_parts(server):
    if not isinstance(server, dict):
        return []
    cmd = server.get("command")
    args = server.get("args")
    parts = []
    if isinstance(cmd, list):
        parts.extend(str(x) for x in cmd)
    elif isinstance(cmd, str) and cmd.strip():
        try:
            parts.extend(shlex.split(cmd))
        except ValueError:
            parts.append(cmd)
    if isinstance(args, list):
        parts.extend(str(x) for x in args)
    elif isinstance(args, str) and args.strip():
        try:
            parts.extend(shlex.split(args))
        except ValueError:
            parts.append(args)
    return parts


def _has_pin(text):
    return bool(PIN_RE.search(text))


def _unpinned_stdio(parts):
    if not parts:
        return False
    base = Path(parts[0]).name
    joined = " ".join(parts)
    if base in UNPINNED_LAUNCHERS or joined.startswith(("npx ", "uvx ", "bunx ")):
        return not _has_pin(joined)
    if base == "pipx" and len(parts) >= 2 and parts[1] == "run":
        return not _has_pin(" ".join(parts[2:]))
    if joined.startswith("pipx run"):
        return not _has_pin(joined)
    return False


def _looks_credential(value):
    if not isinstance(value, str) or len(value) <= 20:
        return False
    return any(marker in value for marker in CRED_MARKERS)


def _server_url(server):
    if not isinstance(server, dict):
        return ""
    for key in ("url", "serverUrl", "httpUrl", "sseUrl"):
        val = server.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _transport(server, parts):
    if parts:
        return "stdio"
    url = _server_url(server)
    type_hint = str((server or {}).get("type") or "").lower()
    if type_hint in ("sse", "http"):
        return type_hint
    if "sse" in url.lower():
        return "sse"
    if url:
        return "http"
    return "http"


def _host_of(url):
    rest = url.split("://", 1)[-1]
    hostport = rest.split("/", 1)[0]
    host = hostport.split("@")[-1]
    if host.startswith("["):
        return host[1:].split("]")[0]
    return host.split(":")[0]


def _insecure_http_url(url):
    if not url:
        return False
    lower = url.lower()
    if lower.startswith("https://"):
        return False
    host = _host_of(url).lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost"):
        return False
    if IPV4_RE.match(host) and host.startswith("127."):
        return False
    return True


def _iter_mcp_maps(obj):
    """Yield (label, mapping) for mcp server dicts found in a parsed document."""
    if not isinstance(obj, dict):
        return
    for key in ("mcpServers", "mcp", "mcp_servers"):
        val = obj.get(key)
        if isinstance(val, dict):
            yield key, val
    projects = obj.get("projects")
    if isinstance(projects, dict):
        for proj_name, proj in projects.items():
            if not isinstance(proj, dict):
                continue
            servers = proj.get("mcpServers") or proj.get("mcp")
            if isinstance(servers, dict):
                yield "projects.%s.mcpServers" % proj_name, servers


def _walk_commands(obj, found):
    if isinstance(obj, dict):
        cmd = obj.get("command")
        if isinstance(cmd, str) and cmd.strip():
            found.append(cmd)
        elif isinstance(cmd, list):
            found.append(" ".join(str(x) for x in cmd))
        for val in obj.values():
            _walk_commands(val, found)
    elif isinstance(obj, list):
        for item in obj:
            _walk_commands(item, found)


def _hook_events(hooks):
    if isinstance(hooks, dict):
        return [str(k) for k in hooks.keys()]
    if isinstance(hooks, list):
        return ["hooks"]
    return []


def _scan_command_string(command, plugin, source):
    flagged = []
    for rule in DEFAULT_RULES:
        if rule["regex"].search(command):
            flagged.append(
                _flag(
                    plugin,
                    source,
                    rule["severity"],
                    rule["title"],
                    rule["explanation"],
                    command,
                    0,
                )
            )
            break
    return flagged


def _record_server(name, source, server, flagged, records):
    parts = _command_parts(server)
    transport = _transport(server, parts)
    command = " ".join(parts)
    url = _server_url(server)
    records.append({
        "name": name,
        "source": source,
        "transport": transport,
        "command": command or url,
    })
    if transport == "stdio" and _unpinned_stdio(parts):
        flagged.append(
            _flag(
                name,
                source,
                "MEDIUM",
                "Unpinned MCP stdio launcher",
                "stdio command uses npx/uvx/pipx run/bunx without a version pin.",
                command,
            )
        )
    env = server.get("env") if isinstance(server, dict) else None
    if isinstance(env, dict):
        for env_key, env_val in env.items():
            if _looks_credential(env_val):
                flagged.append(
                    _flag(
                        name,
                        source,
                        "HIGH",
                        "MCP env value looks like a credential",
                        "Environment key %s on server %s looks like a secret."
                        % (env_key, name),
                        "env %s" % env_key,
                    )
                )
    if transport in {"http", "sse"} and _insecure_http_url(url):
        flagged.append(
            _flag(
                name,
                source,
                "HIGH",
                "MCP HTTP/SSE URL is not https",
                "Server %s uses a non-https URL that is not localhost." % name,
                _redact(url),
            )
        )


def _default_agent_detail(home):
    path = Path(home) / ".config" / "omarchy" / "defaults" / "agent"
    try:
        name = path.read_text(errors="ignore").strip()
    except OSError:
        name = ""
    if not name:
        return (
            "Default agent is not set (~/.config/omarchy/defaults/agent missing); "
            "omarchy-agent will refuse to launch until one is chosen."
        )
    flag = AUTO_APPROVE_FLAGS.get(name)
    if flag:
        if flag.startswith("(none"):
            return (
                "Default agent is %s; omarchy-agent launches it with no extra "
                "auto-approve flag %s." % (name, flag)
            )
        return (
            "Default agent is %s; omarchy-agent launches it with %s "
            "(approval prompts disabled)." % (name, flag)
        )
    return (
        "Default agent is %s; omarchy-agent has no documented auto-approve flag "
        "for this binary." % name
    )


@register_check(
    FAST_CHECKS,
    check_id="agent_mcp",
    category=CATEGORY,
    title="Agent MCP Servers, Hooks, and Permissions",
    max_score=10,
)
def check_agent_mcp(*, home=None):
    home = _home(home)
    flagged = []
    details = []
    records = []
    configs_used = 0
    hooks_count = 0
    hook_events = []
    any_file = False

    for rel in MCP_FILE_RELS:
        path = home / rel
        if not path.exists() or not path.is_file():
            continue
        any_file = True
        source = "~/" + rel
        try:
            if path.suffix.lower() == ".toml":
                doc = _load_toml(path.read_text(errors="ignore"))
            else:
                doc = _load_json(path)
        except Exception as exc:
            details.append("Failed to parse %s: %s" % (source, type(exc).__name__))
            continue
        configs_used += 1
        if not isinstance(doc, dict):
            details.append("Failed to parse %s: not a table/object" % source)
            continue

        for _label, mapping in _iter_mcp_maps(doc):
            for srv_name, srv in mapping.items():
                if isinstance(srv, dict):
                    _record_server(str(srv_name), source, srv, flagged, records)

        if doc.get("enableAllProjectMcpServers") is True:
            flagged.append(
                _flag(
                    "settings",
                    source,
                    "MEDIUM",
                    "enableAllProjectMcpServers is true",
                    "Project MCP servers are auto-enabled without per-project trust.",
                    "enableAllProjectMcpServers",
                )
            )
        perms = doc.get("permissions")
        if isinstance(perms, dict):
            allow = perms.get("allow")
            if isinstance(allow, list):
                hits = [item for item in allow if item in DANGEROUS_ALLOW]
                if hits:
                    flagged.append(
                        _flag(
                            "permissions",
                            source,
                            "HIGH",
                            "Claude permissions.allow includes unrestricted Bash",
                            "permissions.allow contains %s." % ", ".join(str(h) for h in hits),
                            ", ".join(str(h) for h in hits),
                        )
                    )
        hooks = doc.get("hooks")
        if hooks:
            events = _hook_events(hooks)
            hook_events.extend(events)
            commands = []
            _walk_commands(hooks, commands)
            hooks_count += len(commands) if commands else 1
            for cmd in commands:
                flagged.extend(_scan_command_string(cmd, "hooks", source))

    if not any_file:
        result = make_result(
            id="agent_mcp",
            category=CATEGORY,
            title="Agent MCP Servers, Hooks, and Permissions",
            passed=False,
            applicable=False,
            score=0,
            max_score=10,
            description="No agent MCP or settings files are present.",
            details=[
                "None of the known MCP/settings files exist under $HOME.",
                _default_agent_detail(home),
            ],
            refs=REFS,
        )
        return result

    unique_events = []
    for name in hook_events:
        if name not in unique_events:
            unique_events.append(name)
    if unique_events:
        details.append(
            "hooks defined: %s (%d command(s))"
            % (", ".join(unique_events), hooks_count)
        )
    elif hooks_count:
        details.append("hooks defined (%d)" % hooks_count)

    details.append(_default_agent_detail(home))
    for rec in records:
        cmd = rec["command"] or "(none)"
        details.append(
            "MCP %s (%s, %s): %s"
            % (rec["name"], rec["source"], rec["transport"], _redact(cmd))
        )

    score = _deduct(flagged, critical=4, high=4, medium=2, max_score=10)
    passed = not any(x["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} for x in flagged)
    desc = (
        "%d MCP servers across %d configs, %d hooks, %d flagged"
        % (len(records), configs_used, hooks_count, len(flagged))
    )
    rec = None
    if not passed:
        rec = (
            "Pin MCP stdio packages, move secrets out of env blocks, restrict "
            "permissions.allow, and use https for remote MCP servers."
        )
    return make_result(
        id="agent_mcp",
        category=CATEGORY,
        title="Agent MCP Servers, Hooks, and Permissions",
        passed=passed,
        applicable=True,
        score=score,
        max_score=10,
        severity=_severity_from_flags(flagged),
        description=desc,
        details=details,
        recommendation=rec,
        refs=REFS,
        flagged_items=flagged,
    )
