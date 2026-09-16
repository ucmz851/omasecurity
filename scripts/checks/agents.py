"""Agent Surface checks: skill inventory (agent_skills) and MCP/hooks (agent_mcp)."""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

from . import FAST_CHECKS, SLOW_CHECKS, make_result, register_check
from .static_scan import DEFAULT_RULES, SECRET_RULE_IDS, sanitize_snippet, scan_tree

CATEGORY = "Agent Surface"
MAX_SKILL_FILES = 2000
MAX_SKILL_BYTES = 512 * 1024
SCAN_EXTS = (".md", ".sh", ".py", ".js", ".json", ".toml", ".yaml", ".yml")
SCRIPT_EXTS = frozenset({".sh", ".py", ".js"})
MD_EXTS = frozenset({".md"})

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

EXTRA_RULES = [
    {
        "id": "agent_auto_approve",
        "severity": "CRITICAL",
        "exts": None,
        "regex": re.compile(
            r"(?:(?:%s)\b[^\n]*(?:%s)|(?:%s)[^\n]*\b(?:%s)\b)"
            % (_AGENT_ALT, _SKIP_FLAGS, _SKIP_FLAGS, _AGENT_ALT)
        ),
        "title": "Agent launched with auto-approve / skip-permissions flag",
        "explanation": (
            "A skill script invokes an agent binary with --yolo, --allow-all, "
            "or --dangerously-skip-permissions."
        ),
    },
    {
        "id": "prompt_injection",
        "severity": "HIGH",
        "exts": MD_EXTS,
        "regex": re.compile(
            r"ignore (all )?(previous|prior|above) instructions"
            r"|do not (tell|inform|show) the user"
            r"|without (telling|asking) the user"
            r"|exfiltrat",
            re.IGNORECASE,
        ),
        "title": "Prompt-injection phrasing in skill markdown",
        "explanation": (
            "Skill instructions tell the agent to hide actions from the user "
            "or to ignore prior instructions."
        ),
    },
    {
        "id": "skill_sensitive_write",
        "severity": "HIGH",
        "exts": SCRIPT_EXTS,
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
    },
    {
        "id": "insecure_fetch",
        "severity": "HIGH",
        "exts": None,
        "regex": re.compile(
            r"(?:curl|wget)\b[^\n]*"
            r"(?:https?://\d{1,3}(?:\.\d{1,3}){3}\b|http://|"
            r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}\b)",
            re.IGNORECASE,
        ),
        "title": "curl/wget to a bare IPv4 address or non-https URL",
        "explanation": "Downloads from cleartext HTTP or a literal IP address.",
    },
    {
        "id": "skill_obfuscation",
        "severity": "MEDIUM",
        "exts": SCRIPT_EXTS,
        "regex": re.compile(r"base64\s+-d\b|python(?:3)?\s+-c\b", re.IGNORECASE),
        "title": "Obfuscated or inline code in a skill script",
        "explanation": "Skill script uses base64 -d or python -c.",
    },
]
_EXTRA_BY_ID = {rule["id"]: rule for rule in EXTRA_RULES}
SKILL_RULES = list(DEFAULT_RULES) + EXTRA_RULES

SKILL_ROOT_RELS = (
    ".agents/skills",
    ".claude/skills",
    ".codex/skills",
    ".pi/agent/skills",
    ".cursor/skills-cursor",
    ".claude/commands",
    ".claude/agents",
    ".claude/plugins/marketplaces",
    ".codex/skills/.system",
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


def _filter_items(items, skill_name, root_label):
    kept = []
    for item in items:
        rule = _EXTRA_BY_ID.get(item.get("rule_id"))
        if rule and rule.get("exts"):
            ext = Path(item["file"]).suffix.lower()
            if ext not in rule["exts"]:
                continue
        rel = item["file"]
        kept.append(
            _flag(
                skill_name,
                "%s/%s/%s" % (root_label, skill_name, rel),
                item["severity"],
                item["title"],
                item["explanation"],
                item.get("snippet") or "",
                item.get("line") or 0,
            )
        )
    return kept


def _scan_file(filepath, rules, max_bytes):
    """Apply scan_tree rules to a single file (top-level skill that is not a dir)."""
    filepath = Path(filepath)
    ext = filepath.suffix.lower()
    wanted = {e if e.startswith(".") else "." + e for e in SCAN_EXTS}
    if ext not in wanted:
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
    for line_no, line in enumerate(lines, 1):
        sline = line.strip()
        if (
            sline.startswith("//")
            or sline.startswith("#")
            or sline.startswith("*")
            or sline.startswith("/*")
        ):
            continue
        for rule in rules:
            if rule["regex"].search(line):
                snippet = (
                    "[redacted]"
                    if rule.get("id") in SECRET_RULE_IDS
                    else sanitize_snippet(sline, 80)
                )
                flagged.append({
                    "file": filepath.name,
                    "line": line_no,
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "explanation": rule["explanation"],
                    "snippet": snippet,
                    "rule_id": rule.get("id"),
                })
                break
    return flagged, 1


def _scan_entry(path, remaining):
    path = Path(path)
    if remaining <= 0:
        return [], 0
    if path.is_dir():
        return scan_tree(
            path,
            SCAN_EXTS,
            SKILL_RULES,
            remaining,
            MAX_SKILL_BYTES,
            follow_symlinks=False,
        )
    if path.is_file():
        return _scan_file(path, SKILL_RULES, MAX_SKILL_BYTES)
    return [], 0


def _classify(entry, home):
    """Return (kind, target_path). kind is omarchy-shipped, third-party, outside, broken."""
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


def _deduct(flagged, *, critical=8, high=4, medium=2, max_score=15):
    c = sum(1 for x in flagged if x["severity"] == "CRITICAL")
    h = sum(1 for x in flagged if x["severity"] == "HIGH")
    m = sum(1 for x in flagged if x["severity"] == "MEDIUM")
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
    third = 0
    remaining = MAX_SKILL_FILES
    per_root = []

    for rel, root in roots:
        root_label = "~/" + rel
        count = 0
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            details.append("%s: unreadable (%s)" % (root_label, exc))
            continue
        for entry in entries:
            count += 1
            total_skills += 1
            kind, target = _classify(entry, home)
            if kind == "omarchy-shipped":
                shipped += 1
            else:
                third += 1
                details.append(
                    "%s in %s -> %s"
                    % (entry.name, root_label, _display(target, home) if kind != "broken" else str(target))
                )
            if kind == "outside":
                flagged.append(
                    _flag(
                        entry.name,
                        root_label + "/" + entry.name,
                        "HIGH",
                        "skill symlink points outside home and Omarchy",
                        "Top-level skill symlink resolves outside $HOME and /usr/share/omarchy.",
                        str(target),
                    )
                )
            elif kind == "broken":
                flagged.append(
                    _flag(
                        entry.name,
                        root_label + "/" + entry.name,
                        "MEDIUM",
                        "Broken skill symlink",
                        "Top-level skill entry is a symlink whose target does not exist.",
                        str(target),
                    )
                )
            scan_path = target if kind != "broken" else None
            if scan_path is not None and remaining > 0:
                items, n = _scan_entry(scan_path, remaining)
                remaining -= n
                flagged.extend(_filter_items(items, entry.name, root_label))
        per_root.append("%s: %d" % (root_label, count))

    details = per_root + details
    score = _deduct(flagged, critical=8, high=4, medium=2, max_score=15)
    passed = len(flagged) == 0
    desc = (
        "%d skills across %d agent dirs, %d omarchy-shipped, %d third-party"
        % (total_skills, len(roots), shipped, third)
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
