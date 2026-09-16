"""Shell plugin static analysis (id: plugins_deep, weight 25)."""

from __future__ import annotations

from pathlib import Path

from . import FAST_CHECKS, make_result, register_check
from .static_scan import DEFAULT_RULES, scan_tree

HOME = Path.home()
SCAN_EXTS = (".qml", ".js", ".sh", ".py", ".json", ".toml")
MAX_FILES = 500
MAX_BYTES = 1024 * 1024
REFS = ["https://wiki.archlinux.org/title/Security"]


def _self_plugin_dir():
    # scripts/checks/plugins.py -> plugin root
    return Path(__file__).resolve().parents[2]


@register_check(
    FAST_CHECKS,
    check_id="plugins_deep",
    category="Plugin Health",
    title="Shell Plugin Code Health & Safety",
    max_score=25,
)
def check_plugins_deep(*, plugins_dir=None, self_dir=None):
    plugins_dir = Path(plugins_dir) if plugins_dir else HOME / ".config" / "omarchy" / "plugins"
    self_dir = Path(self_dir).resolve() if self_dir else _self_plugin_dir()

    if not plugins_dir.exists():
        return make_result(
            id="plugins_deep",
            category="Plugin Health",
            title="Shell Plugin Code Health & Safety",
            passed=False,
            applicable=False,
            score=0,
            max_score=25,
            description="No user shell plugins directory is present.",
            details=[f"Missing {plugins_dir}"],
            refs=REFS,
        )

    flagged_items = []
    files_scanned = 0
    scanned_plugins = 0
    remaining = MAX_FILES

    try:
        entries = sorted(plugins_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        entries = []

    for plugin in entries:
        if remaining <= 0:
            break
        if not plugin.is_dir() or plugin.name.startswith("."):
            continue
        try:
            if plugin.resolve() == self_dir:
                continue
        except OSError:
            continue
        scanned_plugins += 1
        items, n = scan_tree(
            plugin,
            SCAN_EXTS,
            DEFAULT_RULES,
            remaining,
            MAX_BYTES,
            follow_symlinks=False,
        )
        files_scanned += n
        remaining = MAX_FILES - files_scanned
        for item in items:
            flagged_items.append({
                "plugin": plugin.name,
                "file": str(Path(plugin.name) / item["file"]),
                "line": item["line"],
                "severity": item["severity"],
                "title": item["title"],
                "explanation": item["explanation"],
                "snippet": item["snippet"],
            })

    if scanned_plugins == 0:
        return make_result(
            id="plugins_deep",
            category="Plugin Health",
            title="Shell Plugin Code Health & Safety",
            passed=False,
            applicable=False,
            score=0,
            max_score=25,
            description="No user shell plugins installed.",
            details=["Only this auditor, or no plugin directories, were found."],
            refs=REFS,
        )

    critical_count = sum(1 for x in flagged_items if x["severity"] == "CRITICAL")
    high_count = sum(1 for x in flagged_items if x["severity"] == "HIGH")
    med_count = sum(1 for x in flagged_items if x["severity"] == "MEDIUM")
    deduction = (critical_count * 15) + (high_count * 8) + (med_count * 3)
    final_score = max(0, 25 - deduction)
    passed = len(flagged_items) == 0
    if passed:
        desc = (
            f"All {scanned_plugins} installed plugins ({files_scanned} files) "
            "passed deep static security analysis."
        )
        severity = "info"
        rec = None
    else:
        desc = (
            f"Scanned {scanned_plugins} plugins ({files_scanned} files): "
            f"{len(flagged_items)} risk(s) flagged "
            f"({critical_count} critical, {high_count} high, {med_count} medium)."
        )
        severity = "critical" if critical_count else ("high" if high_count else "medium")
        rec = (
            "Inspect flagged plugin source files and remove unescaped shell executions, "
            "hardcoded tokens, or unneeded sudo commands."
        )

    return make_result(
        id="plugins_deep",
        category="Plugin Health",
        title="Shell Plugin Code Health & Safety",
        passed=passed,
        applicable=True,
        score=final_score,
        max_score=25,
        severity=severity,
        description=desc,
        details=[f"plugins={scanned_plugins}", f"files={files_scanned}"],
        recommendation=rec,
        refs=REFS,
        flagged_items=flagged_items,
    )
