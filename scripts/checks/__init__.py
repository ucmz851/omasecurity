"""OmaSecurity check result contract (schemaVersion 2).

Per-check result fields (make_result validates and fills defaults):
  id            str
  category      str
  title         str
  passed        bool
  applicable    bool
  score         int
  max_score     int
  severity      "critical"|"high"|"medium"|"low"|"info"
                Always "info" when passed is true or applicable is false.
  description   str (one sentence)
  details       list[str] (short strings; may be empty)
  recommendation str|null
  fix_cmd       str|null
  refs          list[str] (URLs)
  flagged_items optional list (plugin scanner items; same shape as v1)
  lane          "fast"|"slow"
  duration_ms   int
  cached        optional bool (slow results served from cache)
  cachedAt      optional ISO 8601 timestamp (with timezone)
  pending       optional bool (slow check not collected yet)

Top-level runner output (do not add or rename these keys):
  schemaVersion    2
  tool             "omasecurity"
  version          str (from manifest.json)
  hostname         str
  timestamp        ISO 8601 with timezone
  timestampDisplay HH:MM:SS
  score            int 0-100
  grade            str
  statusLabel      str
  statusColor      str
  failedCount      int
  naCount          int
  totalChecks      int
  audits           list[result]
  errors           list[{"id": str, "error": str}]
  baselineDiff     null | {"regressed": [id], "improved": [id], "scoreDelta": int}

Scoring: round(100 * sum(score) / sum(max_score)) over applicable checks only.
A raising check becomes applicable=false, passed=false, is excluded from the
score, and is listed in errors.

Lanes: FAST_CHECKS always run. SLOW_CHECKS run only with --slow (results cached
under $XDG_CACHE_HOME/omasecurity for 7200s). The default invocation never
touches the network and must finish in under 150ms.

Registration: each check module appends callables to FAST_CHECKS or SLOW_CHECKS.
scripts/checks/registry.py imports those modules (one line each) so the runner
sees them. Other agents add a module plus one import line in registry.py.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

FAST_CHECKS = []
SLOW_CHECKS = []

_ALLOWED_SEVERITY = frozenset({"critical", "high", "medium", "low", "info"})
_ALLOWED_LANE = frozenset({"fast", "slow"})
_REQUIRED = ("id", "category", "title", "description", "max_score")
_KNOWN = frozenset({
    "id", "category", "title", "passed", "applicable", "score", "max_score",
    "severity", "description", "details", "recommendation", "fix_cmd", "refs",
    "flagged_items", "lane", "duration_ms", "cached", "cachedAt", "pending",
})


def register_check(registry, *, check_id, category, title, max_score, lane="fast"):
    """Attach metadata and append fn to FAST_CHECKS or SLOW_CHECKS."""

    def decorator(fn):
        fn.check_id = check_id
        fn.category = category
        fn.title = title
        fn.max_score = max_score
        fn.lane = lane
        if fn not in registry:
            registry.append(fn)
        return fn

    return decorator


def check_id_of(fn):
    return getattr(fn, "check_id", None) or getattr(fn, "__name__", "unknown")


def make_result(**fields):
    """Fill defaults, force severity=info when passed or N/A, and validate."""
    unknown = set(fields) - _KNOWN
    if unknown:
        raise ValueError("unknown result fields: " + ", ".join(sorted(unknown)))

    result = {
        "passed": True,
        "applicable": True,
        "score": 0,
        "severity": "info",
        "details": [],
        "recommendation": None,
        "fix_cmd": None,
        "refs": [],
        "lane": "fast",
        "duration_ms": 0,
    }
    result.update(fields)

    for key in _REQUIRED:
        if key not in result or result[key] in (None, ""):
            raise ValueError("missing result field: " + key)

    if result["passed"] or not result["applicable"]:
        result["severity"] = "info"
    if result["severity"] not in _ALLOWED_SEVERITY:
        raise ValueError("invalid severity: " + str(result["severity"]))
    if result["lane"] not in _ALLOWED_LANE:
        raise ValueError("invalid lane: " + str(result["lane"]))
    if not isinstance(result["details"], list):
        raise ValueError("details must be a list")
    if not isinstance(result["refs"], list):
        raise ValueError("refs must be a list")

    result["max_score"] = int(result["max_score"])
    result["score"] = int(result["score"])
    result["duration_ms"] = int(result["duration_ms"])
    result["passed"] = bool(result["passed"])
    result["applicable"] = bool(result["applicable"])

    if not result.get("pending"):
        result.pop("pending", None)
    if not result.get("cached"):
        result.pop("cached", None)
        result.pop("cachedAt", None)
    if result.get("flagged_items") is None:
        result.pop("flagged_items", None)

    return result


def run_cmd(argv, timeout=1.0):
    """Run argv (never sudo) and return a CompletedProcess. Missing binaries yield 127."""
    argv = list(argv)
    if not argv:
        raise ValueError("run_cmd requires a command")
    if any(os.path.basename(str(part)) == "sudo" for part in argv):
        raise ValueError("run_cmd refuses to invoke sudo")
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(argv, 127, stdout="", stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout
        stderr = exc.stderr
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return subprocess.CompletedProcess(
            argv, 124, stdout=stdout or "", stderr=stderr or "timeout"
        )


def read_text(path, default=None):
    """Read a text file; return default on any error (including missing/unreadable)."""
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return default
