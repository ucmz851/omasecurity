#!/usr/bin/env python3
"""OmaSecurity audit runner: parse args, run checks, score, print JSON or text."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from checks import (  # noqa: E402
    FAST_CHECKS,
    SLOW_CHECKS,
    check_id_of,
    make_result,
)
from checks.cache import read_cached, write_cached  # noqa: E402
import checks.registry  # noqa: E402,F401


def load_version():
    path = Path(__file__).resolve().parent.parent / "manifest.json"
    try:
        return str(json.loads(path.read_text())["version"])
    except Exception:
        return "0.0.0"


def parse_id_list(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="OmaSecurity audit engine")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    parser.add_argument("--only", type=parse_id_list, default=None)
    parser.add_argument("--skip", type=parse_id_list, default=None)
    parser.add_argument("--list", action="store_true", dest="list_checks")
    parser.add_argument("--slow", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--baseline", default=None)
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args(argv)


def grade_for(pct):
    if pct >= 90:
        return "A", "System Hardened", "good"
    if pct >= 75:
        return "B", "Good Security", "normal"
    if pct >= 60:
        return "C", "Warnings Detected", "warning"
    return "F", "Critical Action Required", "urgent"


def compute_score(audits):
    """round(100 * sum(score) / sum(max_score)) over applicable checks only."""
    scored = [a for a in audits if a.get("applicable")]
    total = sum(int(a.get("score", 0)) for a in scored)
    maximum = sum(int(a.get("max_score", 0)) for a in scored)
    if maximum <= 0:
        return 100
    return int(round(100 * total / maximum))


def selected(checks, only, skip):
    out = []
    only_set = set(only) if only else None
    skip_set = set(skip) if skip else set()
    for fn in checks:
        cid = check_id_of(fn)
        if only_set is not None and cid not in only_set:
            continue
        if cid in skip_set:
            continue
        out.append(fn)
    return out


def _execute(fn):
    cid = check_id_of(fn)
    started = time.perf_counter()
    try:
        result = fn()
        if not isinstance(result, dict):
            raise TypeError("check returned " + type(result).__name__)
        result = dict(result)
        result["duration_ms"] = int((time.perf_counter() - started) * 1000)
        result.setdefault("id", cid)
        result.setdefault("lane", getattr(fn, "lane", "fast"))
        return result, None
    except Exception as exc:
        duration = int((time.perf_counter() - started) * 1000)
        result = make_result(
            id=cid,
            category=getattr(fn, "category", "System"),
            title=getattr(fn, "title", cid),
            passed=False,
            applicable=False,
            score=0,
            max_score=int(getattr(fn, "max_score", 0) or 0),
            description="Check failed to run.",
            details=[str(exc)],
            lane=getattr(fn, "lane", "fast"),
            duration_ms=duration,
        )
        error = f"{type(exc).__name__}: {exc}"
        return result, error


def pending_placeholder(fn):
    cid = check_id_of(fn)
    return make_result(
        id=cid,
        category=getattr(fn, "category", "System"),
        title=getattr(fn, "title", cid),
        passed=False,
        applicable=False,
        score=0,
        max_score=int(getattr(fn, "max_score", 0) or 0),
        description="Not collected yet; runs in the background hourly",
        pending=True,
        lane="slow",
    )


def collect_results(
    *,
    run_slow=False,
    use_cache=True,
    only=None,
    skip=None,
    fast_checks=None,
    slow_checks=None,
):
    audits = []
    errors = []
    fast_checks = FAST_CHECKS if fast_checks is None else fast_checks
    slow_checks = SLOW_CHECKS if slow_checks is None else slow_checks

    for fn in selected(fast_checks, only, skip):
        result, error = _execute(fn)
        result["lane"] = "fast"
        audits.append(result)
        if error:
            errors.append({"id": result["id"], "error": error})

    for fn in selected(slow_checks, only, skip):
        cid = check_id_of(fn)
        if run_slow:
            result, error = _execute(fn)
            result["lane"] = "slow"
            audits.append(result)
            if error:
                errors.append({"id": cid, "error": error})
            else:
                try:
                    write_cached(cid, result)
                except Exception:
                    traceback.print_exc(file=sys.stderr)
            continue
        cached = read_cached(cid) if use_cache else None
        if cached:
            cached["lane"] = "slow"
            audits.append(cached)
        else:
            audits.append(pending_placeholder(fn))

    return audits, errors


def build_baseline_diff(audits, previous_doc, current_score):
    prev_by_id = {a.get("id"): a for a in previous_doc.get("audits", []) if a.get("id")}
    regressed = []
    improved = []
    for audit in audits:
        cid = audit.get("id")
        prev = prev_by_id.get(cid)
        if not prev:
            continue
        curr_applicable = bool(audit.get("applicable"))
        prev_applicable = bool(prev.get("applicable", True))
        curr_fail = curr_applicable and not audit.get("passed")
        prev_fail = prev_applicable and not prev.get("passed", True)
        prev_pass = prev_applicable and prev.get("passed")
        curr_pass = curr_applicable and audit.get("passed")
        if prev_pass and curr_fail:
            regressed.append(cid)
        if prev_fail and curr_pass:
            improved.append(cid)
    return {
        "regressed": regressed,
        "improved": improved,
        "scoreDelta": int(current_score) - int(previous_doc.get("score", 0)),
    }


def build_output(audits, errors, *, version, baseline_diff=None):
    pct = compute_score(audits)
    grade, status_label, status_color = grade_for(pct)
    failed_count = sum(
        1 for a in audits if a.get("applicable") and not a.get("passed")
    )
    na_count = sum(1 for a in audits if not a.get("applicable"))
    now = datetime.now().astimezone()
    return {
        "schemaVersion": 2,
        "tool": "omasecurity",
        "version": version,
        "hostname": socket.gethostname(),
        "timestamp": now.isoformat(),
        "timestampDisplay": now.strftime("%H:%M:%S"),
        "score": pct,
        "grade": grade,
        "statusLabel": status_label,
        "statusColor": status_color,
        "failedCount": failed_count,
        "naCount": na_count,
        "totalChecks": len(audits),
        "audits": audits,
        "errors": errors,
        "baselineDiff": baseline_diff,
    }


def format_text(output):
    lines = [
        (
            f"OmaSecurity {output['version']}  score={output['score']}  "
            f"grade={output['grade']}  {output['statusLabel']}"
        ),
        (
            f"{output['hostname']}  {output['timestampDisplay']}  "
            f"checks={output['totalChecks']}  failed={output['failedCount']}  "
            f"n/a={output['naCount']}"
        ),
        "",
    ]
    for audit in output["audits"]:
        if not audit.get("applicable"):
            status = "N/A "
        elif audit.get("passed"):
            status = "PASS"
        else:
            status = "FAIL"
        score = f"{audit.get('score', 0)}/{audit.get('max_score', 0)}"
        lines.append(
            f"{status}  {audit.get('id', ''):<20} "
            f"{audit.get('category', ''):<20} "
            f"{audit.get('lane', 'fast'):<4} "
            f"{score:>7}  {audit.get('description', '')}"
        )
    if output.get("errors"):
        lines.append("")
        lines.append("Errors:")
        for item in output["errors"]:
            lines.append(f"  {item.get('id')}: {item.get('error')}")
    if output.get("baselineDiff"):
        diff = output["baselineDiff"]
        lines.append("")
        lines.append(
            f"baseline  delta={diff.get('scoreDelta')}  "
            f"regressed={','.join(diff.get('regressed') or []) or 'none'}  "
            f"improved={','.join(diff.get('improved') or []) or 'none'}"
        )
    return "\n".join(lines) + "\n"


def list_checks_text(fast_checks=None, slow_checks=None):
    fast_checks = FAST_CHECKS if fast_checks is None else fast_checks
    slow_checks = SLOW_CHECKS if slow_checks is None else slow_checks
    lines = [f"{'id':<20} {'category':<20} {'lane':<6} max_score"]
    for fn, lane in [(fn, "fast") for fn in fast_checks] + [(fn, "slow") for fn in slow_checks]:
        lines.append(
            f"{check_id_of(fn):<20} "
            f"{getattr(fn, 'category', ''):<20} "
            f"{lane:<6} {getattr(fn, 'max_score', 0)}"
        )
    return "\n".join(lines) + "\n"


def strict_exit_code(output):
    if output.get("errors"):
        return 2
    if any(a.get("applicable") and not a.get("passed") for a in output.get("audits", [])):
        return 1
    diff = output.get("baselineDiff")
    if diff and diff.get("regressed"):
        return 1
    return 0


def main(argv=None, *, fast_checks=None, slow_checks=None):
    args = parse_args(argv)
    if args.list_checks:
        sys.stdout.write(list_checks_text(fast_checks, slow_checks))
        return 0

    audits, errors = collect_results(
        run_slow=args.slow,
        use_cache=not args.no_cache,
        only=args.only,
        skip=args.skip,
        fast_checks=fast_checks,
        slow_checks=slow_checks,
    )
    version = load_version()
    baseline_diff = None
    score = compute_score(audits)
    if args.baseline:
        try:
            previous = json.loads(Path(args.baseline).read_text())
            baseline_diff = build_baseline_diff(audits, previous, score)
        except Exception as exc:
            errors.append({"id": "baseline", "error": f"{type(exc).__name__}: {exc}"})

    output = build_output(audits, errors, version=version, baseline_diff=baseline_diff)
    if args.format == "text":
        sys.stdout.write(format_text(output))
    else:
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")

    if args.strict:
        return strict_exit_code(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
