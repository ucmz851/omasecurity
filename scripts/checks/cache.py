"""Slow-lane result cache under $XDG_CACHE_HOME/omasecurity (default ~/.cache/omasecurity)."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_MAX_AGE_S = 7200


def cache_dir():
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "omasecurity"


def _parse_iso(value):
    if not value:
        raise ValueError("empty timestamp")
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _path_for(check_id):
    safe = _SAFE_ID.sub("_", check_id).strip("._") or "check"
    return cache_dir() / (safe + ".json")


def write_cached(check_id, result):
    """Write result plus written_at as mode 0600 JSON."""
    directory = cache_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = _path_for(check_id)
    payload = {
        "written_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        raise
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle)
    return path


def read_cached(check_id, max_age_s=DEFAULT_MAX_AGE_S):
    """Return a result dict with cached/cachedAt set, or None if missing/stale."""
    path = _path_for(check_id)
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return None
    written_at = payload.get("written_at")
    result = payload.get("result")
    if not isinstance(result, dict) or not written_at:
        return None
    try:
        written = _parse_iso(written_at)
    except Exception:
        return None
    age = datetime.now(timezone.utc) - written.astimezone(timezone.utc)
    if age > timedelta(seconds=int(max_age_s)) or age < timedelta(0):
        return None
    out = dict(result)
    out["cached"] = True
    out["cachedAt"] = written.isoformat()
    out.pop("pending", None)
    return out
