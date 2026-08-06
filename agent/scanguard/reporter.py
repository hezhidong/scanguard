"""Report blocked IPs to a Central Threat Intel API or a GitHub repository.

Two backends:
  - http:   POST {url}/api/report (legacy FastAPI central)
  - github: append to reports/<node_id>.jsonl via the GitHub Contents API
            (the public repo acts as both database and blocklist host; a
            GitHub Actions workflow aggregates reports/* into blocklist + stats)
"""
from __future__ import annotations

import base64
import json
import platform
import urllib.request
from datetime import datetime, timezone
from typing import Iterable, Optional

from .config import CentralConfig

GITHUB_API = "https://api.github.com"


# ── HTTP backend (legacy) ────────────────────────────────────────────

def report(cfg: CentralConfig, ip: str, rule: str, severity: str, count: int,
           evidence: list, source: str = "", geo: Optional[dict] = None) -> bool:
    if not cfg.enabled or cfg.backend != "http" or not cfg.url:
        return False
    payload = {
        "ip": ip,
        "rule": rule,
        "severity": severity,
        "hit_count": count,
        "evidence": evidence or [],
        "source": source,
        "node_id": cfg.node_id or platform.node(),
        "node_name": cfg.node_name or platform.node(),
        "geo": geo or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if cfg.token:
        headers["Authorization"] = f"Bearer {cfg.token}"
    req = urllib.request.Request(cfg.url.rstrip("/") + "/api/report", data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


# ── GitHub backend ───────────────────────────────────────────────────

def _sanitize_event(ip: str, rule: str, severity: str, count: int,
                    source: str, geo: Optional[dict], node_id: str,
                    node_name: str, max_lines: int = 2000) -> dict:
    """Return a public-safe event dict (no full URLs / evidence / hostnames)."""
    g = geo or {}
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": ip,
        "rule": rule,
        "severity": severity,
        "hits": int(count),
        "country": g.get("country") or "",
        "city": g.get("city") or "",
        "isp": g.get("isp") or "",
        "org": g.get("org") or "",
        "node_id": node_id,
        "node_name": node_name,
        "source_kind": source or "",
    }


def _gh_request(method: str, path: str, token: str, body: Optional[dict] = None) -> tuple:
    url = path if path.startswith("http") else GITHUB_API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}


def report_github(cfg: CentralConfig, events: Iterable[dict]) -> bool:
    """Append a batch of events to the node's jsonl file in the repo.

    `events` is an iterable of sanitized event dicts (as produced by
    _sanitize_event). Returns True if the commit succeeded.
    """
    if not cfg.enabled or cfg.backend != "github" or not cfg.token or not cfg.repo:
        return False

    events = [e for e in events if e]
    if not events:
        return True

    node_id = cfg.node_id or platform.node()
    node_name = cfg.node_name or node_id
    path = cfg.reports_path or f"reports/{node_id}.jsonl"
    branch = cfg.branch or "master"

    # 1. Read existing file (may be 404 on first run)
    status, existing = _gh_request(
        "GET",
        f"/repos/{cfg.repo}/contents/{path}?ref={branch}",
        cfg.token,
    )
    sha = None
    old_lines: list[str] = []
    if status == 200:
        sha = existing.get("sha")
        try:
            raw = base64.b64decode(existing.get("content", "")).decode()
            old_lines = [ln for ln in raw.splitlines() if ln.strip()]
        except Exception:
            old_lines = []
    elif status == 404:
        pass
    else:
        return False

    # 2. Append new events, keep file bounded (last max_lines)
    new_lines = [json.dumps(e, ensure_ascii=False, sort_keys=True) for e in events]
    all_lines = (old_lines + new_lines)[-cfg.max_lines:]
    content_b64 = base64.b64encode(("\n".join(all_lines) + "\n").encode()).decode()

    # 3. PUT back (upsert)
    commit_msg = f"report: +{len(new_lines)} event(s) from {node_name}"
    body = {"message": commit_msg, "content": content_b64, "branch": branch}
    if sha:
        body["sha"] = sha
    status, _ = _gh_request(
        "PUT", f"/repos/{cfg.repo}/contents/{path}", cfg.token, body=body,
    )
    return 200 <= status < 300
