"""Report blocked IPs to a Central Threat Intel API."""
from __future__ import annotations

import json
import platform
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from .config import CentralConfig


def report(cfg: CentralConfig, ip: str, rule: str, severity: str, count: int,
           evidence: list, source: str = "", geo: Optional[dict] = None) -> bool:
    if not cfg.enabled or not cfg.url:
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
