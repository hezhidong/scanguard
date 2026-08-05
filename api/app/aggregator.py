"""Threat aggregation helpers (kept simple here; aggregation mostly happens in DB)."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def aggregate(reports: Iterable[dict]) -> list[dict]:
    """Aggregate a batch of reports by IP. Useful for offline / pre-ingest."""
    by_ip: dict[str, dict] = defaultdict(lambda: {
        "rules": set(), "nodes": set(), "total_hits": 0, "evidence": []})
    for r in reports:
        ip = r["ip"]
        a = by_ip[ip]
        a["rules"].add(r.get("rule", "unknown"))
        if r.get("node_id"):
            a["nodes"].add(r["node_id"])
        a["total_hits"] += r.get("hit_count", 1)
        a["evidence"].extend(r.get("evidence", [])[:5])
    out = []
    for ip, a in by_ip.items():
        out.append({"ip": ip, "rules": sorted(a["rules"]),
                    "nodes": sorted(a["nodes"]),
                    "total_hits": a["total_hits"],
                    "evidence": a["evidence"][:20]})
    return out
