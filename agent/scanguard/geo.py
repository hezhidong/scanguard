"""IP geolocation (ip-api free batch endpoint, cached)."""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Dict, List

BATCH_URL = "http://ip-api.com/batch?fields=status,country,regionName,city,isp,org,as,query"


def lookup(ips: List[str], cache_path: Path, ttl_days: int = 7) -> Dict[str, dict]:
    cache: Dict[str, dict] = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text())
        except Exception:
            cache = {}
    # prune stale
    now = time.time()
    ttl_s = ttl_days * 86400
    cache = {k: v for k, v in cache.items() if now - v.get("_ts", 0) < ttl_s}

    missing = [ip for ip in set(ips) if ip not in cache]
    for i in range(0, len(missing), 100):
        batch = missing[i:i + 100]
        try:
            req = urllib.request.Request(
                BATCH_URL, data=json.dumps(batch).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                for item in json.loads(resp.read().decode()):
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        item["_ts"] = now
                        cache[ip] = item
                    else:
                        cache[ip] = {"_ts": now, "country": "Unknown", "error": item.get("message")}
        except Exception as e:
            for ip in batch:
                cache.setdefault(ip, {"_ts": now, "country": "Unknown", "error": str(e)})
        time.sleep(1.5)  # respect ip-api 15 req/min on batch

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True))
    return cache
