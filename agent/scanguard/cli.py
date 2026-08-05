"""ScanGuard Agent CLI entry point."""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import AgentConfig
from .detector import scan
from .firewall import get_backend
from .geo import lookup as geo_lookup
from .reporter import report as central_report
from .state import StateStore


def run(config: AgentConfig) -> dict:
    state = StateStore(config.state_dir)
    already = state.blocked_ips()

    print(f"[scanguard] scanning {len(config.log_sources)} source(s)...", file=sys.stderr)
    hits = scan(config)
    print(f"[scanguard] {len(hits)} offender(s) over threshold", file=sys.stderr)

    backend = get_backend(config.firewall.backend, config.firewall)
    geo_cache = config.state_dir / "geo-cache.json"

    results = []
    new_blocked = []
    for hit in hits:
        if hit.ip in already:
            results.append({"ip": hit.ip, "rule": hit.rule, "status": "already-blocked"})
            continue

        geo = {}
        if config.geo_provider != "none":
            g = geo_lookup([hit.ip], geo_cache, config.geo_cache_ttl_days)
            geo = g.get(hit.ip, {})

        if config.dry_run:
            print(f"[dry-run] would block {hit.ip} ({hit.rule}, {hit.count} hits)", file=sys.stderr)
            results.append({"ip": hit.ip, "rule": hit.rule, "status": "would-block",
                            "count": hit.count, "geo": geo})
            continue

        br = backend.block(hit.ip, reason=hit.rule)
        status = "blocked" if br.blocked else "failed"
        if br.blocked:
            state.mark_blocked(hit.ip, {
                "rule": hit.rule, "severity": hit.severity, "count": hit.count,
                "source": hit.source, "evidence": hit.evidence,
                "backend": config.firewall.backend,
                "geo": {k: geo.get(k) for k in ("country", "city", "isp", "org")},
            })
            new_blocked.append((hit, geo, br))
            if config.central.enabled:
                central_report(config.central, hit.ip, hit.rule, hit.severity,
                               hit.count, hit.evidence, hit.source, geo)
        results.append({"ip": hit.ip, "rule": hit.rule, "status": status,
                        "already": br.already_blocked, "error": br.error,
                        "count": hit.count, "geo": geo})

    # notify
    if new_blocked and config.notify_file:
        nf = Path(config.notify_file)
        with nf.open("a") as f:
            for hit, geo, br in new_blocked:
                country = geo.get("country", "?")
                isp = geo.get("isp", "?")
                f.write(f"🚫 ScanGuard blocked {hit.ip} [{country}/{isp}] "
                        f"rule={hit.rule} hits={hit.count}\n")

    state.append_stats({
        "ts": datetime.now(timezone.utc).isoformat(),
        "node": platform.node(),
        "hits": len(hits),
        "new_blocked": len(new_blocked),
        "results": results,
    })

    return {"hits": len(hits), "new_blocked": len(new_blocked), "results": results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scanguard", description="ScanGuard Agent")
    ap.add_argument("-c", "--config", default="/etc/scanguard/config.yaml",
                    help="path to config (YAML or JSON)")
    ap.add_argument("--dry-run", action="store_true", help="detect only, do not block")
    ap.add_argument("--print", action="store_true", help="print JSON result to stdout")
    ap.add_argument("--notify", action="store_true",
                    help="print pending notifications and truncate the notify file")
    ap.add_argument("--version", action="version", version=f"scanguard {__version__}")
    args = ap.parse_args(argv)

    if args.notify:
        cfg_path = Path(args.config)
        # we only need state_dir; fall back to default if config missing
        state_dir = Path("/var/lib/scanguard")
        if cfg_path.exists():
            try:
                state_dir = AgentConfig.load(cfg_path).state_dir
            except Exception:
                pass
        state = StateStore(state_dir)
        print(state.read_notify(truncate=True), end="")
        return 0

    config = AgentConfig.load(args.config)
    if args.dry_run:
        config.dry_run = True
    result = run(config)
    if args.print or args.dry_run:
        print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
