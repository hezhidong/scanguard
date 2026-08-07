#!/usr/bin/env python3
"""Aggregate reports/*.jsonl into public blocklists + stats.json + threats.json.

Designed to run inside GitHub Actions (no third-party deps). It writes:
  - blocklist.txt / .iptables / .nftables
  - stats.json    (top counters for the web dashboard)
  - threats.json  (array of aggregated IPs for the searchable table)
  - index.html    (copied from web/index.html so GitHub Pages can serve from /)

Reports are append-only jsonl files written by each agent node:
  {"ts": "...", "ip": "...", "rule": "...", "severity": "...", "hits": N,
   "country": "...", "node_id": "...", "node_name": "...", ...}
"""
from __future__ import annotations

import glob
import json
import os
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
WEB = ROOT / "web"
OUT = ROOT  # Pages serves from repo root

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def load_events():
    events = []
    if not REPORTS.exists():
        return events
    for f in sorted(REPORTS.glob("*.jsonl")):
        node_from_file = f.stem
        for ln in f.read_text(errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if not e.get("ip"):
                continue
            e.setdefault("node_id", node_from_file)
            events.append(e)
    return events


def aggregate(events, min_severity_rank=3, per_ip_event_cap=20):
    by_ip = {}
    nodes = set()
    sev_counter = Counter()
    country_counter = Counter()
    rule_counter = Counter()

    for e in events:
        ip = e["ip"]
        sev = e.get("severity", "medium").lower()
        rank = SEV_RANK.get(sev, 2)
        ts = e.get("ts") or ""
        node = e.get("node_id") or ""
        source = (e.get("source") or e.get("source_kind") or "").lower()
        is_community = source == "community"
        if node:
            nodes.add(node)

        rec = by_ip.get(ip)
        if rec is None:
            rec = {
                "ip": ip,
                "max_severity": sev,
                "max_sev_rank": rank,
                "total_hits": 0,
                "distinct_nodes": 0,
                "rules": set(),
                "rule_hits": Counter(),
                "nodes": set(),
                "community_nodes": set(),
                "has_trusted_report": False,
                "first_seen": ts,
                "last_seen": ts,
                "country": e.get("country", ""),
                "city": e.get("city", ""),
                "isp": e.get("isp", ""),
                "org": e.get("org", ""),
                "events": [],
            }
            by_ip[ip] = rec

        rec["total_hits"] += int(e.get("hits", 1))
        rec["rules"].add(e.get("rule", ""))
        rec["rule_hits"][e.get("rule", "")] += int(e.get("hits", 1))
        if node:
            rec["nodes"].add(node)
            if is_community:
                rec["community_nodes"].add(node)
        if not is_community:
            rec["has_trusted_report"] = True
        if rank > rec["max_sev_rank"]:
            rec["max_sev_rank"] = rank
            rec["max_severity"] = sev
        if ts and ts > rec["last_seen"]:
            rec["last_seen"] = ts
            rec["country"] = e.get("country") or rec["country"]
            rec["city"] = e.get("city") or rec["city"]
            rec["isp"] = e.get("isp") or rec["isp"]
            rec["org"] = e.get("org") or rec["org"]
        if ts and (not rec["first_seen"] or ts < rec["first_seen"]):
            rec["first_seen"] = ts
        rec["events"].append({
            "ts": ts,
            "rule": e.get("rule", ""),
            "severity": sev,
            "hit_count": int(e.get("hits", 1)),
            "node_id": node,
            "node_name": e.get("node_name", ""),
            "source_kind": e.get("source_kind") or e.get("source", ""),
        })

    # finalize
    threats = []
    blocklist_ips = []
    pending_ips = []  # community-sourced, single-node (observation only)
    for ip, rec in by_ip.items():
        rec["distinct_nodes"] = len(rec["nodes"])
        rec["rules"] = sorted(r for r in rec["rules"] if r)
        rec["nodes"] = sorted(rec["nodes"])
        rec["events"].sort(key=lambda x: x["ts"], reverse=True)
        rec["events"] = rec["events"][:per_ip_event_cap]
        sev_counter[rec["max_severity"]] += 1
        if rec["country"]:
            country_counter[rec["country"]] += 1
        for r in rec["rules"]:
            rule_counter[r] += 1

        # Blocklist eligibility:
        #   - any report from a trusted (non-community) source, OR
        #   - severity >= high AND at least 2 distinct community nodes
        # Single-node community reports stay in threats.json but are NOT
        # added to the public blocklist (anti-poisoning).
        community_confirmed = len(rec["community_nodes"]) >= 2
        eligible = rec["has_trusted_report"] or community_confirmed

        threats.append({
            "ip": ip,
            "max_severity": rec["max_severity"],
            "total_hits": rec["total_hits"],
            "distinct_nodes": rec["distinct_nodes"],
            "community_nodes": len(rec["community_nodes"]),
            "trusted": rec["has_trusted_report"],
            "rules": rec["rules"],
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "country": rec["country"],
            "city": rec["city"],
            "isp": rec["isp"],
            "org": rec["org"],
            "events": rec["events"],
        })
        if rec["max_sev_rank"] >= min_severity_rank:
            if eligible:
                blocklist_ips.append((ip, rec["country"], rec["isp"]))
            else:
                pending_ips.append((ip, rec["country"], rec["isp"]))

    threats.sort(key=lambda x: (SEV_RANK.get(x["max_severity"], 0),
                                x["total_hits"]), reverse=True)
    blocklist_ips.sort(key=lambda x: socket_sort_key(x[0]))

    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_ips": len(by_ip),
        "events": len(events),
        "nodes": len(nodes),
        "node_ids": sorted(nodes),
        "blocklist_count": len(blocklist_ips),
        "pending_count": len(pending_ips),
        "by_severity": {
            "critical": sev_counter.get("critical", 0),
            "high": sev_counter.get("high", 0),
            "medium": sev_counter.get("medium", 0),
            "low": sev_counter.get("low", 0),
        },
        "top_countries": country_counter.most_common(10),
        "top_rules": rule_counter.most_common(10),
    }
    return threats, blocklist_ips, stats


def socket_sort_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def write_blocklists(blocklist_ips, stats, min_severity="high"):
    ts = stats["generated_at"]
    count = len(blocklist_ips)

    txt = [
        "# ScanGuard community blocklist",
        f"# Generated: {ts}",
        f"# Min severity: {min_severity}",
        f"# Entries: {count}",
        "# Source: https://github.com/hezhidong/scanguard",
        "",
    ]
    txt.extend(ip for ip, _, _ in blocklist_ips)
    (OUT / "blocklist.txt").write_text("\n".join(txt) + "\n")

    ipt = ["*filter"]
    for ip, country, isp in blocklist_ips:
        note = " ".join(x for x in (country, isp) if x)
        ipt.append(f"-A INPUT -s {ip} -j DROP  # {note}".rstrip())
    ipt.append("COMMIT")
    header = [
        "# ScanGuard blocklist (iptables-restore format)",
        f"# Generated: {ts}",
        f"# Entries: {count}",
        "",
    ]
    (OUT / "blocklist.iptables").write_text("\n".join(header + ipt) + "\n")

    if blocklist_ips:
        elems = ", ".join(ip for ip, _, _ in blocklist_ips)
    else:
        elems = ""
    nft = f"""# ScanGuard blocklist (nftables format)
# Generated: {ts}
# Entries: {count}
table inet scanguard {{
  set blocklist {{
    type ipv4_addr
    flags interval
    elements = {{ {elems} }}
  }}
  chain input {{
    type filter hook input priority 0; ip saddr @blocklist drop
  }}
}}
"""
    (OUT / "blocklist.nftables").write_text(nft)


def main():
    events = load_events()
    threats, blocklist_ips, stats = aggregate(events)

    (OUT / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))
    # threats.json is consumed by the dashboard; keep it compact-ish
    (OUT / "threats.json").write_text(json.dumps(threats, ensure_ascii=False))

    write_blocklists(blocklist_ips, stats)

    # Copy web UI to repo root so GitHub Pages serves it at /
    if WEB.exists():
        for item in WEB.iterdir():
            if item.is_file():
                shutil.copy2(item, OUT / item.name)

    print(f"Aggregated {len(events)} events → {len(threats)} IPs "
          f"({len(blocklist_ips)} in blocklist, {stats['pending_count']} pending) "
          f"across {stats['nodes']} node(s)")


if __name__ == "__main__":
    main()
