"""Render blocklists in plain / iptables / nftables formats."""
from __future__ import annotations

from datetime import datetime, timezone


def render_blocklist(db, fmt="txt", min_severity="medium", limit=10000) -> str:
    ips = db.blocklist_ips(min_severity=min_severity, limit=limit)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = (f"# ScanGuard blocklist\n"
              f"# Generated: {ts}\n"
              f"# Min severity: {min_severity}\n"
              f"# Entries: {len(ips)}\n"
              f"# Format: {fmt}\n\n")

    if fmt == "txt":
        body = "\n".join(i["ip"] for i in ips) + "\n"
    elif fmt == "iptables":
        lines = ["*filter"]
        for i in ips:
            lines.append(f"-A INPUT -s {i['ip']} -j DROP  "
                         f"# {i.get('country') or ''} {i.get('isp') or ''}")
        lines.append("COMMIT")
        body = "\n".join(lines) + "\n"
    elif fmt == "nftables":
        elems = ", ".join(i["ip"] for i in ips)
        body = (f"table inet scanguard {{\n"
                f"  set blocklist {{\n"
                f"    type ipv4_addr\n"
                f"    flags interval\n"
                f"    elements = {{ {elems} }}\n"
                f"  }}\n"
                f"  chain input {{ type filter hook input priority 0; "
                f"ip saddr @blocklist drop }}\n"
                f"}}\n")
    else:
        body = ""
    return header + body
