"""SQLite persistence. De-duplicates on IP and aggregates events per node."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ReportIn

SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    severity TEXT NOT NULL,
    max_severity TEXT NOT NULL,
    total_hits INTEGER DEFAULT 0,
    report_count INTEGER DEFAULT 0,
    distinct_nodes INTEGER DEFAULT 1,
    country TEXT,
    city TEXT,
    isp TEXT,
    org TEXT,
    asn TEXT,
    rules TEXT,           -- JSON array
    evidence TEXT         -- JSON array
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    node_id TEXT,
    node_name TEXT,
    rule TEXT,
    severity TEXT,
    hit_count INTEGER,
    source TEXT,
    evidence TEXT,
    ts TEXT NOT NULL,
    FOREIGN KEY(ip) REFERENCES threats(ip)
);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT,
    ip TEXT,
    node_name TEXT,
    last_seen TEXT,
    count INTEGER DEFAULT 1,
    PRIMARY KEY (node_id, ip)
);
"""

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

import os as _os
_DB_PATH = Path(_os.environ.get("SCANGUARD_DB", "/var/lib/scanguard-api/threats.db"))
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_db_instance: "Database | None" = None


def get_db() -> "Database":
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(_DB_PATH)
    return _db_instance


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── writes ───────────────────────────────────────────────────────
    def insert_report(self, r: ReportIn) -> None:
        ts = (r.timestamp or datetime.now(timezone.utc)).isoformat()
        geo = r.geo or {}
        with self._conn() as c:
            row = c.execute("SELECT * FROM threats WHERE ip=?", (r.ip,)).fetchone()
            if row:
                rules = set(json.loads(row["rules"] or "[]"))
                rules.add(r.rule)
                evidence = json.loads(row["evidence"] or "[]")
                evidence = (evidence + r.evidence)[:50]
                new_max = max(row["max_severity"], r.severity,
                              key=lambda s: SEV_RANK.get(s, 0))
                c.execute("""UPDATE threats SET last_seen=?, severity=?, max_severity=?,
                             total_hits=total_hits+?, report_count=report_count+1,
                             country=COALESCE(?, country), city=COALESCE(?, city),
                             isp=COALESCE(?, isp), org=COALESCE(?, org), asn=COALESCE(?, asn),
                             rules=?, evidence=? WHERE ip=?""",
                          (ts, r.severity, new_max, r.hit_count,
                           geo.get("country"), geo.get("city"), geo.get("isp"),
                           geo.get("org"), geo.get("as"),
                           json.dumps(sorted(rules)), json.dumps(evidence), r.ip))
            else:
                c.execute("""INSERT INTO threats
                    (ip, first_seen, last_seen, severity, max_severity, total_hits,
                     report_count, distinct_nodes, country, city, isp, org, asn, rules, evidence)
                    VALUES (?,?,?,?,?,?,1,1,?,?,?,?,?,?,?)""",
                          (r.ip, ts, ts, r.severity, r.severity, r.hit_count,
                           geo.get("country"), geo.get("city"), geo.get("isp"),
                           geo.get("org"), geo.get("as"),
                           json.dumps([r.rule]), json.dumps(r.evidence[:50])))

            c.execute("""INSERT INTO events (ip, node_id, node_name, rule, severity,
                         hit_count, source, evidence, ts)
                         VALUES (?,?,?,?,?,?,?,?,?)""",
                      (r.ip, r.node_id, r.node_name, r.rule, r.severity,
                       r.hit_count, r.source, json.dumps(r.evidence), ts))

            # nodes
            if r.node_id:
                existing = c.execute("SELECT count FROM nodes WHERE node_id=? AND ip=?",
                                     (r.node_id, r.ip)).fetchone()
                if existing:
                    c.execute("UPDATE nodes SET last_seen=?, count=count+1, node_name=? "
                              "WHERE node_id=? AND ip=?",
                              (ts, r.node_name, r.node_id, r.ip))
                else:
                    c.execute("INSERT INTO nodes (node_id, ip, node_name, last_seen, count) "
                              "VALUES (?,?,?,?,1)", (r.node_id, r.ip, r.node_name, ts))
                distinct = c.execute("SELECT COUNT(DISTINCT node_id) n FROM nodes WHERE ip=?",
                                     (r.ip,)).fetchone()["n"]
                c.execute("UPDATE threats SET distinct_nodes=? WHERE ip=?", (distinct, r.ip))

    # ── reads ────────────────────────────────────────────────────────
    def list_threats(self, limit=100, offset=0, severity=None, country=None, q=None):
        sql = "SELECT * FROM threats WHERE 1=1"
        args: list[Any] = []
        if severity:
            sql += " AND max_severity=?"; args.append(severity)
        if country:
            sql += " AND country=?"; args.append(country)
        if q:
            sql += " AND (ip LIKE ? OR isp LIKE ? OR org LIKE ?)"
            args += [f"%{q}%", f"%{q}%", f"%{q}%"]
        sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        for r in rows:
            r["rules"] = json.loads(r.get("rules") or "[]")
            r["evidence"] = json.loads(r.get("evidence") or "[]")
        return rows

    def get_threat(self, ip: str):
        with self._conn() as c:
            row = c.execute("SELECT * FROM threats WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else None

    def get_events(self, ip: str, limit=100):
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT node_id,node_name,rule,severity,hit_count,source,ts FROM events "
                "WHERE ip=? ORDER BY ts DESC LIMIT ?", (ip, limit)).fetchall()]
        return rows

    def get_nodes(self, ip: str):
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT node_id,node_name,last_seen,count FROM nodes WHERE ip=?",
                (ip,)).fetchall()]

    def stats(self):
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM threats").fetchone()["n"]
            by_sev = {r["max_severity"]: r["n"] for r in
                      c.execute("SELECT max_severity, COUNT(*) n FROM threats GROUP BY max_severity")}
            by_country = {r["country"] or "Unknown": r["n"] for r in
                          c.execute("SELECT country, COUNT(*) n FROM threats "
                                    "GROUP BY country ORDER BY n DESC LIMIT 15")}
            nodes = c.execute("SELECT COUNT(DISTINCT node_id) n FROM nodes").fetchone()["n"]
            events = c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
            recent = c.execute("SELECT COUNT(*) n FROM events WHERE ts > ?",
                               ((datetime.now(timezone.utc)).isoformat(),)).fetchone()["n"]
        return {"total_ips": total, "events": events, "nodes": nodes,
                "by_severity": by_sev, "by_country": by_country}

    def blocklist_ips(self, min_severity="medium", limit=10000):
        rank = SEV_RANK.get(min_severity, 2)
        with self._conn() as c:
            rows = c.execute(
                "SELECT ip, max_severity, total_hits, country, isp FROM threats "
                "ORDER BY total_hits DESC, last_seen DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            if SEV_RANK.get(r["max_severity"], 0) >= rank:
                out.append(dict(r))
        return out
