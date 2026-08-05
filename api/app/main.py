"""FastAPI application: ingest, aggregate, search, and blocklist endpoints."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .db import Database, get_db
from .models import IngestBatch, ReportIn
from .aggregator import aggregate
from .blocklist import render_blocklist


API_TOKEN = os.environ.get("SCANGUARD_API_TOKEN", "")   # required for /report if set
WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"


app = FastAPI(title="ScanGuard Central Threat Intel API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def auth(authorization: str | None = Header(default=None)) -> None:
    if not API_TOKEN:
        return  # open mode (self-hosted)
    if not authorization or authorization.removeprefix("Bearer ").strip() != API_TOKEN:
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


# ── Ingest ────────────────────────────────────────────────────────────
@app.post("/api/report", dependencies=[Depends(auth)])
def report(payload: ReportIn, db: Database = Depends(get_db)):
    db.insert_report(payload)
    return {"ok": True}


@app.post("/api/report/batch", dependencies=[Depends(auth)])
def report_batch(batch: IngestBatch, db: Database = Depends(get_db)):
    n = 0
    for r in batch.reports:
        db.insert_report(r)
        n += 1
    return {"ok": True, "inserted": n}


# ── Query ─────────────────────────────────────────────────────────────
@app.get("/api/threats")
def list_threats(
    limit: int = Query(100, le=1000),
    offset: int = 0,
    severity: str | None = None,
    country: str | None = None,
    q: str | None = None,
    db: Database = Depends(get_db),
):
    return db.list_threats(limit=limit, offset=offset, severity=severity, country=country, q=q)


@app.get("/api/threats/{ip}")
def threat_detail(ip: str, db: Database = Depends(get_db)):
    t = db.get_threat(ip)
    if not t:
        raise HTTPException(404, "IP not found")
    t["events"] = db.get_events(ip)
    t["nodes"] = db.get_nodes(ip)
    return t


@app.get("/api/stats")
def stats(db: Database = Depends(get_db)):
    return db.stats()


# ── Blocklist subscription ────────────────────────────────────────────
@app.get("/blocklist.txt", response_class=PlainTextResponse)
def blocklist_txt(
    min_severity: str = "medium",
    limit: int = 10000,
    db: Database = Depends(get_db),
):
    return render_blocklist(db, fmt="txt", min_severity=min_severity, limit=limit)


@app.get("/blocklist.iptables", response_class=PlainTextResponse)
def blocklist_iptables(
    min_severity: str = "medium",
    limit: int = 10000,
    db: Database = Depends(get_db),
):
    return render_blocklist(db, fmt="iptables", min_severity=min_severity, limit=limit)


@app.get("/blocklist.nftables", response_class=PlainTextResponse)
def blocklist_nftables(
    min_severity: str = "medium",
    limit: int = 10000,
    db: Database = Depends(get_db),
):
    return render_blocklist(db, fmt="nftables", min_severity=min_severity, limit=limit)


# ── Web UI (static) ───────────────────────────────────────────────────
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
