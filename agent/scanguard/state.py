"""Persistent state: which IPs were already blocked, plus append-only stats log."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Set


class StateStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.banned_file = self.dir / "banned.json"
        self.stats_file = self.dir / "stats.jsonl"
        self.notify_file = self.dir / "notify.txt"

    def load_banned(self) -> Dict[str, Any]:
        if self.banned_file.exists():
            try:
                return json.loads(self.banned_file.read_text())
            except Exception:
                return {}
        return {}

    def save_banned(self, banned: Dict[str, Any]) -> None:
        self.banned_file.write_text(json.dumps(banned, indent=2, sort_keys=True))

    def blocked_ips(self) -> Set[str]:
        return set(self.load_banned().keys())

    def mark_blocked(self, ip: str, meta: Dict[str, Any]) -> None:
        banned = self.load_banned()
        banned[ip] = {"blocked_at": datetime.now(timezone.utc).isoformat(), **meta}
        self.save_banned(banned)

    def append_stats(self, record: Dict[str, Any]) -> None:
        with self.stats_file.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def append_notify(self, text: str) -> None:
        with self.notify_file.open("a") as f:
            f.write(text + "\n")

    def read_notify(self, truncate: bool = False) -> str:
        text = self.notify_file.read_text() if self.notify_file.exists() else ""
        if truncate and self.notify_file.exists():
            self.notify_file.write_text("")
        return text
