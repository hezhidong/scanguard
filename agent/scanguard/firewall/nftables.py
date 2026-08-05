"""nftables backend — adds an element to a scanguard set (create it if missing)."""
from __future__ import annotations

from .base import FirewallBackend, BlockResult

SET_NAME = "scanguard_blocklist"
TABLE = "inet"
TABLE_NAME = "filter"


class NftablesBackend(FirewallBackend):
    name = "nftables"

    def _ensure_set(self) -> None:
        # Create table + set if absent. `add rule` is idempotent-ish; use -- checks in bash.
        cmd = self._sudo([
            "bash", "-c",
            f"nft list table {TABLE} {TABLE_NAME} >/dev/null 2>&1 || "
            f"nft create table {TABLE} {TABLE_NAME}; "
            f"nft list set {TABLE} {TABLE_NAME} {SET_NAME} >/dev/null 2>&1 || "
            f"nft add set {TABLE} {TABLE_NAME} {SET_NAME} '{{ type ipv4_addr; flags interval; }}'; "
            f"nft list chain {TABLE} {TABLE_NAME} input >/dev/null 2>&1 || "
            f"nft add chain {TABLE} {TABLE_NAME} input '{{ type filter hook input priority 0; }}'; "
            f"nft add rule {TABLE} {TABLE_NAME} input ip saddr @{SET_NAME} {self.cfg.policy}",
        ])
        self._run(cmd)

    def is_blocked(self, ip: str) -> bool:
        cmd = self._sudo(["nft", "get", "element", TABLE, TABLE_NAME, SET_NAME, f"{{ {ip} }}"])
        r = self._run(cmd)
        return r.returncode == 0

    def block(self, ip: str, reason: str = "") -> BlockResult:
        result = BlockResult(ip=ip, blocked=False, backend=self.name, remote=bool(self.cfg.host))
        self._ensure_set()
        if self.is_blocked(ip):
            result.already_blocked = True
            result.blocked = True
            return result
        cmd = self._sudo(["nft", "add", "element", TABLE, TABLE_NAME, SET_NAME, f"{{ {ip} }}"])
        result.command = " ".join(cmd)
        r = self._run(cmd)
        if r.returncode != 0:
            result.error = (r.stderr or r.stdout or "nft failed").strip()
            return result
        result.blocked = True
        if self.cfg.persistent:
            result.output = self.persist() or ""
        return result

    def persist(self) -> str | None:
        # nftables persists via /etc/nftables.conf on most distros (enabled service)
        r = self._run(self._sudo(["bash", "-c", "nft list ruleset > /etc/nftables.conf"]))
        return "persisted to /etc/nftables.conf" if r.returncode == 0 else None
