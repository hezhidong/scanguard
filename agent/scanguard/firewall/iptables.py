"""iptables backend — inserts a DROP/REJECT rule and can persist via iptables-persistent."""
from __future__ import annotations

from .base import FirewallBackend, BlockResult


class IptablesBackend(FirewallBackend):
    name = "iptables"

    def _ipt(self) -> str:
        # iptables binary; allow override via env
        import shutil
        return shutil.which("iptables") or "/sbin/iptables"

    def is_blocked(self, ip: str) -> bool:
        cmd = self._sudo([self._ipt(), "-C", self.cfg.chain, "-s", ip, "-j", self.cfg.policy.upper()])
        r = self._run(cmd)
        return r.returncode == 0

    def block(self, ip: str, reason: str = "") -> BlockResult:
        result = BlockResult(ip=ip, blocked=False, backend=self.name, remote=bool(self.cfg.host))
        if self.is_blocked(ip):
            result.already_blocked = True
            result.blocked = True
            return result
        cmd = self._sudo([self._ipt(), "-I", self.cfg.chain, "1", "-s", ip,
                          "-j", self.cfg.policy.upper()])
        result.command = " ".join(cmd)
        r = self._run(cmd)
        if r.returncode != 0:
            result.error = (r.stderr or r.stdout or "iptables failed").strip()
            return result
        result.blocked = True
        result.output = r.stdout.strip()
        if self.cfg.persistent:
            result.output += (" " + self.persist()) if result.output else (self.persist() or "")
        return result

    def persist(self) -> str | None:
        # netfilter-persistent (Debian/Ubuntu) is the standard; fall back to iptables-save
        for tool in (["netfilter-persistent", "save"],
                     ["service", "netfilter-persistent", "save"],
                     ["iptables-save"]):
            r = self._run(self._sudo(tool))
            if r.returncode == 0:
                return f"persisted via {' '.join(tool)}"
        return None
