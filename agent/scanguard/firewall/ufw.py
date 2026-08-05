"""ufw backend."""
from __future__ import annotations

from .base import FirewallBackend, BlockResult


class UfwBackend(FirewallBackend):
    name = "ufw"

    def is_blocked(self, ip: str) -> bool:
        r = self._run(self._sudo(["ufw", "status"]))
        return f"from {ip}" in (r.stdout or "")

    def block(self, ip: str, reason: str = "") -> BlockResult:
        result = BlockResult(ip=ip, blocked=False, backend=self.name, remote=bool(self.cfg.host))
        if self.is_blocked(ip):
            result.already_blocked = True
            result.blocked = True
            return result
        cmd = ["ufw", "--force", "deny", "from", ip] if self.cfg.policy == "drop" \
            else ["ufw", "--force", "reject", "from", ip]
        r = self._run(self._sudo(cmd))
        result.command = " ".join(cmd)
        if r.returncode != 0:
            result.error = (r.stderr or r.stdout or "ufw failed").strip()
            return result
        result.blocked = True
        result.output = r.stdout.strip()
        return result
