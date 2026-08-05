"""firewalld backend (uses firewall-cmd with rich rules / ipset)."""
from __future__ import annotations

from .base import FirewallBackend, BlockResult

IPSET = "scanguard"


class FirewalldBackend(FirewallBackend):
    name = "firewalld"

    def _ensure_ipset(self) -> None:
        # permanent ipset + a rich rule dropping source matching it
        sudo = self._sudo
        self._run(sudo(["firewall-cmd", "--permanent", "--new-ipset=" + IPSET, "--type=hash:ip"]))
        self._run(sudo(["firewall-cmd", "--permanent", f"--ipset={IPSET}",
                        "--add-entry=__probe__"]))  # may fail, harmless
        # remove probe
        self._run(sudo(["firewall-cmd", "--permanent", f"--ipset={IPSET}",
                        "--remove-entry=__probe__"]))
        self._run(sudo(["firewall-cmd", "--permanent", "--zone=drop", "--add-source="
                        f"ipset:{IPSET}"]))
        self._run(sudo(["firewall-cmd", "--reload"]))

    def is_blocked(self, ip: str) -> bool:
        r = self._run(self._sudo(["firewall-cmd", "--permanent",
                                  f"--ipset={IPSET}", "--query-entry=" + ip]))
        return r.returncode == 0

    def block(self, ip: str, reason: str = "") -> BlockResult:
        result = BlockResult(ip=ip, blocked=False, backend=self.name, remote=bool(self.cfg.host))
        try:
            self._ensure_ipset()
        except Exception:
            pass
        if self.is_blocked(ip):
            result.already_blocked = True
            result.blocked = True
            return result
        r = self._run(self._sudo(["firewall-cmd", "--permanent", f"--ipset={IPSET}",
                                  "--add-entry=" + ip]))
        result.command = f"firewall-cmd --permanent --ipset={IPSET} --add-entry={ip}"
        if r.returncode != 0:
            result.error = (r.stderr or r.stdout or "firewall-cmd failed").strip()
            return result
        self._run(self._sudo(["firewall-cmd", "--reload"]))
        result.blocked = True
        result.output = "added + reloaded"
        return result
