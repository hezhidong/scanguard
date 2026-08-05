"""Base firewall backend. Supports local or remote (SSH) command execution."""
from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import FirewallConfig


@dataclass
class BlockResult:
    ip: str
    blocked: bool
    already_blocked: bool = False
    command: str = ""
    output: str = ""
    error: Optional[str] = None
    backend: str = ""
    remote: bool = False
    evidence: List[str] = field(default_factory=list)


class FirewallBackend:
    """Base class. Subclasses implement the actual commands."""

    name = "base"

    def __init__(self, cfg: FirewallConfig):
        self.cfg = cfg

    # ── command execution ────────────────────────────────────────────
    def _run(self, cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
        if self.cfg.host:
            return self._run_remote(cmd, check=check)
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _run_remote(self, cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
        remote_cmd = " ".join(shlex.quote(c) for c in cmd)
        if self.cfg.sudo:
            remote_cmd = f"sudo {remote_cmd}"
        ssh: List[str] = ["ssh", "-o", "StrictHostKeyChecking=no",
                          "-o", "ConnectTimeout=10", "-p", str(self.cfg.port or 22)]
        if self.cfg.key:
            ssh += ["-i", self.cfg.key]
        target = f"{self.cfg.user}@{self.cfg.host}"
        ssh += [target, remote_cmd]
        if self.cfg.password:
            ssh = ["sshpass", "-p", self.cfg.password] + ssh
        return subprocess.run(ssh, capture_output=True, text=True, check=check)

    def _sudo(self, cmd: List[str]) -> List[str]:
        """Prepend sudo for local non-root execution (remote sudo is handled in _run_remote)."""
        if not self.cfg.host and self.cfg.sudo:
            return ["sudo"] + cmd
        return cmd

    # ── interface ────────────────────────────────────────────────────
    def is_blocked(self, ip: str) -> bool:
        raise NotImplementedError

    def block(self, ip: str, reason: str = "") -> BlockResult:
        raise NotImplementedError

    def persist(self) -> Optional[str]:
        """Persist rules across reboots. Returns a message or None."""
        return None
