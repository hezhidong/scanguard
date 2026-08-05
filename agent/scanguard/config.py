"""Configuration loading for ScanGuard Agent."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False


@dataclass
class LogSource:
    """A local or remote log source."""
    name: str
    kind: str = "nginx"            # nginx | apache | auth | generic
    paths: List[str] = field(default_factory=list)
    # remote target (optional)
    host: Optional[str] = None
    user: Optional[str] = None
    port: int = 22
    key: Optional[str] = None
    password: Optional[str] = None
    sudo: bool = False
    timezone: str = "UTC"

    @property
    def is_remote(self) -> bool:
        return bool(self.host)


@dataclass
class Rule:
    """A detection rule."""
    name: str
    pattern: str                  # regex matched against request line / message
    threshold: int = 20           # hits within window to trigger
    window_minutes: int = 30
    severity: str = "high"        # low | medium | high | critical
    response_codes: Optional[List[int]] = None  # only count these status codes


@dataclass
class FirewallConfig:
    """Firewall backend config."""
    backend: str = "iptables"     # iptables | nftables | ufw | firewalld
    policy: str = "drop"          # drop | reject
    chain: str = "INPUT"
    persistent: bool = True
    # remote (optional): block on a remote host instead of locally
    host: Optional[str] = None
    user: Optional[str] = None
    port: int = 22
    key: Optional[str] = None
    password: Optional[str] = None
    sudo: bool = True


@dataclass
class CentralConfig:
    """Report blocked IPs to a Central Threat Intel API."""
    enabled: bool = False
    url: Optional[str] = None
    node_id: Optional[str] = None
    token: Optional[str] = None
    node_name: Optional[str] = None


@dataclass
class AgentConfig:
    state_dir: Path
    log_sources: List[LogSource] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    whitelist: List[str] = field(default_factory=list)
    central: CentralConfig = field(default_factory=CentralConfig)
    geo_provider: str = "ip-api"   # ip-api | none
    geo_cache_ttl_days: int = 7
    notify_file: Optional[str] = None
    dry_run: bool = False

    @staticmethod
    def from_dict(data: Dict[str, Any], state_dir: Optional[Path] = None) -> "AgentConfig":
        sd = Path(data.get("state_dir") or state_dir or "/var/lib/scanguard")
        fw = data.get("firewall", {}) or {}
        cfg = AgentConfig(
            state_dir=sd,
            log_sources=[LogSource(**s) for s in data.get("log_sources", [])],
            rules=[Rule(**r) for r in data.get("rules", [])],
            firewall=FirewallConfig(**fw),
            whitelist=list(data.get("whitelist", [])),
            central=CentralConfig(**(data.get("central", {}) or {})),
            geo_provider=data.get("geo", {}).get("provider", "ip-api"),
            geo_cache_ttl_days=data.get("geo", {}).get("cache_ttl_days", 7),
            notify_file=data.get("notify_file"),
            dry_run=bool(data.get("dry_run", False)),
        )
        return cfg

    @staticmethod
    def load(path: str | os.PathLike) -> "AgentConfig":
        p = Path(path)
        text = p.read_text()
        if p.suffix in (".yaml", ".yml"):
            if not _HAS_YAML:
                raise RuntimeError("PyYAML required for YAML config: pip install pyyaml")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        return AgentConfig.from_dict(data)
