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
    """Report blocked IPs to a self-owned fork (GitHub or legacy HTTP API).

    Use this when the node operator wants to run their own dashboard.
    For the public community feed, use CommunityConfig instead.

    backend: http      — POST to {url}/api/report with a Bearer token (legacy)
    backend: github    — append to a public GitHub repo via the Contents API.
    """
    enabled: bool = False
    backend: str = "http"             # http | github
    url: Optional[str] = None
    node_id: Optional[str] = None
    node_name: Optional[str] = None
    token: Optional[str] = None       # http: Bearer token; github: fine-grained PAT
    # github backend only:
    repo: Optional[str] = None        # owner/name, e.g. hezhidong/scanguard
    branch: str = "master"
    reports_path: Optional[str] = None  # default: reports/<node_id>.jsonl
    max_lines: int = 5000             # per-file cap before oldest events are trimmed


@dataclass
class CommunityConfig:
    """Report blocked IPs to the public ScanGuard community intake (no token).

    The endpoint is a Cloudflare Worker that validates, rate-limits and
    buffers events before committing them to the central repository.
    Defaults are set so a fresh install contributes with zero configuration.
    """
    enabled: bool = True
    endpoint: str = "https://scanguard-intake.hezhidong.workers.dev/report"
    node_id: Optional[str] = None     # defaults to hostname
    node_name: Optional[str] = None   # defaults to hostname
    timeout: int = 10


@dataclass
class AgentConfig:
    state_dir: Path
    log_sources: List[LogSource] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    whitelist: List[str] = field(default_factory=list)
    central: CentralConfig = field(default_factory=CentralConfig)
    community: CommunityConfig = field(default_factory=CommunityConfig)
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
            community=CommunityConfig(**(data.get("community", {}) or {})),
            geo_provider=data.get("geo", {}).get("provider", "ip-api"),
            geo_cache_ttl_days=data.get("geo", {}).get("cache_ttl_days", 7),
            notify_file=data.get("notify_file"),
            dry_run=bool(data.get("dry_run", False)),
        )
        # Resolve central token from env / file if not inline
        if cfg.central.enabled and not cfg.central.token:
            import pathlib
            env = os.environ.get("SCANGUARD_GITHUB_TOKEN") or os.environ.get("SCANGUARD_CENTRAL_TOKEN")
            if env:
                cfg.central.token = env.strip()
            else:
                for p in ("/etc/scanguard/github_token", "/etc/scanguard/central_token"):
                    try:
                        if pathlib.Path(p).exists():
                            cfg.central.token = pathlib.Path(p).read_text().strip()
                            break
                    except Exception:
                        pass
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
