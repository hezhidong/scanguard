"""Firewall backends. Each backend can run locally or over SSH."""
from .base import FirewallBackend, BlockResult
from .iptables import IptablesBackend
from .nftables import NftablesBackend
from .ufw import UfwBackend
from .firewalld import FirewalldBackend

BACKENDS = {
    "iptables": IptablesBackend,
    "nftables": NftablesBackend,
    "ufw": UfwBackend,
    "firewalld": FirewalldBackend,
}


def get_backend(name: str, cfg) -> FirewallBackend:
    cls = BACKENDS.get(name)
    if not cls:
        raise ValueError(f"Unknown firewall backend: {name} (choose from {list(BACKENDS)})")
    return cls(cfg)

__all__ = ["FirewallBackend", "BlockResult", "get_backend", "BACKENDS"]
