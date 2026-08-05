"""Log readers: local files and remote (SSH) files, including rotated .gz logs."""
from __future__ import annotations

import gzip
import shlex
import subprocess
from pathlib import Path
from typing import Iterator, List

from ..config import LogSource


def read_log(src: LogSource, path: str) -> Iterator[str]:
    """Yield lines from a log file, local or remote, plain or gzipped."""
    if path.endswith(".gz"):
        if src.is_remote:
            yield from _remote_gz(src, path)
        else:
            with gzip.open(path, "rt", errors="replace") as f:
                yield from f
    else:
        if src.is_remote:
            yield from _remote_plain(src, path)
        else:
            with open(path, "rt", errors="replace") as f:
                yield from f


def _ssh_prefix(src: LogSource) -> List[str]:
    target = f"{src.user}@{src.host}"
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10", "-p", str(src.port or 22)]
    if src.key:
        cmd += ["-i", src.key]
    cmd.append(target)
    if src.password:
        cmd = ["sshpass", "-p", src.password] + cmd
    return cmd


def _remote_plain(src: LogSource, path: str) -> Iterator[str]:
    cat = "cat" if not src.sudo else f"sudo cat {shlex.quote(path)}"
    r = subprocess.run(_ssh_prefix(src) + [cat], capture_output=True, text=True)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            yield line


def _remote_gz(src: LogSource, path: str) -> Iterator[str]:
    zcat = "zcat" if not src.sudo else f"sudo zcat {shlex.quote(path)}"
    r = subprocess.run(_ssh_prefix(src) + [zcat], capture_output=True, text=True)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            yield line
