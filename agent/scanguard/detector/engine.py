"""Detection engine: scan logs, apply rules, return offending IPs with evidence."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from ..config import AgentConfig, LogSource, Rule
from .parser import LogEvent, parse_line
from .reader import read_log


@dataclass
class Hit:
    ip: str
    rule: str
    severity: str
    count: int
    first_seen: datetime
    last_seen: datetime
    evidence: List[str] = field(default_factory=list)
    source: str = ""


def scan(config: AgentConfig, now: datetime | None = None) -> List[Hit]:
    """Scan all configured log sources and return hits exceeding rule thresholds."""
    now = now or datetime.now(timezone.utc)
    # ip -> rule -> events
    buckets: Dict[str, Dict[str, List[LogEvent]]] = defaultdict(lambda: defaultdict(list))
    compiled = {r.name: re.compile(r.pattern, re.IGNORECASE) for r in config.rules}
    rule_meta = {r.name: r for r in config.rules}

    for src in config.log_sources:
        for path in src.paths:
            for line in read_log(src, path):
                evt = parse_line(src.kind, line)
                if not evt:
                    continue
                if evt.ip in config.whitelist:
                    continue
                for rname, rx in compiled.items():
                    if not rx.search(evt.message):
                        continue
                    rule = rule_meta[rname]
                    if rule.response_codes and evt.status not in rule.response_codes:
                        continue
                    if evt.ts.tzinfo is None:
                        evt.ts = evt.ts.replace(tzinfo=timezone.utc)
                    buckets[evt.ip][rname].append(evt)

    hits: List[Hit] = []
    for ip, by_rule in buckets.items():
        for rname, events in by_rule.items():
            rule = rule_meta[rname]
            window = timedelta(minutes=rule.window_minutes)
            # sliding window: find if any window has >= threshold
            events.sort(key=lambda e: e.ts)
            for i in range(len(events)):
                start = events[i].ts
                recent = [e for e in events[i:] if e.ts - start <= window]
                if len(recent) >= rule.threshold:
                    evidence = list({e.message for e in recent[:5]})
                    hits.append(Hit(
                        ip=ip,
                        rule=rname,
                        severity=rule.severity,
                        count=len(recent),
                        first_seen=recent[0].ts,
                        last_seen=recent[-1].ts,
                        evidence=evidence,
                    ))
                    break
    return hits
