"""基础数据结构."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Target:
    """一个探测目标（TCP 握手端点）."""

    name: str
    host: str
    port: int = 443
    group: str = "overseas"  # overseas | domestic | custom
    note: str = ""

    @property
    def endpoint(self) -> str:
        return "%s:%d" % (self.host, self.port)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "group": self.group,
            "note": self.note,
        }


@dataclass
class Sample:
    """一次探测的记录."""

    ts: float
    target: str
    ok: bool
    rtt_ms: Optional[float] = None
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ts": round(self.ts, 3),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts)),
            "target": self.target,
            "ok": self.ok,
            "rtt_ms": None if self.rtt_ms is None else round(self.rtt_ms, 2),
            "error": self.error,
        }
