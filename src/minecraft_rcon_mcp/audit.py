"""Append-only JSONL audit log. See docs/DESIGN.md §7.

One line per record: `ts` (ISO-8601 UTC) followed by the caller's fields. As defense in depth, any field whose
key contains "password" or "secret" (at any nesting level) is dropped before writing. File mode is 0600.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["AuditLog"]

_FORBIDDEN = ("password", "secret")


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: _scrub(v)
            for k, v in value.items()
            if not any(word in str(k).lower() for word in _FORBIDDEN)
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    return value


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()

    def record(self, **fields: Any) -> None:
        """Append one JSON line. `ts` is always set here; a caller-supplied `ts` is ignored."""
        fields.pop("ts", None)
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **_scrub(fields)}
        line = json.dumps(entry, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.fchmod(fd, 0o600)
                data = line.encode("utf-8")
                while data:
                    data = data[os.write(fd, data) :]
            finally:
                os.close(fd)
