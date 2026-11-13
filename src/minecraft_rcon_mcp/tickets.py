"""Single-use confirmation tickets. See docs/DESIGN.md §5.

A ticket is bound to one server and to the sha256 of one normalized command. Redeeming it always consumes it,
whether or not the redemption succeeds. Tickets live in memory only.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import string
import threading
import time
from dataclasses import dataclass
from typing import Callable

__all__ = ["TicketStore", "TICKET_LENGTH"]

TICKET_LENGTH = 10
_ALPHABET = string.ascii_letters + string.digits + "-_"


def _digest(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Entry:
    server: str
    command_sha256: str
    expires_at: float


class TicketStore:
    def __init__(self, ttl_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            self._purge(self._clock())
            return len(self._entries)

    def issue(self, server: str, normalized_command: str) -> str:
        """New ticket for running `normalized_command` on `server`, valid for `ttl_seconds`."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            while True:
                ticket = "".join(secrets.choice(_ALPHABET) for _ in range(TICKET_LENGTH))
                if ticket not in self._entries:
                    break
            self._entries[ticket] = _Entry(server, _digest(normalized_command), now + self.ttl_seconds)
            return ticket

    def redeem(self, ticket: str, server: str, normalized_command: str) -> tuple[bool, str]:
        """(ok, reason). Any call consumes the ticket, so a failed attempt cannot be retried."""
        with self._lock:
            now = self._clock()
            entry = self._entries.pop(ticket, None)
            self._purge(now)
            if entry is None:
                return False, "unknown, expired or already used ticket"
            if now >= entry.expires_at:
                return False, "ticket expired"
            if entry.server != server:
                return False, "ticket was issued for another server"
            if not hmac.compare_digest(entry.command_sha256, _digest(normalized_command)):
                return False, "command does not match the ticket"
            return True, "ok"

    def _purge(self, now: float) -> None:
        expired = [t for t, e in self._entries.items() if now >= e.expires_at]
        for t in expired:
            del self._entries[t]
