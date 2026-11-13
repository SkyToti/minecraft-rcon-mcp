"""Command policy: normalize() + classify(). Pure functions; the security core. See docs/DESIGN.md §4.

INTERFACE (fixed — other modules depend on these names and signatures; implement the bodies, do not rename).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence


class Tier(str, Enum):
    READ = "read"
    WRITE = "write"
    CONFIRM = "confirm"
    DENY = "deny"


@dataclass(frozen=True)
class Policy:
    """Token-glob patterns per tier (DESIGN §4.3)."""

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    confirm: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    tier: Tier
    allowed: bool              # may run right now, without a ticket
    needs_confirmation: bool   # may run only through a confirmation ticket
    normalized: str            # "" when the input was rejected by normalize()
    reason: str                # short sentence, safe to show to the model


class CommandRejected(ValueError):
    """Raised by normalize() for empty, oversized or control-character input."""


def normalize(command: str) -> str:
    """DESIGN §4.2. Raises CommandRejected."""
    raise NotImplementedError


def classify(command: str, mode: str, policy: Policy) -> Decision:
    """DESIGN §4.3. `mode` is "read-only" or "read-write". Never raises: rejected input → Tier.DENY."""
    raise NotImplementedError


def load_default_policy() -> Policy:
    """Policy shipped in default_policy.toml (next to this file)."""
    raise NotImplementedError


def merge_policy(base: Policy, extra: Mapping[str, Sequence[str]]) -> Policy:
    """User additions on top of `base`. Raises ValueError if `extra` tries to lower a HARD_CONFIRM / HARD_DENY root."""
    raise NotImplementedError
