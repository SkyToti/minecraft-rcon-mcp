"""Command policy: normalize() + classify(). Pure functions; the security core. See docs/DESIGN.md §4.

INTERFACE (fixed — other modules depend on these names and signatures; implement the bodies, do not rename).

How a command is classified, in order:

1. ``normalize()`` rejects empty input, control characters (C0, DEL, C1), invisible formatting characters
   (Unicode ``Cf``, e.g. bidi overrides that could disguise a command in the approval dialog), line/paragraph
   separators, and anything over 1400 UTF-8 bytes. It strips surrounding spaces, collapses runs of spaces and
   strips ONE leading ``/``. The normalized string is what must be sent to the server.
2. The root (first token) is lower-cased for matching; arguments match case-sensitively.
3. ``HARD_DENY`` roots are ``deny``. ``execute … run X`` and ``return run X`` take the tier of ``X``.
   Otherwise the policy patterns decide; nothing matched → ``confirm``.
4. ``HARD_CONFIRM`` roots, and every root starting with ``/`` (WorldEdit), are never below ``confirm``.
5. A ``write`` command with an unbounded ``@a`` / ``@e`` selector anywhere in it becomes ``confirm``.

Pattern syntax (token globs): a literal token matches itself; ``?`` matches exactly one token (an extension of
DESIGN §4.3, used for ``gamerule ?`` vs ``gamerule ? ?``); ``*`` matches one or more tokens and is only allowed
as the last token. The most specific matching pattern wins: most literal tokens first, then most tokens
(so ``tick query`` beats ``tick *``). On a tie the most restrictive tier wins.

Choices stricter than the letter of DESIGN §4 (each is tested):

- ``execute`` (and ``return run X``): every standalone ``run`` is a possible split point (a player or score
  holder can be named ``run``); the most restrictive remainder wins. ``store``/``summon`` before ``run``
  make it at least ``write``; ``function`` (``execute if function``) makes it at least ``confirm``.
- Selectors: ``@a`` needs ``limit=N`` with 1 ≤ N ≤ 10; ``@e`` needs a positive ``type=`` (``type=!x`` does not
  count), and ``@e[type=player]`` is treated like ``@a``. Selectors with nested data (``{``, ``[``, quotes) or
  split by spaces count as unbounded. Every argument counts: the ``execute`` prefix, and also message text
  (``say hi @a`` needs confirmation).
- Namespaced roots (``minecraft:stop``) are classified as the bare root but never below ``confirm``, unless a
  pattern names the namespaced root explicitly.
- An unknown ``mode`` is treated as ``read-only``.
"""
from __future__ import annotations

import functools
import tomllib
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
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


HARD_CONFIRM: frozenset[str] = frozenset({
    "stop", "op", "deop", "ban", "ban-ip", "pardon", "pardon-ip", "whitelist", "kick", "kill", "fill",
    "clone", "save-off", "reload", "lp", "luckperms", "perm",
})  # plus every root starting with "/" (WorldEdit), see _is_hard_confirm()
HARD_DENY: frozenset[str] = frozenset({"debug", "perf", "jfr", "publish", "transfer"})

MAX_COMMAND_BYTES = 1400
MAX_EXECUTE_DEPTH = 8
MAX_SELECTOR_LIMIT = 10

_SEVERITY = {Tier.READ: 0, Tier.WRITE: 1, Tier.CONFIRM: 2, Tier.DENY: 3}
_FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Cs", "Zl", "Zp"}
_DEFAULT_POLICY_FILE = Path(__file__).with_name("default_policy.toml")


# --------------------------------------------------------------------------------------------- normalize


def normalize(command: str) -> str:
    """DESIGN §4.2. Raises CommandRejected."""
    if not isinstance(command, str):
        raise CommandRejected("command must be a string")
    for char in command:
        if unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise CommandRejected("command contains a control or invisible formatting character")
    if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise CommandRejected(f"command is longer than {MAX_COMMAND_BYTES} bytes")
    text = " ".join(token for token in command.split(" ") if token)
    if text.startswith("/"):
        text = text[1:].lstrip(" ")
    if not text:
        raise CommandRejected("command is empty")
    return text


# --------------------------------------------------------------------------------------------- patterns


def _pattern_tokens(pattern: str) -> list[str]:
    """Split and validate one pattern. Raises ValueError. The root is lower-cased like a command root."""
    if not isinstance(pattern, str):
        raise ValueError(f"pattern must be a string, got {type(pattern).__name__}")
    if any(unicodedata.category(c) in _FORBIDDEN_CATEGORIES for c in pattern):
        raise ValueError(f"pattern {pattern!r} contains a control character")
    tokens = pattern.split()
    if not tokens:
        raise ValueError("empty pattern")
    if tokens[0] in ("*", "?"):
        raise ValueError(f"pattern {pattern!r}: the first token must be a literal command name")
    if "*" in tokens[:-1]:
        raise ValueError(f"pattern {pattern!r}: '*' is only allowed as the last token")
    return [tokens[0].lower(), *tokens[1:]]


@functools.cache
def _compiled(pattern: str) -> tuple[tuple[str, ...], int]:
    """(tokens, number of literal tokens) of a pattern, cached."""
    tokens = tuple(_pattern_tokens(pattern))
    return tokens, sum(1 for t in tokens if t not in ("*", "?"))


def _matches(pattern: Sequence[str], words: Sequence[str]) -> bool:
    if pattern[-1] == "*":
        fixed = pattern[:-1]
        if len(words) <= len(fixed):
            return False
    else:
        fixed = pattern
        if len(words) != len(fixed):
            return False
    return all(p == "?" or p == w for p, w in zip(fixed, words))


def _best_match(policy: Policy, words: Sequence[str]) -> tuple[Tier, str] | None:
    """Most specific matching pattern (literals, then length); on a tie the most restrictive tier."""
    best: tuple[tuple[int, int, int], Tier, str] | None = None
    for tier in Tier:
        for pattern in getattr(policy, tier.value):
            tokens, literals = _compiled(pattern)
            if not _matches(tokens, words):
                continue
            key = (literals, len(tokens), _SEVERITY[tier])
            if best is None or key > best[0]:
                best = (key, tier, pattern)
    if best is None:
        return None
    return best[1], best[2]


# --------------------------------------------------------------------------------------------- selectors


def _selector_args(token: str) -> dict[str, list[str]] | None:
    """Arguments of a selector like '@e[type=zombie,limit=1]'; None if we do not trust the parse."""
    rest = token[2:]
    if not rest:
        return {}
    if not (rest.startswith("[") and rest.endswith("]")):
        return None  # split by a space, or not a selector we understand
    body = rest[1:-1]
    if any(c in body for c in "{}[]\"'"):
        return None  # nested data (nbt=, scores=, quoted names) could hide a fake "limit="
    args: dict[str, list[str]] = {}
    for part in body.split(","):
        key, equals, value = part.partition("=")
        if not equals:
            return None
        args.setdefault(key.strip(), []).append(value.strip())
    return args


def _is_unbounded_selector(token: str) -> bool:
    """@a needs limit=1..10; @e needs a positive type= (and limit= when the type is player)."""
    kind = token[:2].lower()
    if kind not in ("@a", "@e"):
        return False  # @s, @p, @r, @n and plain names never escalate
    args = _selector_args(token)
    if args is None:
        return True
    limited = any(
        v.isascii() and v.isdigit() and 1 <= int(v) <= MAX_SELECTOR_LIMIT for v in args.get("limit", [])
    )
    if kind == "@a":
        return not limited
    types = [v for v in args.get("type", []) if v and not v.startswith("!")]
    if not types:
        return True
    if any(t in ("player", "minecraft:player") for t in types):
        return not limited
    return False


# --------------------------------------------------------------------------------------------- classify


def _is_hard_confirm(root: str) -> bool:
    return root in HARD_CONFIRM or root.startswith("/")


def _execute_floor(lowered: set[str]) -> tuple[Tier, str]:
    """Side effects of the execute subcommands themselves, given the lower-cased tokens before 'run'."""
    if "function" in lowered:
        return Tier.CONFIRM, "'execute … function' runs a function"
    if lowered & {"store", "summon"}:
        return Tier.WRITE, "'execute store/summon' changes state"
    return Tier.READ, "'execute' without 'run' only tests conditions"


def _pattern_tier(policy: Policy, root: str, bare: str, args: Sequence[str]) -> tuple[Tier, str]:
    match = _best_match(policy, (root, *args))
    if match is not None:
        return match[0], f"matches '{match[1]}'"
    if bare != root:  # "plugin:cmd": treat as "cmd", but a namespace is never trusted below confirm
        match = _best_match(policy, (bare, *args))
        if match is not None and _SEVERITY[match[0]] >= _SEVERITY[Tier.CONFIRM]:
            return match[0], f"matches '{match[1]}'"
        return Tier.CONFIRM, f"namespaced command '{root}' needs confirmation"
    return Tier.CONFIRM, "unknown command; anything not in the policy needs confirmation"


def _classify_words(words: tuple[str, ...], policy: Policy) -> tuple[Tier, str]:
    """Tier of a normalized, split command, before selector escalation."""

    @functools.cache  # (start, depth) -> tier; keeps many 'run' tokens from exploding the search
    def at(start: int, depth: int) -> tuple[Tier, str]:
        if start >= len(words):
            return Tier.CONFIRM, "'run' is not followed by a command"
        root = words[start].lower()
        bare = root.rpartition(":")[2]  # "minecraft:stop" -> "stop"
        if root in HARD_DENY or bare in HARD_DENY:
            return Tier.DENY, f"'{bare}' is never allowed through this server"

        is_return_run = bare == "return" and start + 1 < len(words) and words[start + 1].lower() == "run"
        if bare == "execute" or is_return_run:
            tier, reason = wrapped(start, depth)
            if bare != root and _SEVERITY[tier] < _SEVERITY[Tier.CONFIRM]:
                tier, reason = Tier.CONFIRM, f"namespaced command '{root}' needs confirmation"
        else:
            tier, reason = _pattern_tier(policy, root, bare, words[start + 1:])

        if (_is_hard_confirm(root) or _is_hard_confirm(bare)) and _SEVERITY[tier] < _SEVERITY[Tier.CONFIRM]:
            tier, reason = Tier.CONFIRM, f"'{bare}' always needs confirmation"
        return tier, reason

    def wrapped(start: int, depth: int) -> tuple[Tier, str]:
        """'execute … run X' / 'return run X': any standalone 'run' may be the real split; take the worst."""
        if depth >= MAX_EXECUTE_DEPTH:
            return Tier.DENY, f"execute nested deeper than {MAX_EXECUTE_DEPTH}"
        candidates: list[tuple[Tier, str]] = []
        prefix: set[str] = set()
        for i in range(start + 1, len(words)):
            token = words[i].lower()
            # a trailing 'run' cannot be the real split when an earlier one exists (nothing would follow it)
            if token == "run" and (i + 1 < len(words) or not candidates):
                candidates += [at(i + 1, depth + 1), _execute_floor(prefix)]
            prefix.add(token)
        if not candidates:
            return _execute_floor(prefix)
        return max(candidates, key=lambda candidate: _SEVERITY[candidate[0]])

    return at(0, 0)


def _decide(tier: Tier, mode: str, normalized: str, reason: str) -> Decision:
    if tier is Tier.READ:
        return Decision(tier, True, False, normalized, f"Read command ({reason}).")
    if tier is Tier.DENY:
        return Decision(tier, False, False, normalized, f"Refused: {reason}.")
    if mode != "read-write":
        return Decision(tier, False, False, normalized, f"Refused: server is read-only and this is a {tier.value} "
                        f"command ({reason}).")
    if tier is Tier.WRITE:
        return Decision(tier, True, False, normalized, f"Write command ({reason}).")
    return Decision(tier, False, True, normalized, f"Needs human confirmation: {reason}.")


def classify(command: str, mode: str, policy: Policy) -> Decision:
    """DESIGN §4.3. `mode` is "read-only" or "read-write". Never raises: rejected input → Tier.DENY."""
    try:
        normalized = normalize(command)
    except CommandRejected as exc:
        return Decision(Tier.DENY, False, False, "", f"Rejected: {exc}.")
    except Exception:  # noqa: BLE001 — classify must never raise
        return Decision(Tier.DENY, False, False, "", "Rejected: invalid command.")
    try:
        words = tuple(normalized.split(" "))
        tier, reason = _classify_words(words, policy)
        if tier is Tier.WRITE and any(_is_unbounded_selector(w) for w in words[1:]):
            tier = Tier.CONFIRM
            reason = f"unbounded selector (@a needs limit=1..{MAX_SELECTOR_LIMIT}, @e needs type=)"
        return _decide(tier, mode, normalized, reason)
    except Exception:  # noqa: BLE001 — e.g. a malformed pattern in a hand-built Policy
        return Decision(Tier.DENY, False, False, normalized, "Refused: the policy could not be evaluated.")


# --------------------------------------------------------------------------------------------- policies


def _validated(tier: Tier, patterns: object) -> tuple[str, ...]:
    if isinstance(patterns, (str, bytes)) or not isinstance(patterns, Sequence):
        raise ValueError(f"policy.{tier.value} must be a list of patterns")
    for pattern in patterns:
        tokens = _pattern_tokens(pattern)
        root = tokens[0]
        bare = root.rpartition(":")[2]
        if bare == "execute":
            raise ValueError(f"pattern {pattern!r}: 'execute' is classified by the command after 'run'")
        if (root in HARD_DENY or bare in HARD_DENY) and tier is not Tier.DENY:
            raise ValueError(f"pattern {pattern!r}: '{bare}' is always denied and cannot be moved to {tier.value}")
        if (_is_hard_confirm(root) or _is_hard_confirm(bare)) and tier in (Tier.READ, Tier.WRITE):
            raise ValueError(f"pattern {pattern!r}: '{bare}' always needs confirmation and cannot be {tier.value}")
    return tuple(patterns)


@functools.cache
def load_default_policy() -> Policy:
    """Policy shipped in default_policy.toml (next to this file)."""
    with _DEFAULT_POLICY_FILE.open("rb") as fh:
        data = tomllib.load(fh)
    return Policy(**{tier.value: _validated(tier, data.get(tier.value, [])) for tier in Tier})


def merge_policy(base: Policy, extra: Mapping[str, Sequence[str]]) -> Policy:
    """User additions on top of `base`. Raises ValueError if `extra` tries to lower a HARD_CONFIRM / HARD_DENY root."""
    unknown = set(extra) - {tier.value for tier in Tier}
    if unknown:
        raise ValueError(f"unknown policy keys: {', '.join(sorted(unknown))} (use read, write, confirm, deny)")
    merged = {}
    for tier in Tier:
        added = _validated(tier, extra.get(tier.value, ()))
        current = getattr(base, tier.value)
        merged[tier.value] = current + tuple(p for p in dict.fromkeys(added) if p not in current)
    return Policy(**merged)
