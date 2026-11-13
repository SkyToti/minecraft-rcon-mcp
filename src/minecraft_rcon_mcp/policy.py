"""Command policy: normalize() + classify(). Pure functions; the security core. See docs/DESIGN.md §4.

INTERFACE (fixed — other modules depend on these names and signatures; implement the bodies, do not rename).

How a command is classified, in order:

1. ``normalize()`` rejects empty input, control characters (C0, DEL, C1), invisible formatting characters
   (Unicode ``Cf``, e.g. bidi overrides that could disguise a command in the approval dialog), line/paragraph
   separators, and anything over 1400 UTF-8 bytes. It strips surrounding spaces, collapses runs of spaces and
   strips ONE leading ``/``. The normalized string is what must be sent to the server.
2. The root (first token) is lower-cased for matching, and one leading ``minecraft:`` namespace is removed
   from it (``minecraft:stop`` is ``stop``); arguments match case-sensitively. The command is still sent as given.
3. ``HARD_DENY`` roots are ``deny``. ``execute … run X`` and ``return run X`` take the tier of ``X``.
   Otherwise the policy patterns decide; nothing matched → ``confirm``.
4. ``HARD_CONFIRM`` roots, and every root starting with ``/`` (WorldEdit), are never below ``confirm``.
5. A ``write`` command becomes ``confirm`` when an unbounded selector multiplies its effect: in its own
   arguments, or in the prefix of an ``execute`` that wraps it. Message commands (``MESSAGE_ROOTS``:
   ``say``, ``tellraw``…) do not escalate on their own arguments: asking a human to approve every broadcast
   causes approval fatigue, which weakens the confirmations that matter.
6. Indirect execution: if the whole normalized command (``execute`` prefix, NBT and JSON included) contains an
   ``INDIRECT_MARKERS`` substring, or (for a ``write``) an NBT path token ending in ``Command``, it is raised
   to at least ``confirm``. A command block, a command-block minecart or a ``run_command`` click event stores a
   command that runs later with no ticket. This applies to every root, ``MESSAGE_ROOTS`` included, and no user
   pattern can lower it. The check also runs on a copy with SNBT/JSON escapes (``\\u0061``, ``\\x61``, ``\\N{…}``) decoded
   and quotes and whitespace removed, so ``{'Command' : "x"}`` is caught too. False positives are accepted:
   ``say I typed a command: x`` and ``say command`` need confirmation.

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
  split by spaces count as unbounded. ANY selector (``@p``, ``@r``, ``@n``, ``@s`` too) is unbounded when it
  sets ``limit=`` to anything but 1..10 or sets ``limit=`` more than once; ``@p``/``@r``/``@n`` without
  ``limit=`` stay bounded. In ``scoreboard players …`` a standalone ``*`` (every score holder) counts as an
  unbounded selector, and so does a standalone ``*`` in an ``execute`` prefix (``store … score * obj``).
  An unbounded selector in the ``execute`` prefix escalates whatever ``write`` command it wraps
  (``execute as @a run say hi`` needs confirmation).
- Other namespaces (``plugin:cmd``) are classified as ``cmd`` but never below ``confirm``, unless a pattern
  names the namespaced root explicitly.
- An unknown ``mode`` is treated as ``read-only``.
"""
from __future__ import annotations

import functools
import re
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
# Commands that only show something to players: an unbounded selector in their own arguments picks the
# audience, it does not multiply a state change. (A selector in a wrapping execute prefix still counts.)
MESSAGE_ROOTS: frozenset[str] = frozenset({"say", "tellraw", "title", "playsound", "particle"})
# Substrings (of the lower-cased whole command) that may store a command which runs later, with no ticket:
# command blocks and their minecarts, "run_command" click events in text, signs and books, "Command" NBT.
INDIRECT_MARKERS: tuple[str, ...] = ("command_block", "run_command", "command:", '"command"')

MAX_COMMAND_BYTES = 1400
MAX_EXECUTE_DEPTH = 8
MAX_SELECTOR_LIMIT = 10
_VANILLA_NAMESPACE = "minecraft:"
_UNBOUNDED = (f"unbounded selector (@a needs limit=1..{MAX_SELECTOR_LIMIT}, @e needs type=, no selector may "
              f"set limit= above {MAX_SELECTOR_LIMIT}, '*' is every score holder)")
_INDIRECT = "may store a command that runs later (indirect execution)"
# markers still meaningful once quotes and whitespace are removed ('"command"' would match any word)
_CANONICAL_MARKERS = ("command_block", "run_command", "command:")
_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|N\{([^}]{1,100})\})")
_STRIPPED = re.compile(r"[\s'\"\\\\]")
_COMMAND_PATH = re.compile(r"(?:.*[.\]])?command")   # NBT path whose last key is Command: "Command", "a[0].Command"

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


def _root(token: str) -> str:
    """Command root for matching: lower-cased, one leading 'minecraft:' removed."""
    root = token.lower()
    return root[len(_VANILLA_NAMESPACE):] if root.startswith(_VANILLA_NAMESPACE) else root


def _pattern_tokens(pattern: str) -> list[str]:
    """Split and validate one pattern. Raises ValueError. The root is normalized like a command root."""
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
    return [_root(tokens[0]), *tokens[1:]]


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


def _bounded_limit(values: Sequence[str]) -> bool:
    """Exactly one limit= value, a plain ASCII number from 1 to MAX_SELECTOR_LIMIT."""
    return len(values) == 1 and values[0].isascii() and values[0].isdigit() and (
        1 <= int(values[0]) <= MAX_SELECTOR_LIMIT)


def _is_unbounded_selector(token: str) -> bool:
    """@a needs limit=1..10; @e needs a positive type= (and limit= when the type is player).

    Any selector with limit= outside 1..10, or with limit= twice, is unbounded; @s/@p/@r/@n without it are not.
    """
    if not token.startswith("@") or len(token) < 2:
        return False  # a plain name
    kind = token[:2].lower()
    args = _selector_args(token)
    if kind not in ("@a", "@e"):
        if args is None:
            return "limit" in token.lower()  # cannot parse: any limit= could be a big one
        limits = [v for k, values in args.items() if k.lower() == "limit" for v in values]
        return bool(limits) and not _bounded_limit(limits)
    if args is None:
        return True
    limited = _bounded_limit(args.get("limit", []))
    if kind == "@a":
        return not limited
    if len(args.get("limit", [])) > 1:
        return True
    types = [v for v in args.get("type", []) if v and not v.startswith("!")]
    if not types:
        return True
    if any(t in ("player", "minecraft:player") for t in types):
        return not limited
    return False


def _all_score_holders(bare: str, args: Sequence[str]) -> bool:
    """'scoreboard players … *': a standalone '*' is every tracked score holder."""
    return bare == "scoreboard" and bool(args) and args[0].lower() == "players" and "*" in args


def _unescape(match: re.Match[str]) -> str:
    code, wide, byte, name = match.groups()
    try:
        if name is not None:
            return unicodedata.lookup(name)
        return chr(int(code or wide or byte, 16))
    except (KeyError, ValueError):
        return match.group(0)


def _stores_command(normalized: str, tier: Tier) -> bool:
    """True when the command may store a command that runs later (see INDIRECT_MARKERS).

    An NBT path ending in Command (``data modify block … Command set value …``) only counts for a ``write``:
    reading a command block's command (``data get block … Command``) stays ``read``.
    """
    lowered = normalized.lower()
    if any(marker in lowered for marker in INDIRECT_MARKERS):
        return True
    if tier is Tier.WRITE and any(_COMMAND_PATH.fullmatch(token) for token in lowered.split(" ")):
        return True
    canonical = _STRIPPED.sub("", _ESCAPE.sub(_unescape, normalized).lower())
    return any(marker in canonical for marker in _CANONICAL_MARKERS)

# --------------------------------------------------------------------------------------------- classify


def _is_hard_confirm(root: str) -> bool:
    return root in HARD_CONFIRM or root.startswith("/")


def _escalate(found: tuple[Tier, str], unbounded: bool) -> tuple[Tier, str]:
    """An unbounded selector turns a write into confirm."""
    return (Tier.CONFIRM, _UNBOUNDED) if unbounded and found[0] is Tier.WRITE else found


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
    """Tier of a normalized, split command."""

    @functools.cache  # (start, depth) -> tier; keeps many 'run' tokens from exploding the search
    def at(start: int, depth: int) -> tuple[Tier, str]:
        if start >= len(words):
            return Tier.CONFIRM, "'run' is not followed by a command"
        root = _root(words[start])
        bare = root.rpartition(":")[2]  # "plugin:stop" -> "stop"
        if root in HARD_DENY or bare in HARD_DENY:
            return Tier.DENY, f"'{bare}' is never allowed through this server"

        is_return_run = bare == "return" and start + 1 < len(words) and words[start + 1].lower() == "run"
        if bare == "execute" or is_return_run:
            tier, reason = wrapped(start, depth)
            if bare != root and _SEVERITY[tier] < _SEVERITY[Tier.CONFIRM]:
                tier, reason = Tier.CONFIRM, f"namespaced command '{root}' needs confirmation"
        else:
            args = words[start + 1:]
            own_selectors = bare not in MESSAGE_ROOTS and (
                any(_is_unbounded_selector(a) for a in args) or _all_score_holders(bare, args))
            tier, reason = _escalate(_pattern_tier(policy, root, bare, args), own_selectors)

        if (_is_hard_confirm(root) or _is_hard_confirm(bare)) and _SEVERITY[tier] < _SEVERITY[Tier.CONFIRM]:
            tier, reason = Tier.CONFIRM, f"'{bare}' always needs confirmation"
        return tier, reason

    def wrapped(start: int, depth: int) -> tuple[Tier, str]:
        """'execute … run X' / 'return run X': any standalone 'run' may be the real split; take the worst."""
        if depth >= MAX_EXECUTE_DEPTH:
            return Tier.DENY, f"execute nested deeper than {MAX_EXECUTE_DEPTH}"
        candidates: list[tuple[Tier, str]] = []
        prefix: set[str] = set()
        unbounded = False  # an unbounded selector in the prefix (execute as @a …) multiplies the inner command
        for i in range(start + 1, len(words)):
            token = words[i].lower()
            # a trailing 'run' cannot be the real split when an earlier one exists (nothing would follow it)
            if token == "run" and (i + 1 < len(words) or not candidates):
                candidates += [_escalate(at(i + 1, depth + 1), unbounded), _escalate(_execute_floor(prefix), unbounded)]
            prefix.add(token)
            # a standalone '*' in the prefix can only be "every score holder" (execute store … score * obj)
            unbounded = unbounded or _is_unbounded_selector(words[i]) or words[i] == "*"
        if not candidates:
            return _escalate(_execute_floor(prefix), unbounded)
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
        if _SEVERITY[tier] < _SEVERITY[Tier.CONFIRM] and _stores_command(normalized, tier):
            tier, reason = Tier.CONFIRM, _INDIRECT  # after the patterns: no user config can lower it
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
