"""Service layer: one method per MCP tool, each returning a JSON-serializable dict. See docs/DESIGN.md §6–7.

No MCP imports here: :mod:`minecraft_rcon_mcp.server` wires these methods to MCP tools.

Rules every public method follows:

- Expected failures never raise; they return ``{"status": "error", "error": "<message>"}`` (or ``refused`` /
  ``rate_limited`` / ``confirmation_required``).
- A command reaches RCON only after the policy allowed it, the rate limiter allowed it and, for the confirm
  tier, a ticket was redeemed.
- Every outgoing string (results and audit records) is scrubbed of every RCON password this process has read,
  as defense in depth on top of the lower layers never including it.
"""
from __future__ import annotations

import functools
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from . import logs
from .audit import AuditLog
from .config import Config, ConfigError, Scenario, ServerConfig, read_rcon_endpoint
from .policy import Policy, Tier, classify, load_default_policy, merge_policy
from .ratelimit import RateLimiter
from .rcon import RconClient, RconError
from .tickets import TicketStore

__all__ = ["Service", "MAX_PLAYERS", "PLAYER_NAME_RE"]

MAX_PLAYERS = 20
PLAYER_NAME_RE = re.compile(r"^[A-Za-z0-9_.]{1,32}$")
REDACTED = "[redacted]"
PROBE_TIMEOUT = 0.5          # seconds, TCP probe of the RCON port in list_servers
MAX_NAME_CHARS = 200         # mod file names are cut at this length

_COLOR = re.compile(r"§.?", re.DOTALL)
_UNPRINTABLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_LIST = re.compile(
    r"There are (?P<online>\d+)\s*(?:of a max(?: of)?|/)\s*(?P<max>\d+) players online:?\s*(?P<names>.*)",
    re.DOTALL,
)
_MS = r"([0-9]+(?:[.,][0-9]+)?)\s*ms"
_TICK_FIELDS = {
    "average_ms": re.compile(r"Average time per tick:\s*" + _MS),
    "target_ms": re.compile(r"\(Target:\s*" + _MS),
    "p50_ms": re.compile(r"P50:\s*" + _MS),
    "p95_ms": re.compile(r"P95:\s*" + _MS),
    "p99_ms": re.compile(r"P99:\s*" + _MS),
}
_NUMBER = r"(-?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)"
_POS = re.compile(r"\[\s*" + _NUMBER + r"d?\s*,\s*" + _NUMBER + r"d?\s*,\s*" + _NUMBER + r"d?\s*\]")
_DIMENSION = re.compile(r'"([a-z0-9_.-]+:[a-z0-9_./-]+)"')

AUDITED_OUTCOMES = (
    "executed", "refused", "ticket_issued", "confirmed", "ticket_rejected", "rate_limited", "error",
)


def _never_raise(method: Callable[..., dict]) -> Callable[..., dict]:
    """Turn an unexpected exception into an error result (scrubbed), so a tool call never crashes the server."""

    @functools.wraps(method)
    def wrapper(self: Service, *args: Any, **kwargs: Any) -> dict:
        try:
            result = method(self, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — the contract is "never raise"
            result = {"status": "error", "error": f"internal error ({type(exc).__name__})"}
        return self._scrub(result)

    return wrapper


class Service:
    """All tool logic. `clock` drives tickets and rate limits; `sleep` is used between scenario steps.

    `proc_root` is where process information is read from (``/proc``); tests point it at a fake tree.
    Raises ConfigError if the configured policy additions or a scenario step are invalid.
    """

    def __init__(
        self,
        config: Config,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        *,
        proc_root: Path | str = "/proc",
    ) -> None:
        self.config = config
        self._clock = clock
        self._sleep = sleep
        self._proc_root = Path(proc_root)
        try:
            self.policy: Policy = merge_policy(load_default_policy(), config.policy_extra)
        except ValueError as exc:
            raise ConfigError(f"policy: {exc}") from None
        for scenario in config.scenarios.values():
            for i, step in enumerate(scenario.steps):
                decision = classify(step, "read-write", self.policy)
                if decision.tier not in (Tier.READ, Tier.WRITE):
                    raise ConfigError(
                        f"scenarios.{scenario.name}.steps[{i}]: must be a read or write command, "
                        f"not {decision.tier.value} ({decision.reason})"
                    )
        limits = config.limits
        self._tickets = TicketStore(limits.ticket_ttl_seconds, clock=clock)
        self._ticket_servers: dict[str, tuple[str, float]] = {}   # ticket -> (server, expires_at)
        self._ticket_lock = threading.Lock()
        self._commands = RateLimiter(limits.commands_per_minute, clock=clock)
        self._confirmations = RateLimiter(limits.confirmations_per_minute, clock=clock)
        self._audit = AuditLog(config.audit_path)
        self._secrets: set[str] = set()
        self._secrets_lock = threading.Lock()

    # ================================================================================================ tools

    @_never_raise
    def list_servers(self) -> dict:
        """Every configured server: name, mode, dir and whether its RCON port answers a TCP connect."""
        servers = []
        for name, server in sorted(self.config.servers.items()):
            entry: dict[str, Any] = {"name": name, "mode": server.mode, "dir": str(server.dir)}
            try:
                host, port, _ = self._endpoint(server)
            except ConfigError as exc:
                entry.update(online=False, detail=str(exc))
            else:
                entry["online"] = _tcp_probe(host, port)
            servers.append(entry)
        return {"status": "ok", "servers": servers}

    @_never_raise
    def server_status(self, server: str) -> dict:
        cfg, error = self._server(server)
        if error:
            return error
        base: dict[str, Any] = {
            "server": cfg.name,
            "mode": cfg.mode,
            "process_rss_mb": self._process_rss_mb(cfg.dir),
            "mod_jars": _mod_jar_count(cfg.dir),
        }
        limited = self._rate_limit(self._commands, cfg, "server_status", "list")
        if limited:
            return limited
        try:
            list_text, tick_text = self._rcon(cfg, ["list", "tick query"])
        except ConfigError as exc:
            self._record(cfg, "server_status", "list", Tier.READ, "error", str(exc))
            return {"status": "error", "error": str(exc), **base}
        except RconError as exc:
            # A server that is down is a normal state for this tool, not an error.
            self._record(cfg, "server_status", "list", Tier.READ, "error", str(exc))
            return {"status": "ok", "online": False, "detail": str(exc),
                    "players_online": None, "players_max": None, **base}
        self._record(cfg, "server_status", "list; tick query", Tier.READ, "executed",
                     f"response chars: {len(list_text) + len(tick_text)}")
        result: dict[str, Any] = {"status": "ok", "online": True, **base}
        players = _parse_list(_clean(list_text))
        if players is None:
            result.update(players_online=None, players_max=None, players_raw=self._cut(list_text)[0])
        else:
            result.update(players_online=players[0], players_max=players[1], players=players[2])
        tick = _parse_tick(_clean(tick_text))
        if tick is None:
            result["tick_raw"] = self._cut(tick_text)[0]
        else:
            result["tick"] = tick
        return result

    @_never_raise
    def list_players(self, server: str) -> dict:
        cfg, error = self._server(server)
        if error:
            return error
        limited = self._rate_limit(self._commands, cfg, "list_players", "list")
        if limited:
            return limited
        try:
            with self._connect(cfg) as client:
                list_text = _clean(client.command("list"))
                parsed = _parse_list(list_text)
                if parsed is None:
                    self._record(cfg, "list_players", "list", Tier.READ, "executed", "unparseable list output")
                    return {"status": "error", "server": cfg.name,
                            "error": "could not parse the output of 'list'", "raw": self._cut(list_text)[0]}
                online, maximum, names = parsed
                players = []
                sent = 1
                for name in names[:MAX_PLAYERS]:
                    if not PLAYER_NAME_RE.match(name):
                        players.append({"name": _printable(name)[:40], "skipped": "unsafe name"})
                        continue
                    players.append(self._player_position(client, name))
                    sent += 2
        except ConfigError as exc:
            self._record(cfg, "list_players", "list", Tier.READ, "error", str(exc))
            return {"status": "error", "server": cfg.name, "error": str(exc)}
        except RconError as exc:
            self._record(cfg, "list_players", "list", Tier.READ, "error", str(exc))
            return {"status": "error", "server": cfg.name, "error": str(exc)}
        self._record(cfg, "list_players", "list; data get entity <name> Pos/Dimension", Tier.READ, "executed",
                     f"commands sent: {sent}")
        return {
            "status": "ok",
            "server": cfg.name,
            "players_online": online,
            "players_max": maximum,
            "players": players,
            "capped": len(names) > MAX_PLAYERS,
        }

    @_never_raise
    def list_mods(self, server: str) -> dict:
        cfg, error = self._server(server)
        if error:
            return error
        mods_dir = cfg.dir / "mods"
        if not mods_dir.is_dir():
            return {"status": "ok", "server": cfg.name, "mods": [], "count": 0, "detail": "no mods directory"}
        names = sorted(_printable(p.name)[:MAX_NAME_CHARS] for p in _mod_jars(mods_dir))
        return {"status": "ok", "server": cfg.name, "mods": names, "count": len(names)}

    @_never_raise
    def run_command(self, server: str, command: str) -> dict:
        cfg, error = self._server(server)
        if error:
            return error
        decision = classify(command, cfg.mode, self.policy)
        shown = decision.normalized
        if not decision.allowed and not decision.needs_confirmation:
            self._record(cfg, "run_command", shown, decision.tier, "refused", decision.reason)
            return {"status": "refused", "server": cfg.name, "command": shown, "tier": decision.tier.value,
                    "reason": decision.reason}
        limited = self._rate_limit(self._commands, cfg, "run_command", shown, decision.tier)
        if limited:
            return limited
        if decision.needs_confirmation:
            ticket = self._issue_ticket(cfg.name, shown)
            self._record(cfg, "run_command", shown, decision.tier, "ticket_issued", decision.reason)
            return {
                "status": "confirmation_required",
                "ticket": ticket,
                "command": shown,
                "server": cfg.name,
                "tier": decision.tier.value,
                "reason": decision.reason,
                "expires_in_seconds": self.config.limits.ticket_ttl_seconds,
                "next": "Call confirm_command with this ticket and the same command; a human will be asked "
                        "to approve it.",
            }
        return self._execute(cfg, "run_command", shown, decision.tier, "executed")

    @_never_raise
    def confirm_command(self, ticket: str, command: str) -> dict:
        if not isinstance(ticket, str) or not isinstance(command, str):
            return {"status": "error", "error": "ticket and command must be strings"}
        server_name = self._ticket_server(ticket)
        cfg = self.config.servers.get(server_name) if server_name else None
        if cfg is None:
            self._burn(ticket)
            self._audit_record(None, "confirm_command", "", None, "ticket_rejected",
                               "unknown, expired or already used ticket")
            return {"status": "refused", "reason": "unknown, expired or already used ticket"}
        decision = classify(command, cfg.mode, self.policy)
        shown = decision.normalized
        limited = self._rate_limit(self._confirmations, cfg, "confirm_command", shown, decision.tier)
        if limited:
            return limited  # the ticket is not consumed: the human may retry after the wait
        self._pop_ticket_server(ticket)
        ok, reason = self._tickets.redeem(ticket, cfg.name, shown)
        if not ok:
            self._record(cfg, "confirm_command", shown, decision.tier, "ticket_rejected", reason)
            return {"status": "refused", "server": cfg.name, "command": shown, "reason": reason}
        if cfg.mode != "read-write":
            reason = "server is read-only"
            self._record(cfg, "confirm_command", shown, decision.tier, "refused", reason)
            return {"status": "refused", "server": cfg.name, "command": shown, "reason": reason}
        if decision.tier is Tier.DENY or not (decision.allowed or decision.needs_confirmation):
            self._record(cfg, "confirm_command", shown, decision.tier, "refused", decision.reason)
            return {"status": "refused", "server": cfg.name, "command": shown, "reason": decision.reason}
        return self._execute(cfg, "confirm_command", shown, decision.tier, "confirmed")

    @_never_raise
    def tail_log(self, server: str, lines: int = 30, level: str | None = None, contains: str | None = None) -> dict:
        cfg, error = self._server(server)
        if error:
            return error
        self._learn_secret(cfg)
        try:
            result = logs.tail(cfg.log, cfg.dir, lines=lines, level=level, contains=contains)
        except (logs.LogError, OSError) as exc:
            return {"status": "error", "server": cfg.name, "error": _os_message(exc)}
        return {"status": "ok", "server": cfg.name, **result}

    @_never_raise
    def find_errors(self, server: str) -> dict:
        cfg, error = self._server(server)
        if error:
            return error
        self._learn_secret(cfg)
        try:
            result = logs.find_errors(cfg.dir, cfg.log, noise=self.config.log_noise)
        except (logs.LogError, OSError) as exc:
            return {"status": "error", "server": cfg.name, "error": _os_message(exc)}
        return {"status": "ok", "server": cfg.name, **result}

    @_never_raise
    def spawn_test(self, scenario: str) -> dict:
        found = self.config.scenarios.get(scenario) if isinstance(scenario, str) else None
        if found is None:
            valid = ", ".join(sorted(self.config.scenarios)) or "(none configured)"
            return {"status": "error", "error": f"unknown scenario {scenario!r}; valid scenarios: {valid}"}
        cfg = self.config.servers.get(found.server)
        if cfg is None:
            return {"status": "error", "scenario": found.name, "error": f"unknown server {found.server!r}"}
        head = {"scenario": found.name, "server": cfg.name}
        if cfg.mode != "read-write":
            reason = "scenarios only run on a read-write server"
            self._record(cfg, "spawn_test", "", None, "refused", f"{found.name}: {reason}")
            return {"status": "refused", **head, "reason": reason, "steps": []}

        decisions = [classify(step, cfg.mode, self.policy) for step in found.steps]
        for i, decision in enumerate(decisions):
            if decision.tier not in (Tier.READ, Tier.WRITE) or not decision.allowed:
                reason = f"step {i + 1} is not a read or write command: {decision.reason}"
                self._record(cfg, "spawn_test", decision.normalized, decision.tier, "refused",
                             f"{found.name}: {reason}")
                return {"status": "refused", **head, "reason": reason, "steps": [
                    {"command": decision.normalized, "status": "refused", "reason": decision.reason}]}

        limited = self._rate_limit(self._commands, cfg, "spawn_test", found.name)
        if limited:
            return {**limited, "scenario": found.name}
        return self._run_scenario(cfg, found, [d.normalized for d in decisions], [d.tier for d in decisions],
                                  head)

    # ================================================================================== used by server.py

    def pending_ticket(self, ticket: str, command: str) -> dict | None:
        """{"server", "command"} a ticket would run, without consuming it; None if the ticket is unknown.

        Used to show the human the exact command before asking (``--elicit``). The command is the
        caller's, normalized; redemption still checks it against the ticket.
        """
        if not isinstance(ticket, str) or not isinstance(command, str):
            return None
        server_name = self._ticket_server(ticket)
        cfg = self.config.servers.get(server_name) if server_name else None
        if cfg is None:
            return None
        return self._scrub({"server": cfg.name, "command": classify(command, cfg.mode, self.policy).normalized})

    @_never_raise
    def reject_ticket(self, ticket: str, command: str, reason: str) -> dict:
        """Burn `ticket` without running anything (the human declined) and audit it as ticket_rejected."""
        server_name = self._pop_ticket_server(ticket) if isinstance(ticket, str) else None
        cfg = self.config.servers.get(server_name) if server_name else None
        shown = classify(command, cfg.mode, self.policy).normalized if cfg and isinstance(command, str) else ""
        if isinstance(ticket, str):
            self._tickets.redeem(ticket, server_name or "", "")   # consumes it whatever the outcome
        self._audit_record(cfg.name if cfg else None, "confirm_command", shown, None, "ticket_rejected", reason)
        result: dict[str, Any] = {"status": "refused", "reason": reason}
        if cfg:
            result.update(server=cfg.name, command=shown)
        return result

    # ================================================================================================ helpers

    def _server(self, name: Any) -> tuple[ServerConfig, None] | tuple[None, dict]:
        cfg = self.config.servers.get(name) if isinstance(name, str) else None
        if cfg is None:
            valid = ", ".join(sorted(self.config.servers))
            return None, {"status": "error", "error": f"unknown server {name!r}; valid servers: {valid}"}
        return cfg, None

    def _endpoint(self, cfg: ServerConfig) -> tuple[str, int, str]:
        host, port, password = read_rcon_endpoint(cfg)
        with self._secrets_lock:
            self._secrets.add(password)
        return host, port, password

    def _learn_secret(self, cfg: ServerConfig) -> None:
        """Read the server's password (if any) so it can be scrubbed from log content too."""
        try:
            self._endpoint(cfg)
        except ConfigError:
            pass

    def _connect(self, cfg: ServerConfig) -> RconClient:
        host, port, password = self._endpoint(cfg)
        return RconClient(host, port, password)

    def _rcon(self, cfg: ServerConfig, commands: Sequence[str]) -> list[str]:
        """Run `commands` over one connection. Raises ConfigError / RconError."""
        with self._connect(cfg) as client:
            return [client.command(c) for c in commands]

    def _execute(self, cfg: ServerConfig, tool: str, command: str, tier: Tier, outcome: str) -> dict:
        try:
            response = self._rcon(cfg, [command])[0]
        except (ConfigError, RconError) as exc:
            self._record(cfg, tool, command, tier, "error", str(exc))
            return {"status": "error", "server": cfg.name, "command": command, "error": str(exc)}
        self._record(cfg, tool, command, tier, outcome, f"response chars: {len(response)}")
        text, truncated = self._cut(response)
        return {"status": "ok", "server": cfg.name, "command": command, "tier": tier.value,
                "response": text, "truncated": truncated}

    def _run_scenario(self, cfg: ServerConfig, scenario: Scenario, commands: list[str], tiers: list[Tier],
                      head: dict) -> dict:
        steps: list[dict] = []
        try:
            with self._connect(cfg) as client:
                parsed = _parse_list(_clean(client.command("list")))
                if parsed is None:
                    reason = "could not parse the output of 'list' to check who is online"
                    self._record(cfg, "spawn_test", "list", Tier.READ, "refused", f"{scenario.name}: {reason}")
                    return {"status": "refused", **head, "reason": reason, "steps": []}
                bot = re.compile(scenario.bot_pattern)
                humans = [n for n in parsed[2] if not bot.search(n)]
                if humans or (parsed[0] > 0 and not parsed[2]):
                    reason = (f"{parsed[0]} player(s) online and not every one matches bot_pattern "
                              f"{scenario.bot_pattern!r}")
                    self._record(cfg, "spawn_test", "list", Tier.READ, "refused", f"{scenario.name}: {reason}")
                    return {"status": "refused", **head, "reason": reason,
                            "players_not_matching": [_printable(n)[:40] for n in humans], "steps": []}
                for i, (command, tier) in enumerate(zip(commands, tiers)):
                    if i and scenario.step_delay_ms:
                        self._sleep(scenario.step_delay_ms / 1000)
                    try:
                        response = client.command(command)
                    except RconError as exc:
                        self._record(cfg, "spawn_test", command, tier, "error", f"{scenario.name}: {exc}")
                        steps.append({"command": command, "status": "error", "error": str(exc)})
                        return {"status": "error", **head, "error": f"step {i + 1} failed: {exc}",
                                "completed": False, "steps": steps}
                    self._record(cfg, "spawn_test", command, tier, "executed",
                                 f"{scenario.name}: response chars: {len(response)}")
                    text, truncated = self._cut(response)
                    steps.append({"command": command, "status": "ok", "response": text, "truncated": truncated})
        except (ConfigError, RconError) as exc:
            self._record(cfg, "spawn_test", "list", Tier.READ, "error", f"{scenario.name}: {exc}")
            return {"status": "error", **head, "error": str(exc), "completed": False, "steps": steps}
        return {"status": "ok", **head, "completed": True, "steps": steps}

    def _player_position(self, client: RconClient, name: str) -> dict:
        player: dict[str, Any] = {"name": name}
        pos_text = _clean(client.command(f"data get entity {name} Pos"))
        dim_text = _clean(client.command(f"data get entity {name} Dimension"))
        pos = _POS.search(pos_text)
        if pos:
            player.update(x=float(pos.group(1)), y=float(pos.group(2)), z=float(pos.group(3)))
        else:
            player["pos_raw"] = pos_text[:200]
        dim = _DIMENSION.search(dim_text)
        if dim:
            player["dimension"] = dim.group(1)
        else:
            player["dimension_raw"] = dim_text[:200]
        return player

    # -- tickets ---------------------------------------------------------------------------------------------

    def _issue_ticket(self, server: str, command: str) -> str:
        ticket = self._tickets.issue(server, command)
        with self._ticket_lock:
            now = self._clock()
            for old in [t for t, (_, expires) in self._ticket_servers.items() if now >= expires]:
                del self._ticket_servers[old]
            self._ticket_servers[ticket] = (server, now + self.config.limits.ticket_ttl_seconds)
        return ticket

    def _ticket_server(self, ticket: str) -> str | None:
        with self._ticket_lock:
            entry = self._ticket_servers.get(ticket)
        return entry[0] if entry else None

    def _pop_ticket_server(self, ticket: str) -> str | None:
        with self._ticket_lock:
            entry = self._ticket_servers.pop(ticket, None)
        return entry[0] if entry else None

    def _burn(self, ticket: str) -> None:
        self._pop_ticket_server(ticket)
        self._tickets.redeem(ticket, "", "")

    # -- limits, audit, output -------------------------------------------------------------------------------

    def _rate_limit(self, limiter: RateLimiter, cfg: ServerConfig, tool: str, command: str,
                    tier: Tier | None = None) -> dict | None:
        allowed, retry_after = limiter.allow(cfg.name)
        if allowed:
            return None
        seconds = max(1, int(retry_after + 0.999))
        self._record(cfg, tool, command, tier, "rate_limited", f"retry after {seconds} s")
        return {"status": "rate_limited", "server": cfg.name, "retry_after_seconds": seconds}

    def _record(self, cfg: ServerConfig, tool: str, command: str, tier: Tier | None, outcome: str,
                detail: str) -> None:
        self._audit_record(cfg.name, tool, command, tier, outcome, detail)

    def _audit_record(self, server: str | None, tool: str, command: str, tier: Tier | None, outcome: str,
                      detail: str) -> None:
        if outcome not in AUDITED_OUTCOMES:
            raise ValueError(f"unknown audit outcome {outcome!r}")
        try:
            self._audit.record(**self._scrub({
                "server": server,
                "tool": tool,
                "command": command,
                "tier": tier.value if tier else None,
                "outcome": outcome,
                "detail": detail,
            }))
        except OSError as exc:
            # Never turn an executed command into an "error" result (the model would retry it). Say it on stderr,
            # which is not the MCP channel on stdio.
            print(f"minecraft-rcon-mcp: cannot write the audit log: {exc.strerror or exc}", file=sys.stderr)

    def _cut(self, text: str) -> tuple[str, bool]:
        text = _clean(text)
        limit = self.config.limits.max_response_chars
        if len(text) > limit:
            return text[:limit], True
        return text, False

    def _scrub(self, value: Any) -> Any:
        with self._secrets_lock:
            secrets = sorted(self._secrets, key=len, reverse=True)
        return _replace_secrets(value, secrets) if secrets else value

    def _process_rss_mb(self, server_dir: Path) -> float | None:
        """RSS of a `java` process whose working directory is `server_dir`; None if none or not Linux."""
        if not sys.platform.startswith("linux") and self._proc_root == Path("/proc"):
            return None
        try:
            target = server_dir.resolve()
            entries = list(self._proc_root.iterdir())
        except OSError:
            return None
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                if (entry / "comm").read_text().strip() != "java":
                    continue
                if Path(os.readlink(entry / "cwd")).resolve() != target:
                    continue
                for line in (entry / "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        return round(int(line.split()[1]) / 1024, 1)
            except (OSError, ValueError, IndexError):
                continue
        return None


# ==================================================================================================== pure


def _replace_secrets(value: Any, secrets: Sequence[str]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            if secret and secret in value:
                value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, dict):
        return {_replace_secrets(k, secrets): _replace_secrets(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_replace_secrets(v, secrets) for v in value]
    return value


def _clean(text: str) -> str:
    """Strip `§x` color codes and control characters other than newline."""
    return _UNPRINTABLE.sub("", _COLOR.sub("", text))


def _printable(text: str) -> str:
    return _UNPRINTABLE.sub("", text).replace("\n", " ")


def _parse_list(text: str) -> tuple[int, int, list[str]] | None:
    """(online, max, names) from `list` output, or None if the format is unknown."""
    match = _LIST.search(text)
    if not match:
        return None
    names = [n.strip() for n in re.split(r",\s*", match.group("names").strip()) if n.strip()]
    return int(match.group("online")), int(match.group("max")), names


def _parse_tick(text: str) -> dict | None:
    """Tick times in ms from `tick query` output, or None if no average could be found."""
    values: dict[str, float] = {}
    for key, regex in _TICK_FIELDS.items():
        match = regex.search(text)
        if match:
            try:
                values[key] = float(match.group(1).replace(",", "."))
            except ValueError:
                pass
    if "average_ms" not in values:
        return None
    result: dict[str, Any] = dict(values)
    first = text.strip().splitlines()[0]
    if not any(regex.search(first) for regex in _TICK_FIELDS.values()) and "tick rate" not in first:
        result["state"] = first[:120]   # e.g. "The game is running normally" / "The game is frozen"
    return result


def _mod_jars(mods_dir: Path) -> list[Path]:
    try:
        return [p for p in mods_dir.iterdir() if p.name.lower().endswith(".jar") and p.is_file()]
    except OSError:
        return []


def _mod_jar_count(server_dir: Path) -> int | None:
    mods_dir = server_dir / "mods"
    if not mods_dir.is_dir():
        return None
    return len(_mod_jars(mods_dir))


def _tcp_probe(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def _os_message(exc: Exception) -> str:
    if isinstance(exc, OSError):
        return f"cannot read the log: {exc.strerror or type(exc).__name__}"
    return str(exc)
