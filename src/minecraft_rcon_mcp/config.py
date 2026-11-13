"""TOML configuration → frozen dataclasses. See docs/DESIGN.md §3.

The RCON password is never part of the configuration: :func:`read_rcon_endpoint` reads it from the server's
``server.properties`` at call time. Scenario steps are stored as given; classifying them is the service
layer's job.
"""
from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ConfigError",
    "ServerConfig",
    "Limits",
    "Scenario",
    "Config",
    "ENV_VAR",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_AUDIT_PATH",
    "MODES",
    "load_config",
    "resolve_config_path",
    "read_rcon_endpoint",
    "is_loopback_host",
]

ENV_VAR = "MINECRAFT_RCON_MCP_CONFIG"
DEFAULT_CONFIG_PATH = "~/.config/minecraft-rcon-mcp/config.toml"
DEFAULT_AUDIT_PATH = "~/.local/state/minecraft-rcon-mcp/audit.jsonl"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_LOG = "logs/latest.log"
MODES = ("read-only", "read-write")
POLICY_TIERS = ("read", "write", "confirm", "deny")
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ConfigError(ValueError):
    """Invalid or unusable configuration. The message names the offending key; it never contains a password."""


@dataclass(frozen=True)
class ServerConfig:
    name: str
    dir: Path
    mode: str
    host: str
    log: Path
    allow_remote: bool


@dataclass(frozen=True)
class Limits:
    commands_per_minute: int = 30
    confirmations_per_minute: int = 5
    max_response_chars: int = 4000
    ticket_ttl_seconds: int = 60


@dataclass(frozen=True)
class Scenario:
    name: str
    server: str
    bot_pattern: str
    steps: tuple[str, ...]
    step_delay_ms: int


@dataclass(frozen=True)
class Config:
    servers: dict[str, ServerConfig]
    limits: Limits
    audit_path: Path
    policy_extra: dict[str, tuple[str, ...]]
    log_noise: tuple[str, ...]
    scenarios: dict[str, Scenario]


# -- loading ---------------------------------------------------------------------------------------------------


def resolve_config_path(path: Path | None = None) -> Path:
    """`path` (from --config), else $MINECRAFT_RCON_MCP_CONFIG, else ~/.config/minecraft-rcon-mcp/config.toml."""
    if path is None:
        env = os.environ.get(ENV_VAR)
        path = Path(env) if env else Path(DEFAULT_CONFIG_PATH)
    return Path(path).expanduser()


def load_config(path: Path | None = None) -> Config:
    """Read and validate the configuration file. Raises ConfigError."""
    resolved = resolve_config_path(path)
    try:
        raw = resolved.read_bytes()
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {resolved}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config file {resolved}: {exc.strerror}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"config file {resolved} is not valid TOML: {exc}") from None
    return parse_config(data)


def parse_config(data: dict[str, Any]) -> Config:
    """Validate an already-parsed TOML document. Raises ConfigError."""
    _check_keys(data, "", {"servers", "limits", "audit", "policy", "log_noise", "scenarios"})

    servers_raw = _table(data, "servers", required=True)
    if not servers_raw:
        raise ConfigError("servers: at least one [servers.<name>] table is required")
    servers = {name: _parse_server(name, value) for name, value in servers_raw.items()}

    limits = _parse_limits(_table(data, "limits"))

    audit = _table(data, "audit")
    _check_keys(audit, "audit", {"path"})
    audit_path = Path(_str(audit, "audit", "path", DEFAULT_AUDIT_PATH)).expanduser()

    policy = _table(data, "policy")
    _check_keys(policy, "policy", set(POLICY_TIERS))
    policy_extra = {tier: _str_list(policy, "policy", tier) for tier in POLICY_TIERS if tier in policy}

    noise = _table(data, "log_noise")
    _check_keys(noise, "log_noise", {"patterns"})
    log_noise = _str_list(noise, "log_noise", "patterns") if "patterns" in noise else ()
    for i, pattern in enumerate(log_noise):
        _check_regex(pattern, f"log_noise.patterns[{i}]")

    scenarios_raw = _table(data, "scenarios")
    scenarios = {name: _parse_scenario(name, value, servers) for name, value in scenarios_raw.items()}

    return Config(
        servers=servers,
        limits=limits,
        audit_path=audit_path,
        policy_extra=policy_extra,
        log_noise=log_noise,
        scenarios=scenarios,
    )


def _parse_server(name: str, value: Any) -> ServerConfig:
    key = f"servers.{name}"
    if not _NAME_RE.match(name):
        raise ConfigError(f"{key}: server names may only use letters, digits, '-' and '_' (max 64)")
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: must be a table")
    _check_keys(value, key, {"dir", "mode", "host", "log", "allow_remote"})
    if "dir" not in value:
        raise ConfigError(f"{key}.dir: is required")
    directory = Path(_str(value, key, "dir")).expanduser()
    mode = _str(value, key, "mode", "read-only")
    if mode not in MODES:
        raise ConfigError(f"{key}.mode: must be one of {', '.join(MODES)}")
    host = _str(value, key, "host", DEFAULT_HOST)
    allow_remote = value.get("allow_remote", False)
    if not isinstance(allow_remote, bool):
        raise ConfigError(f"{key}.allow_remote: must be true or false")
    if not allow_remote and not is_loopback_host(host):
        raise ConfigError(f"{key}.host: {host!r} is not a loopback address; set allow_remote = true to allow it")
    log = directory / Path(_str(value, key, "log", DEFAULT_LOG)).expanduser()
    return ServerConfig(name=name, dir=directory, mode=mode, host=host, log=log, allow_remote=allow_remote)


def _parse_limits(table: dict[str, Any]) -> Limits:
    defaults = Limits()
    fields = ("commands_per_minute", "confirmations_per_minute", "max_response_chars", "ticket_ttl_seconds")
    _check_keys(table, "limits", set(fields))
    values = {}
    for field in fields:
        value = table.get(field, getattr(defaults, field))
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigError(f"limits.{field}: must be a positive integer")
        values[field] = value
    return Limits(**values)


def _parse_scenario(name: str, value: Any, servers: dict[str, ServerConfig]) -> Scenario:
    key = f"scenarios.{name}"
    if not _NAME_RE.match(name):
        raise ConfigError(f"{key}: scenario names may only use letters, digits, '-' and '_' (max 64)")
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: must be a table")
    _check_keys(value, key, {"server", "bot_pattern", "steps", "step_delay_ms"})
    for required in ("server", "bot_pattern", "steps"):
        if required not in value:
            raise ConfigError(f"{key}.{required}: is required")
    server = _str(value, key, "server")
    if server not in servers:
        raise ConfigError(f"{key}.server: unknown server {server!r}")
    bot_pattern = _str(value, key, "bot_pattern")
    if not bot_pattern:
        raise ConfigError(f"{key}.bot_pattern: must not be empty")
    _check_regex(bot_pattern, f"{key}.bot_pattern")
    steps = _str_list(value, key, "steps")
    if not steps:
        raise ConfigError(f"{key}.steps: must contain at least one command")
    delay = value.get("step_delay_ms", 250)
    if isinstance(delay, bool) or not isinstance(delay, int) or not 0 <= delay <= 60_000:
        raise ConfigError(f"{key}.step_delay_ms: must be an integer between 0 and 60000")
    return Scenario(name=name, server=server, bot_pattern=bot_pattern, steps=steps, step_delay_ms=delay)


# -- small validators ------------------------------------------------------------------------------------------


def _check_keys(table: dict[str, Any], prefix: str, allowed: set[str]) -> None:
    for key in table:
        if key not in allowed:
            full = f"{prefix}.{key}" if prefix else key
            raise ConfigError(f"{full}: unknown key (allowed: {', '.join(sorted(allowed))})")


def _table(data: dict[str, Any], key: str, required: bool = False) -> dict[str, Any]:
    if key not in data:
        if required:
            raise ConfigError(f"{key}: is required")
        return {}
    value = data[key]
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: must be a table")
    return value


def _str(table: dict[str, Any], prefix: str, key: str, default: str | None = None) -> str:
    value = table.get(key, default)
    if not isinstance(value, str) or (default is None and not value):
        raise ConfigError(f"{prefix}.{key}: must be a non-empty string")
    return value


def _str_list(table: dict[str, Any], prefix: str, key: str) -> tuple[str, ...]:
    value = table.get(key)
    if not isinstance(value, list):
        raise ConfigError(f"{prefix}.{key}: must be a list of strings")
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"{prefix}.{key}[{i}]: must be a non-empty string")
    return tuple(value)


def _check_regex(pattern: str, key: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"{key}: invalid regular expression ({exc})") from None


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


# -- server.properties -----------------------------------------------------------------------------------------


def read_rcon_endpoint(server: ServerConfig) -> tuple[str, int, str]:
    """(host, port, password) for `server`, read from `<dir>/server.properties` now. Raises ConfigError.

    Error messages never include the password.
    """
    if not server.allow_remote and not is_loopback_host(server.host):
        raise ConfigError(
            f"servers.{server.name}.host: {server.host!r} is not a loopback address; set allow_remote = true"
        )
    props_path = server.dir / "server.properties"
    try:
        text = props_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise ConfigError(f"servers.{server.name}: {props_path} not found") from None
    except OSError as exc:
        raise ConfigError(f"servers.{server.name}: cannot read {props_path}: {exc.strerror}") from None
    props = parse_properties(text)

    if props.get("enable-rcon", "").strip().lower() != "true":
        raise ConfigError(f"servers.{server.name}: enable-rcon is not true in {props_path}")
    port_text = props.get("rcon.port", "").strip()
    if not port_text:
        raise ConfigError(f"servers.{server.name}: rcon.port is missing in {props_path}")
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ConfigError(f"servers.{server.name}: rcon.port in {props_path} is not a valid port")
    password = props.get("rcon.password", "")
    if not password:
        raise ConfigError(f"servers.{server.name}: rcon.password is missing or empty in {props_path}")
    return server.host, port, password


def parse_properties(text: str) -> dict[str, str]:
    """Parse the Java .properties format (comments, `=`/`:`/space separators, escapes, line continuations)."""
    result: dict[str, str] = {}
    logical: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.lstrip()
        if not pending and (not line or line[0] in "#!"):
            continue
        # A line ending in an odd number of backslashes continues on the next line.
        trailing = len(line) - len(line.rstrip("\\"))
        if trailing % 2 == 1:
            pending += line[:-1]
            continue
        logical.append(pending + line)
        pending = ""
    if pending:
        logical.append(pending)

    for line in logical:
        key_chars: list[str] = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == "\\" and i + 1 < len(line):
                key_chars.append(line[i : i + 2])
                i += 2
                continue
            if ch in "=: \t\f":
                break
            key_chars.append(ch)
            i += 1
        # Skip whitespace, at most one separator, then whitespace.
        while i < len(line) and line[i] in " \t\f":
            i += 1
        if i < len(line) and line[i] in "=:":
            i += 1
        while i < len(line) and line[i] in " \t\f":
            i += 1
        result[_unescape("".join(key_chars))] = _unescape(line[i:])
    return result


_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}


def _unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != "\\" or i + 1 >= len(value):
            out.append(ch)
            i += 1
            continue
        nxt = value[i + 1]
        if nxt == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", value[i + 2 : i + 6]):
            out.append(chr(int(value[i + 2 : i + 6], 16)))
            i += 6
            continue
        out.append(_ESCAPES.get(nxt, nxt))
        i += 2
    return "".join(out)
