from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from minecraft_rcon_mcp.config import (
    DEFAULT_CONFIG_PATH,
    ENV_VAR,
    Config,
    ConfigError,
    Limits,
    ServerConfig,
    load_config,
    parse_properties,
    read_rcon_endpoint,
    resolve_config_path,
)

FULL = """
[servers.test]
dir  = "{dir}"
mode = "read-write"
host = "127.0.0.1"
log  = "logs/latest.log"

[servers.live]
dir  = "~/minecraft/live-server"
mode = "read-only"

[limits]
commands_per_minute = 30
confirmations_per_minute = 5
max_response_chars = 4000
ticket_ttl_seconds = 60

[audit]
path = "~/.local/state/minecraft-rcon-mcp/audit.jsonl"

[policy]
read    = ["mymod status *"]
write   = ["mymod boss reset *"]
confirm = []

[log_noise]
patterns = ["Couldn't parse data file"]

[scenarios.boss_phase2]
server = "test"
bot_pattern = "^Bot"
steps = ["execute in minecraft:overworld run forceload add 0 0", "player Bot1 spawn at 0 64 0"]
step_delay_ms = 250
"""

MINIMAL = """
[servers.test]
dir = "/srv/test"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def load_text(tmp_path: Path, text: str) -> Config:
    return load_config(write(tmp_path, text))


def error_for(tmp_path: Path, text: str) -> str:
    with pytest.raises(ConfigError) as info:
        load_text(tmp_path, text)
    return str(info.value)


# -- loading ---------------------------------------------------------------------------------------------------


def test_full_example(tmp_path: Path) -> None:
    cfg = load_text(tmp_path, FULL.format(dir=tmp_path / "srv"))
    test = cfg.servers["test"]
    assert test == ServerConfig(
        name="test",
        dir=tmp_path / "srv",
        mode="read-write",
        host="127.0.0.1",
        log=tmp_path / "srv" / "logs" / "latest.log",
        allow_remote=False,
    )
    live = cfg.servers["live"]
    assert live.mode == "read-only"
    assert live.dir == Path.home() / "minecraft" / "live-server"
    assert cfg.limits == Limits(30, 5, 4000, 60)
    assert cfg.audit_path == Path.home() / ".local/state/minecraft-rcon-mcp/audit.jsonl"
    assert cfg.policy_extra == {"read": ("mymod status *",), "write": ("mymod boss reset *",), "confirm": ()}
    assert cfg.log_noise == ("Couldn't parse data file",)
    scenario = cfg.scenarios["boss_phase2"]
    assert scenario.server == "test" and scenario.bot_pattern == "^Bot" and scenario.step_delay_ms == 250
    assert scenario.steps == (
        "execute in minecraft:overworld run forceload add 0 0",
        "player Bot1 spawn at 0 64 0",
    )


def test_defaults(tmp_path: Path) -> None:
    cfg = load_text(tmp_path, MINIMAL)
    server = cfg.servers["test"]
    assert server.mode == "read-only"
    assert server.host == "127.0.0.1"
    assert server.log == Path("/srv/test/logs/latest.log")
    assert server.allow_remote is False
    assert cfg.limits == Limits(30, 5, 4000, 60)
    assert cfg.audit_path == Path.home() / ".local/state/minecraft-rcon-mcp/audit.jsonl"
    assert cfg.policy_extra == {} and cfg.log_noise == () and cfg.scenarios == {}


def test_frozen(tmp_path: Path) -> None:
    cfg = load_text(tmp_path, MINIMAL)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.servers["test"].mode = "read-write"  # type: ignore[misc]


def test_absolute_log_path(tmp_path: Path) -> None:
    cfg = load_text(tmp_path, MINIMAL + 'log = "/var/log/mc.log"\n')
    assert cfg.servers["test"].log == Path("/var/log/mc.log")


def test_scenario_steps_stored_verbatim(tmp_path: Path) -> None:
    # config.py does not classify: even a dangerous step is stored as given (the service refuses it).
    text = MINIMAL + '[scenarios.s]\nserver = "test"\nbot_pattern = "^Bot"\nsteps = ["stop"]\n'
    assert load_text(tmp_path, text).scenarios["s"].steps == ("stop",)


def test_remote_host_allowed_with_flag(tmp_path: Path) -> None:
    cfg = load_text(tmp_path, MINIMAL + 'host = "10.0.0.5"\nallow_remote = true\n')
    assert cfg.servers["test"].host == "10.0.0.5"


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1", "localhost", "LOCALHOST"])
def test_loopback_hosts_accepted(tmp_path: Path, host: str) -> None:
    assert load_text(tmp_path, MINIMAL + f'host = "{host}"\n').servers["test"].host == host


# -- path resolution -------------------------------------------------------------------------------------------


def test_path_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert resolve_config_path() == Path(DEFAULT_CONFIG_PATH).expanduser()
    env_path = write(tmp_path, MINIMAL)
    monkeypatch.setenv(ENV_VAR, str(env_path))
    assert resolve_config_path() == env_path
    assert "test" in load_config().servers
    explicit = tmp_path / "other.toml"
    assert resolve_config_path(explicit) == explicit


def test_tilde_expanded_in_explicit_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "c.toml").write_text(MINIMAL)
    assert "test" in load_config(Path("~/c.toml")).servers


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


def test_invalid_toml(tmp_path: Path) -> None:
    assert "not valid TOML" in error_for(tmp_path, "[servers.test\n")


# -- validation errors name the key ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("", "servers"),
        ("servers = 1\n", "servers"),
        ("[servers]\n", "servers"),
        (MINIMAL + "[bogus]\n", "bogus"),
        ('[servers."bad name"]\ndir = "/x"\n', "servers.bad name"),
        ("[servers.test]\nmode = 'read-only'\n", "servers.test.dir"),
        ("[servers.test]\ndir = ''\n", "servers.test.dir"),
        ("[servers.test]\ndir = 3\n", "servers.test.dir"),
        (MINIMAL + "mode = 'admin'\n", "servers.test.mode"),
        (MINIMAL + "host = 5\n", "servers.test.host"),
        (MINIMAL + "host = '10.0.0.5'\n", "servers.test.host"),
        (MINIMAL + "host = 'mc.example.com'\n", "servers.test.host"),
        (MINIMAL + "allow_remote = 'yes'\n", "servers.test.allow_remote"),
        (MINIMAL + "log = 7\n", "servers.test.log"),
        (MINIMAL + "password = 'x'\n", "servers.test.password"),
        (MINIMAL + "[limits]\ncommands_per_minute = 0\n", "limits.commands_per_minute"),
        (MINIMAL + "[limits]\nconfirmations_per_minute = -2\n", "limits.confirmations_per_minute"),
        (MINIMAL + "[limits]\nmax_response_chars = 'big'\n", "limits.max_response_chars"),
        (MINIMAL + "[limits]\nticket_ttl_seconds = true\n", "limits.ticket_ttl_seconds"),
        (MINIMAL + "[limits]\nticket_ttl_seconds = 1.5\n", "limits.ticket_ttl_seconds"),
        (MINIMAL + "[limits]\nburst = 3\n", "limits.burst"),
        (MINIMAL + "limits = 3\n", "servers.test.limits"),
        (MINIMAL + "[audit]\npath = 1\n", "audit.path"),
        (MINIMAL + "[audit]\nfile = 'x'\n", "audit.file"),
        (MINIMAL + "[policy]\nread = 'list'\n", "policy.read"),
        (MINIMAL + "[policy]\nwrite = ['ok', 3]\n", "policy.write[1]"),
        (MINIMAL + "[policy]\ndeny = ['  ']\n", "policy.deny[0]"),
        (MINIMAL + "[policy]\nallow = []\n", "policy.allow"),
        (MINIMAL + "[log_noise]\npatterns = ['(']\n", "log_noise.patterns[0]"),
        (MINIMAL + "[log_noise]\nregex = []\n", "log_noise.regex"),
        (MINIMAL + "[scenarios.s]\nbot_pattern = '^Bot'\nsteps = ['list']\n", "scenarios.s.server"),
        (MINIMAL + "[scenarios.s]\nserver = 'nope'\nbot_pattern = '^B'\nsteps = ['list']\n", "scenarios.s.server"),
        (MINIMAL + "[scenarios.s]\nserver = 'test'\nsteps = ['list']\n", "scenarios.s.bot_pattern"),
        (MINIMAL + "[scenarios.s]\nserver = 'test'\nbot_pattern = '['\nsteps = ['l']\n", "scenarios.s.bot_pattern"),
        (MINIMAL + "[scenarios.s]\nserver = 'test'\nbot_pattern = '^B'\n", "scenarios.s.steps"),
        (MINIMAL + "[scenarios.s]\nserver = 'test'\nbot_pattern = '^B'\nsteps = []\n", "scenarios.s.steps"),
        (MINIMAL + "[scenarios.s]\nserver = 'test'\nbot_pattern = '^B'\nsteps = [1]\n", "scenarios.s.steps[0]"),
        (
            MINIMAL + "[scenarios.s]\nserver = 'test'\nbot_pattern = '^B'\nsteps = ['l']\nstep_delay_ms = -1\n",
            "scenarios.s.step_delay_ms",
        ),
        (
            MINIMAL + "[scenarios.s]\nserver = 'test'\nbot_pattern = '^B'\nsteps = ['l']\nrepeat = 2\n",
            "scenarios.s.repeat",
        ),
        (MINIMAL + "[scenarios]\ns = 1\n", "scenarios.s"),
    ],
)
def test_errors_name_the_key(tmp_path: Path, text: str, key: str) -> None:
    message = error_for(tmp_path, text)
    assert message.startswith(f"{key}:"), message


# -- server.properties -----------------------------------------------------------------------------------------

SECRET = "pa:ss=w\\rd!#"


def make_server(tmp_path: Path, properties: str | None, **overrides) -> ServerConfig:
    directory = tmp_path / "server"
    directory.mkdir(exist_ok=True)
    if properties is not None:
        (directory / "server.properties").write_text(properties, encoding="utf-8")
    fields = dict(
        name="test",
        dir=directory,
        mode="read-write",
        host="127.0.0.1",
        log=directory / "logs/latest.log",
        allow_remote=False,
    )
    fields.update(overrides)
    return ServerConfig(**fields)


GOOD_PROPS = (
    "#Minecraft server properties\n"
    "#Thu Nov 12 10:00:00 UTC 2026\n"
    "enable-rcon=true\n"
    "rcon.port=25575\n"
    "rcon.password=pa\\:ss\\=w\\\\rd\\!\\#\n"
    "server-port=25565\n"
)


def test_read_rcon_endpoint(tmp_path: Path) -> None:
    server = make_server(tmp_path, GOOD_PROPS)
    assert read_rcon_endpoint(server) == ("127.0.0.1", 25575, SECRET)


def test_read_rcon_endpoint_reads_at_call_time(tmp_path: Path) -> None:
    server = make_server(tmp_path, GOOD_PROPS)
    assert read_rcon_endpoint(server)[1] == 25575
    (server.dir / "server.properties").write_text(GOOD_PROPS.replace("25575", "25580"))
    assert read_rcon_endpoint(server)[1] == 25580


@pytest.mark.parametrize(
    ("props", "needle"),
    [
        (None, "not found"),
        (GOOD_PROPS.replace("enable-rcon=true", "enable-rcon=false"), "enable-rcon"),
        (GOOD_PROPS.replace("enable-rcon=true\n", ""), "enable-rcon"),
        (GOOD_PROPS.replace("rcon.port=25575\n", ""), "rcon.port"),
        (GOOD_PROPS.replace("rcon.port=25575", "rcon.port=abc"), "rcon.port"),
        (GOOD_PROPS.replace("rcon.port=25575", "rcon.port=70000"), "rcon.port"),
        (GOOD_PROPS.replace("rcon.password=pa\\:ss\\=w\\\\rd\\!\\#\n", ""), "rcon.password"),
        (GOOD_PROPS.replace("rcon.password=pa\\:ss\\=w\\\\rd\\!\\#", "rcon.password="), "rcon.password"),
    ],
)
def test_read_rcon_endpoint_errors(tmp_path: Path, props: str | None, needle: str) -> None:
    server = make_server(tmp_path, props)
    with pytest.raises(ConfigError) as info:
        read_rcon_endpoint(server)
    message = str(info.value)
    assert needle in message
    assert message.startswith("servers.test")
    assert SECRET not in message and "pa\\:ss" not in message


def test_read_rcon_endpoint_missing_dir(tmp_path: Path) -> None:
    server = ServerConfig("test", tmp_path / "gone", "read-only", "127.0.0.1", tmp_path / "gone/l.log", False)
    with pytest.raises(ConfigError, match="not found"):
        read_rcon_endpoint(server)


def test_read_rcon_endpoint_refuses_remote_host(tmp_path: Path) -> None:
    server = make_server(tmp_path, GOOD_PROPS, host="192.168.1.20")
    with pytest.raises(ConfigError, match="servers.test.host"):
        read_rcon_endpoint(server)
    remote_ok = make_server(tmp_path, GOOD_PROPS, host="192.168.1.20", allow_remote=True)
    assert read_rcon_endpoint(remote_ok) == ("192.168.1.20", 25575, SECRET)


def test_parse_properties_format() -> None:
    text = (
        "# comment\n"
        "! also comment\n"
        "  key1 = value one  \n"
        "key2:value2\n"
        "key3 value3\n"
        "multi=first \\\n"
        "    second\n"
        "unicode=\\u00f1and\\u00fa\n"
        "empty=\n"
        "esc\\=key=v\n"
    )
    props = parse_properties(text)
    assert props["key1"] == "value one  "
    assert props["key2"] == "value2"
    assert props["key3"] == "value3"
    assert props["multi"] == "first second"
    assert props["unicode"] == "ñandú"
    assert props["empty"] == ""
    assert props["esc=key"] == "v"
    assert "# comment" not in props
