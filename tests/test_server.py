"""MCP layer through the SDK's in-memory client (DESIGN §9 group 6)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import types
from mcp.client.client import Client

from minecraft_rcon_mcp import __version__
from minecraft_rcon_mcp.server import INSTRUCTIONS, REQUIRES_USER_INTERACTION, build_server, main
from test_service import LIST_EMPTY, Env

READ_TOOLS = {"list_servers", "server_status", "list_players", "list_mods", "tail_log", "find_errors"}
ALL_TOOLS = READ_TOOLS | {"run_command", "confirm_command", "spawn_test"}
SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture
def env(tmp_path, fake_rcon) -> Env:
    fake_rcon.responses = {"list": LIST_EMPTY, "stop": "Stopping the server"}
    return Env(tmp_path, fake_rcon)


def run(coro_fn, *args: Any) -> Any:
    return anyio.run(coro_fn, *args)


async def tools_of(server) -> dict[str, types.Tool]:
    async with Client(server) as client:
        return {tool.name: tool for tool in (await client.list_tools()).tools}


def payload(result: types.CallToolResult) -> dict:
    assert result.is_error is False
    assert result.structured_content is not None
    assert json.loads(result.content[0].text) == result.structured_content
    return result.structured_content


# ============================================================================================ tool list


def test_tool_list_and_annotations(env):
    tools = run(tools_of, build_server(env.service))
    assert set(tools) == ALL_TOOLS
    for name in READ_TOOLS:
        assert tools[name].annotations.read_only_hint is True, name
        assert tools[name].annotations.destructive_hint is False, name
    for name in ("run_command", "spawn_test"):
        assert tools[name].annotations.read_only_hint is False
        assert tools[name].annotations.destructive_hint is False
    confirm = tools["confirm_command"]
    assert confirm.annotations.destructive_hint is True and confirm.annotations.read_only_hint is False
    assert confirm.meta[REQUIRES_USER_INTERACTION] is True
    for name, tool in tools.items():
        assert tool.description and len(tool.description) > 80, name
        if name != "confirm_command":
            assert not (tool.meta or {}).get(REQUIRES_USER_INTERACTION), name
    assert "ticket" in tools["run_command"].description and "confirm_command" in tools["run_command"].description
    assert "human" in tools["run_command"].description
    assert set(confirm.input_schema["required"]) == {"ticket", "command"}
    assert "server" not in confirm.input_schema["properties"]
    assert set(tools["tail_log"].input_schema["required"]) == {"server"}


def test_no_confirm_tool_removes_it(env):
    tools = run(tools_of, build_server(env.service, confirm_tool=False))
    assert set(tools) == ALL_TOOLS - {"confirm_command"}
    assert "cannot be run" in tools["run_command"].description


def test_elicit_keeps_the_same_tool_shape(env):
    tools = run(tools_of, build_server(env.service, elicit=True))
    confirm = tools["confirm_command"]
    assert confirm.meta[REQUIRES_USER_INTERACTION] is True
    assert set(confirm.input_schema["properties"]) == {"ticket", "command"}     # ctx is not an argument


def test_instructions(env):
    async def go():
        async with Client(build_server(env.service), mode="legacy") as client:
            return client.session.initialize_result

    init = run(go)
    assert init.instructions == INSTRUCTIONS
    assert "untrusted" in INSTRUCTIONS and "human" in INSTRUCTIONS
    assert init.server_info.name == "minecraft-rcon-mcp" and init.server_info.version == __version__


# ============================================================================================ calls


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_run_command_ticket_confirm_round_trip(env, mode):
    async def go():
        async with Client(build_server(env.service), mode=mode) as client:
            issued = payload(await client.call_tool("run_command", {"server": "test", "command": "/stop"}))
            assert issued["status"] == "confirmation_required"
            assert env.fake.received == []
            done = payload(await client.call_tool("confirm_command",
                                                  {"ticket": issued["ticket"], "command": "stop"}))
            again = payload(await client.call_tool("confirm_command",
                                                   {"ticket": issued["ticket"], "command": "stop"}))
            return done, again

    done, again = run(go)
    assert done["status"] == "ok" and done["response"] == "Stopping the server"
    assert again["status"] == "refused"
    assert env.fake.received == ["stop"]
    assert env.outcomes() == ["ticket_issued", "confirmed", "ticket_rejected"]


def test_read_tools_through_mcp(env):
    async def go():
        async with Client(build_server(env.service)) as client:
            servers = payload(await client.call_tool("list_servers", {}))
            status = payload(await client.call_tool("server_status", {"server": "test"}))
            mods = payload(await client.call_tool("list_mods", {"server": "test"}))
            missing = payload(await client.call_tool("tail_log", {"server": "test", "level": "WARN"}))
            bad = await client.call_tool("tail_log", {"server": "test", "lines": 500})
            return servers, status, mods, missing, bad

    servers, status, mods, missing, bad = run(go)
    assert {s["name"] for s in servers["servers"]} == {"test", "live"}
    assert status["online"] is True and status["players_online"] == 0
    assert mods["mods"] == []
    assert missing["status"] == "error"
    assert bad.is_error is True          # schema validation: lines is 1..100


def test_refused_command_through_mcp(env):
    async def go():
        async with Client(build_server(env.service)) as client:
            return payload(await client.call_tool("run_command", {"server": "live", "command": "say hi"}))

    assert run(go)["status"] == "refused"
    assert env.fake.received == []


def test_without_confirm_tool_a_ticket_cannot_be_redeemed(env):
    async def go():
        async with Client(build_server(env.service, confirm_tool=False)) as client:
            issued = payload(await client.call_tool("run_command", {"server": "test", "command": "stop"}))
            redeem = await client.call_tool("confirm_command", {"ticket": issued["ticket"], "command": "stop"})
            return issued, redeem

    issued, redeem = run(go)
    assert issued["status"] == "confirmation_required"
    assert redeem.is_error is True
    assert env.fake.received == []


# ============================================================================================ --elicit


def elicitation_answer(action: str, content: dict | None, seen: list):
    async def callback(context, params: types.ElicitRequestParams):
        seen.append(params)
        return types.ElicitResult(action=action, content=content)

    return callback


def elicit_call(env: Env, *, mode: str = "legacy", callback=None, command: str = "stop") -> dict:
    async def go():
        server = build_server(env.service, elicit=True)
        async with Client(server, mode=mode, elicitation_callback=callback) as client:
            issued = payload(await client.call_tool("run_command", {"server": "test", "command": "stop"}))
            return payload(await client.call_tool("confirm_command",
                                                  {"ticket": issued["ticket"], "command": command}))

    return run(go)


def test_elicit_accept_runs_the_command(env):
    seen: list = []
    result = elicit_call(env, callback=elicitation_answer("accept", {"approve": True}, seen))
    assert result["status"] == "ok"
    assert env.fake.received == ["stop"]
    (params,) = seen
    assert "stop" in params.message and "'test'" in params.message
    schema = params.requested_schema
    assert list(schema["properties"]) == ["approve"]
    assert schema["properties"]["approve"]["type"] == "boolean"


@pytest.mark.parametrize("action, content", [
    ("accept", {"approve": False}),
    ("accept", {}),                     # invalid content → refused
    ("decline", None),
    ("cancel", None),
])
def test_elicit_anything_but_an_explicit_yes_refuses(env, action, content):
    result = elicit_call(env, callback=elicitation_answer(action, content, []))
    assert result["status"] == "refused"
    assert env.fake.received == []
    assert env.outcomes() == ["ticket_issued", "ticket_rejected"]


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_elicit_without_client_support_refuses(env, mode):
    # legacy: the client did not declare elicitation; auto (in-process modern protocol): no back-channel.
    result = elicit_call(env, mode=mode, callback=None)
    assert result["status"] == "refused" and "elicitation" in result["reason"]
    assert env.fake.received == []


def test_elicit_burns_the_ticket_on_decline(env):
    async def go():
        server = build_server(env.service, elicit=True)
        async with Client(server, mode="legacy",
                          elicitation_callback=elicitation_answer("decline", None, [])) as client:
            ticket = payload(await client.call_tool("run_command", {"server": "test", "command": "stop"}))["ticket"]
            await client.call_tool("confirm_command", {"ticket": ticket, "command": "stop"})
        return ticket

    ticket = run(go)
    assert env.service.confirm_command(ticket, "stop")["status"] == "refused"
    assert env.fake.received == []


def test_elicit_unknown_ticket_does_not_ask(env):
    seen: list = []

    async def go():
        server = build_server(env.service, elicit=True)
        async with Client(server, mode="legacy",
                          elicitation_callback=elicitation_answer("accept", {"approve": True}, seen)) as client:
            return payload(await client.call_tool("confirm_command", {"ticket": "AAAAAAAAAA", "command": "stop"}))

    assert run(go)["status"] == "refused"
    assert seen == []


def test_elicit_wrong_command_is_still_refused_after_yes(env):
    result = elicit_call(env, callback=elicitation_answer("accept", {"approve": True}, []), command="op Bot1")
    assert result["status"] == "refused"
    assert env.fake.received == []


# ============================================================================================ CLI


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"minecraft-rcon-mcp {__version__}"


@pytest.mark.parametrize("content", [None, "not toml [", "[servers.x]\nmode = 'read-write'\n",
                                     "[servers.x]\ndir = '/tmp'\n[policy]\nread = ['op *']\n"])
def test_config_error_exits_2_with_one_line(tmp_path, capsys, content):
    path = tmp_path / "config.toml"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(path)])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith("minecraft-rcon-mcp: ") and err.count("\n") == 1


def test_server_module_is_the_only_mcp_importer():
    package = SRC / "minecraft_rcon_mcp"
    importers = sorted(p.name for p in package.glob("*.py")
                       if "from mcp" in p.read_text(encoding="utf-8")
                       or "import mcp" in p.read_text(encoding="utf-8"))
    assert importers == ["server.py"]


def test_stdio_entry_point_answers_initialize(env, tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        f'[servers.test]\ndir = "{env.test_dir}"\nmode = "read-write"\n'
        f'[audit]\npath = "{tmp_path / "audit.jsonl"}"\n',
        encoding="utf-8",
    )
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}}
    proc = subprocess.Popen(
        [sys.executable, "-m", "minecraft_rcon_mcp", "--config", str(config)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    try:
        assert proc.stdin and proc.stdout
        proc.stdin.write((json.dumps(request) + "\n").encode())
        proc.stdin.flush()
        line = _readline_with_timeout(proc, 10)
    finally:
        proc.kill()
        proc.wait(timeout=5)
    response = json.loads(line)
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "minecraft-rcon-mcp"
    assert response["result"]["instructions"] == INSTRUCTIONS


def _readline_with_timeout(proc: subprocess.Popen, seconds: float) -> bytes:
    import selectors

    with selectors.DefaultSelector() as sel:
        sel.register(proc.stdout, selectors.EVENT_READ)
        if not sel.select(timeout=seconds):
            raise AssertionError("no answer to initialize within the timeout")
    return proc.stdout.readline()
