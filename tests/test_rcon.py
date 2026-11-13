from __future__ import annotations

import socket
import threading

import pytest

from fake_rcon import FakeRconServer
from minecraft_rcon_mcp.rcon import MAX_BODY_BYTES, RconAuthError, RconClient, RconError

PASSWORD = "test-password"
SECRET = "s3cr3t-Hunter2-pw"


def client_for(server: FakeRconServer, password: str = PASSWORD, **kw) -> RconClient:
    kw.setdefault("connect_timeout", 0.5)
    kw.setdefault("read_timeout", 0.5)
    client = RconClient("127.0.0.1", server.port, password, **kw)
    client.multipacket_timeout = 0.05
    return client


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def assert_no_secret(exc: BaseException, secret: str) -> None:
    for text in (str(exc), repr(exc), *map(str, exc.args)):
        assert secret not in text
    assert exc.__cause__ is None or secret not in repr(exc.__cause__)


def test_auth_ok_and_command(fake_rcon: FakeRconServer) -> None:
    fake_rcon.responses = {"list": "There are 0 of a max of 20 players online: "}
    with client_for(fake_rcon) as client:
        assert client.command("list") == "There are 0 of a max of 20 players online: "
        assert client.command("seed") == ""
    assert fake_rcon.received == ["list", "seed"]


def test_command_connects_lazily(fake_rcon: FakeRconServer) -> None:
    client = client_for(fake_rcon)
    try:
        assert client.command("time query daytime") == ""
    finally:
        client.close()
    assert fake_rcon.received == ["time query daytime"]


def test_callable_responses_and_default() -> None:
    with FakeRconServer(responses=lambda cmd: cmd.upper()) as server:
        with client_for(server) as client:
            assert client.command("say hi") == "SAY HI"
    with FakeRconServer(responses={"a": lambda cmd: cmd * 2}, default_response="?") as server:
        with client_for(server) as client:
            assert client.command("a") == "aa"
            assert client.command("b") == "?"


def test_unicode_round_trip(fake_rcon: FakeRconServer) -> None:
    fake_rcon.responses = {"say ñandú ✓": "§aok ✓"}
    with client_for(fake_rcon) as client:
        assert client.command("say ñandú ✓") == "§aok ✓"


def test_multi_packet_response() -> None:
    long_text = "x" * 4096 + "y" * 4096 + "tail"
    with FakeRconServer(responses={"help": long_text}) as server:
        with client_for(server) as client:
            assert client.command("help") == long_text


def test_multi_packet_response_capped() -> None:
    huge = "z" * (4096 * 6)
    with FakeRconServer(responses={"help": huge}) as server:
        with client_for(server) as client:
            out = client.command("help")
    assert 4096 * 4 <= len(out) < len(huge)


def test_wrong_password() -> None:
    with FakeRconServer(password="right-one") as server:
        client = client_for(server, password=SECRET)
        with pytest.raises(RconAuthError) as info:
            client.connect()
        assert_no_secret(info.value, SECRET)
        assert isinstance(info.value, RconError)
        assert server.received == []


def test_server_down() -> None:
    client = RconClient("127.0.0.1", free_port(), SECRET, connect_timeout=0.5, read_timeout=0.5)
    with pytest.raises(RconError) as info:
        client.command("list")
    assert_no_secret(info.value, SECRET)
    assert "cannot connect" in str(info.value)


def test_read_timeout_message_has_no_password() -> None:
    # A listener that completes the TCP handshake but never answers the auth packet.
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        port = silent.getsockname()[1]
        client = RconClient("127.0.0.1", port, SECRET, connect_timeout=0.5, read_timeout=0.1)
        with pytest.raises(RconError) as info:
            client.connect()
    assert "timed out" in str(info.value)
    assert_no_secret(info.value, SECRET)


def test_repr_has_no_password() -> None:
    client = RconClient("127.0.0.1", 25575, SECRET)
    assert SECRET not in repr(client)
    assert SECRET not in str(client)


def test_oversize_body_rejected_before_sending(fake_rcon: FakeRconServer) -> None:
    with client_for(fake_rcon) as client:
        with pytest.raises(RconError, match="1400"):
            client.command("say " + "a" * MAX_BODY_BYTES)
        # Multi-byte characters count in bytes, not characters.
        with pytest.raises(RconError):
            client.command("say " + "ñ" * 700)
        assert client.command("say " + "a" * (MAX_BODY_BYTES - 4)) == ""
    assert fake_rcon.received == ["say " + "a" * (MAX_BODY_BYTES - 4)]


def test_reconnect_after_server_dropped_connection() -> None:
    with FakeRconServer(drop_after=1, default_response="ok") as server:
        with client_for(server) as client:
            assert client.command("list") == "ok"
            assert server.wait_closed(1)
            assert client.command("seed") == "ok"
        assert server.received == ["list", "seed"]
        assert server.connections == 2


def test_reconnect_once_on_broken_pipe(fake_rcon: FakeRconServer) -> None:
    class BrokenSocket:
        def sendall(self, data: bytes) -> None:
            raise BrokenPipeError(32, "Broken pipe")

        def close(self) -> None:
            pass

    client = client_for(fake_rcon)
    client._sock = BrokenSocket()  # type: ignore[assignment]
    client._peer_closed = lambda: False  # type: ignore[method-assign]
    try:
        assert client.command("list") == ""
    finally:
        client.close()
    assert fake_rcon.received == ["list"]


def test_no_retry_once_command_was_sent() -> None:
    # The server dies after receiving the command: it may have run, so the client must not resend it.
    calls = threading.Event()

    def respond(cmd: str) -> str:
        calls.set()
        raise OSError("simulated crash")

    with FakeRconServer(responses=respond) as server:
        with client_for(server) as client:
            with pytest.raises(RconError, match="closed"):
                client.command("stop")
        assert server.received == ["stop"]
        assert calls.is_set()


def test_unauthenticated_command_drops_connection(fake_rcon: FakeRconServer) -> None:
    # Sanity check of the fake: commands before auth are never recorded.
    import struct

    with socket.create_connection(("127.0.0.1", fake_rcon.port), timeout=0.5) as raw:
        body = b"stop"
        raw.sendall(struct.pack("<iii", len(body) + 10, 1, 2) + body + b"\x00\x00")
        assert raw.recv(16) == b""
    assert fake_rcon.received == []
