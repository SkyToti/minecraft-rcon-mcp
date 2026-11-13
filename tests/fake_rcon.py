"""In-process RCON server speaking the real Source RCON wire protocol, for tests. See docs/DESIGN.md §9.

It records every command body it receives (``received``) so tests can assert that a refused command never
reached the server.
"""
from __future__ import annotations

import select
import socket
import struct
import threading
from types import TracebackType
from typing import Callable, Mapping, Union

ResponseValue = Union[str, Callable[[str], str]]
Responses = Union[Mapping[str, ResponseValue], Callable[[str], str]]

_HEADER = struct.Struct("<iii")
TYPE_RESPONSE = 0
TYPE_AUTH_RESPONSE = 2
TYPE_COMMAND = 2
TYPE_AUTH = 3
FRAGMENT_CHARS = 4096


class FakeRconServer:
    """Threaded TCP RCON server on 127.0.0.1 with an ephemeral port.

    ``responses`` maps an exact command body to its reply (a string, or a callable taking the command), or is
    itself a callable ``(command) -> str``. Unknown commands get ``default_response``.
    ``drop_after``: close each connection after it has answered that many commands (tests reconnects).
    """

    def __init__(
        self,
        password: str = "test-password",
        responses: Responses | None = None,
        default_response: str = "",
        drop_after: int | None = None,
    ) -> None:
        self.password = password
        self.responses: Responses = responses if responses is not None else {}
        self.default_response = default_response
        self.drop_after = drop_after
        self.received: list[str] = []
        self.auth_attempts = 0
        self.connections = 0
        self.closed_connections = 0
        self._closed_cv = threading.Condition()
        self.port = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._clients: list[socket.socket] = []
        self._threads: list[threading.Thread] = []

    # -- lifecycle -------------------------------------------------------------------------------------------

    def start(self) -> FakeRconServer:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        self._listener = listener
        self.port = listener.getsockname()[1]
        self._stop.clear()
        self._accept_thread = threading.Thread(target=self._accept_loop, name="fake-rcon-accept", daemon=True)
        self._accept_thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)
            self._accept_thread = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with self._lock:
            clients, self._clients = self._clients, []
            threads, self._threads = self._threads, []
        for conn in clients:
            _shutdown(conn)
        for thread in threads:
            thread.join(timeout=2)

    def __enter__(self) -> FakeRconServer:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    # -- server loop -----------------------------------------------------------------------------------------

    def _accept_loop(self) -> None:
        assert self._listener is not None
        listener = self._listener
        while not self._stop.is_set():
            readable, _, _ = select.select([listener], [], [], 0.02)
            if not readable:
                continue
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            thread = threading.Thread(target=self._serve, args=(conn,), name="fake-rcon-conn", daemon=True)
            with self._lock:
                self.connections += 1
                self._clients.append(conn)
                self._threads.append(thread)
            thread.start()

    def _serve(self, conn: socket.socket) -> None:
        authed = False
        answered = 0
        try:
            while not self._stop.is_set():
                packet = _read_packet(conn)
                if packet is None:
                    return
                request_id, packet_type, body = packet
                if packet_type == TYPE_AUTH:
                    with self._lock:
                        self.auth_attempts += 1
                    authed = body == self.password
                    conn.sendall(_encode(request_id if authed else -1, TYPE_AUTH_RESPONSE, b""))
                    continue
                if packet_type != TYPE_COMMAND or not authed:
                    return  # Minecraft drops the connection on anything else
                with self._lock:
                    self.received.append(body)
                text = self._respond(body)
                for i in range(0, max(len(text), 1), FRAGMENT_CHARS):
                    conn.sendall(_encode(request_id, TYPE_RESPONSE, text[i : i + FRAGMENT_CHARS].encode("utf-8")))
                answered += 1
                if self.drop_after is not None and answered >= self.drop_after:
                    return
        except OSError:
            return
        finally:
            _shutdown(conn)
            with self._closed_cv:
                self.closed_connections += 1
                self._closed_cv.notify_all()

    def wait_closed(self, count: int = 1, timeout: float = 1.0) -> bool:
        """Block until the server side has closed at least `count` connections."""
        with self._closed_cv:
            return self._closed_cv.wait_for(lambda: self.closed_connections >= count, timeout)

    def _respond(self, command: str) -> str:
        responses = self.responses
        if callable(responses):
            return responses(command)
        value = responses.get(command, self.default_response)
        return value(command) if callable(value) else value


def _encode(request_id: int, packet_type: int, body: bytes) -> bytes:
    return _HEADER.pack(len(body) + 10, request_id, packet_type) + body + b"\x00\x00"


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_packet(conn: socket.socket) -> tuple[int, int, str] | None:
    head = _recv_exact(conn, 4)
    if head is None:
        return None
    (length,) = struct.unpack("<i", head)
    if length < 10 or length > 4096 + 10:
        return None
    payload = _recv_exact(conn, length)
    if payload is None:
        return None
    request_id, packet_type = struct.unpack("<ii", payload[:8])
    return request_id, packet_type, payload[8:-2].decode("utf-8", errors="replace")


def _shutdown(conn: socket.socket) -> None:
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass
