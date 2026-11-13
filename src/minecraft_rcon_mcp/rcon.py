"""Minimal Source RCON client for Minecraft Java servers. See docs/DESIGN.md §8.

Wire format (little-endian): ``int32 length, int32 request id, int32 type`` followed by the body and two NUL
bytes. ``length`` counts everything after itself. Auth is type 3, a command is type 2, a command response is
type 0. A failed auth is answered with request id -1.

Security rule: the password is only ever written to the socket. It never appears in an exception message,
in ``repr()`` or in any log line.
"""
from __future__ import annotations

import select
import socket
import struct
from types import TracebackType

__all__ = ["RconError", "RconAuthError", "RconClient", "MAX_BODY_BYTES"]

TYPE_RESPONSE = 0
TYPE_COMMAND = 2
TYPE_AUTH_RESPONSE = 2
TYPE_AUTH = 3

MAX_BODY_BYTES = 1400              # Minecraft silently drops larger request packets
FRAGMENT_CHARS = 4096              # Minecraft splits responses into chunks of this many characters
MAX_RESPONSE_BYTES = 4096 * 4      # stop collecting fragments after this many body bytes
MULTIPACKET_TIMEOUT = 0.2          # wait for further fragments after the first one
_MAX_PACKET_LENGTH = 4 + 4 + 4096 * 4 + 2  # sanity bound on the length field of an incoming packet
_HEADER = struct.Struct("<iii")


class RconError(Exception):
    """Any RCON failure. Messages are safe to show: they never contain the password."""


class RconAuthError(RconError):
    """The server rejected the RCON password."""


class _ConnectionClosed(RconError):
    """The peer closed the connection (internal; surfaced as RconError)."""


def _encode_packet(request_id: int, packet_type: int, body: bytes) -> bytes:
    return _HEADER.pack(len(body) + 10, request_id, packet_type) + body + b"\x00\x00"


class RconClient:
    """One RCON connection, authenticated on connect.

    Use as a context manager, or call :meth:`command` directly (it connects lazily) and :meth:`close` at the end.
    A connection the server already closed is detected before sending and reopened once.
    """

    def __init__(
        self,
        host: str,
        port: int,
        password: str,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.__password = password
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.multipacket_timeout = MULTIPACKET_TIMEOUT
        self._sock: socket.socket | None = None
        self._next_id = 0

    def __repr__(self) -> str:
        return f"RconClient(host={self.host!r}, port={self.port!r}, connected={self._sock is not None})"

    # -- context manager -------------------------------------------------------------------------------------

    def __enter__(self) -> RconClient:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- public API ------------------------------------------------------------------------------------------

    def connect(self) -> None:
        """Open the TCP connection and authenticate. Raises RconError / RconAuthError."""
        self.close()
        where = f"{self.host}:{self.port}"
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        except socket.timeout:
            raise RconError(f"timed out connecting to RCON at {where}") from None
        except OSError as exc:
            raise RconError(f"cannot connect to RCON at {where}: {exc.strerror or type(exc).__name__}") from None
        sock.settimeout(self.read_timeout)
        self._sock = sock
        try:
            self._authenticate()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def command(self, body: str) -> str:
        """Send one command and return the full response text. Raises RconError."""
        data = body.encode("utf-8")
        if len(data) > MAX_BODY_BYTES:
            raise RconError(f"command is {len(data)} bytes; the RCON limit is {MAX_BODY_BYTES}")
        if self._sock is None or self._peer_closed():
            self.connect()
        request_id = self._new_id()
        try:
            self._send(request_id, TYPE_COMMAND, data)
        except _ConnectionClosed:
            # Broken pipe while sending: the command was not delivered, so one retry is safe.
            self.connect()
            request_id = self._new_id()
            self._send(request_id, TYPE_COMMAND, data)
        try:
            return self._read_response(request_id)
        except RconError:
            # The command may or may not have run; never retry it, and do not reuse this connection.
            self.close()
            raise

    # -- internals -------------------------------------------------------------------------------------------

    def _new_id(self) -> int:
        self._next_id = self._next_id % 0x7FFFFFFF + 1
        return self._next_id

    def _authenticate(self) -> None:
        request_id = self._new_id()
        self._send(request_id, TYPE_AUTH, self.__password.encode("utf-8"))
        for _ in range(4):
            resp_id, resp_type, _ = self._read_packet()
            if resp_type == TYPE_AUTH_RESPONSE:
                break
            # Some Source servers send an empty RESPONSE_VALUE before the auth response; skip it.
        else:
            raise RconError("no RCON auth response")
        if resp_id == -1:
            raise RconAuthError(f"RCON authentication failed at {self.host}:{self.port} (wrong rcon.password)")
        if resp_id != request_id:
            raise RconError("unexpected RCON auth response id")

    def _peer_closed(self) -> bool:
        """True if the server already closed this idle connection (EOF or unsolicited data pending)."""
        assert self._sock is not None
        try:
            readable, _, _ = select.select([self._sock], [], [], 0)
        except (OSError, ValueError):
            return True
        return bool(readable)

    def _send(self, request_id: int, packet_type: int, body: bytes) -> None:
        assert self._sock is not None
        try:
            self._sock.sendall(_encode_packet(request_id, packet_type, body))
        except socket.timeout:
            self.close()
            raise RconError("timed out sending to RCON") from None
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close()
            raise _ConnectionClosed("RCON connection closed by the server") from None
        except OSError as exc:
            self.close()
            raise RconError(f"RCON send failed: {exc.strerror or type(exc).__name__}") from None

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        chunks: list[bytes] = []
        remaining = n
        while remaining:
            try:
                chunk = self._sock.recv(remaining)
            except socket.timeout:
                raise RconError("timed out waiting for the RCON response") from None
            except (ConnectionResetError, ConnectionAbortedError):
                raise RconError("RCON connection closed by the server") from None
            except OSError as exc:
                raise RconError(f"RCON receive failed: {exc.strerror or type(exc).__name__}") from None
            if not chunk:
                raise RconError("RCON connection closed by the server")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_packet(self) -> tuple[int, int, bytes]:
        (length,) = struct.unpack("<i", self._recv_exact(4))
        if length < 10 or length > _MAX_PACKET_LENGTH:
            raise RconError(f"malformed RCON packet (length {length})")
        payload = self._recv_exact(length)
        request_id, packet_type = struct.unpack("<ii", payload[:8])
        return request_id, packet_type, payload[8:-2]

    def _read_response(self, request_id: int) -> str:
        assert self._sock is not None
        resp_id, _, body = self._read_packet()
        if resp_id != request_id:
            raise RconError("unexpected RCON response id")
        parts = [body]
        total = len(body)
        # Minecraft splits long responses into 4096-character fragments; a shorter fragment is the last one.
        # After a full fragment, wait briefly for the next one, up to MAX_RESPONSE_BYTES in total.
        while _is_full_fragment(body):
            if total >= MAX_RESPONSE_BYTES:
                # Unread fragments may still be in flight: this connection can no longer be reused.
                self.close()
                break
            self._sock.settimeout(self.multipacket_timeout)
            try:
                resp_id, _, body = self._read_packet()
            except RconError:
                # No further fragment in time (or a broken one): keep what we have and drop the connection,
                # because the stream position is no longer trustworthy.
                self.close()
                break
            self._sock.settimeout(self.read_timeout)
            if resp_id != request_id:
                self.close()
                break
            parts.append(body)
            total += len(body)
        return b"".join(parts).decode("utf-8", errors="replace")


def _is_full_fragment(body: bytes) -> bool:
    return len(body) >= FRAGMENT_CHARS and len(body.decode("utf-8", errors="replace")) >= FRAGMENT_CHARS
