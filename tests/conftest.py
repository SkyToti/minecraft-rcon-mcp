from __future__ import annotations

from collections.abc import Iterator

import pytest

from fake_rcon import FakeRconServer


@pytest.fixture
def fake_rcon() -> Iterator[FakeRconServer]:
    """A started FakeRconServer (password "test-password"); tests may edit `.responses` before connecting."""
    server = FakeRconServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()
