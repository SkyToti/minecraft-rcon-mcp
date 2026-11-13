from __future__ import annotations

import re

import pytest

from minecraft_rcon_mcp.tickets import TicketStore


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(clock: FakeClock) -> TicketStore:
    return TicketStore(ttl_seconds=60, clock=clock)


def test_ticket_format(store: TicketStore) -> None:
    tickets = {store.issue("test", "stop") for _ in range(50)}
    assert len(tickets) == 50
    for ticket in tickets:
        assert re.fullmatch(r"[A-Za-z0-9_-]{10}", ticket)


def test_happy_path(store: TicketStore) -> None:
    ticket = store.issue("test", "kill @e[type=zombie]")
    assert store.redeem(ticket, "test", "kill @e[type=zombie]") == (True, "ok")


def test_reuse_refused(store: TicketStore) -> None:
    ticket = store.issue("test", "stop")
    assert store.redeem(ticket, "test", "stop")[0] is True
    ok, reason = store.redeem(ticket, "test", "stop")
    assert not ok and "used" in reason


def test_unknown_ticket(store: TicketStore) -> None:
    ok, reason = store.redeem("AAAAAAAAAA", "test", "stop")
    assert not ok and reason


def test_expiry(store: TicketStore, clock: FakeClock) -> None:
    ticket = store.issue("test", "stop")
    clock.now += 59.9
    still_valid = store.issue("test", "op Bot1")
    assert store.redeem(still_valid, "test", "op Bot1")[0] is True
    clock.now += 0.1  # exactly at expiry
    ok, reason = store.redeem(ticket, "test", "stop")
    assert not ok
    assert "expired" in reason


def test_expired_tickets_are_purged(store: TicketStore, clock: FakeClock) -> None:
    for _ in range(5):
        store.issue("test", "stop")
    assert len(store) == 5
    clock.now += 61
    store.issue("test", "stop")
    assert len(store) == 1


def test_wrong_command_burns_ticket(store: TicketStore) -> None:
    ticket = store.issue("test", "kill @e[type=zombie]")
    ok, reason = store.redeem(ticket, "test", "kill @e")
    assert not ok and "does not match" in reason
    # Burned: the right command no longer works either.
    assert store.redeem(ticket, "test", "kill @e[type=zombie]")[0] is False


def test_wrong_server_burns_ticket(store: TicketStore) -> None:
    ticket = store.issue("test", "stop")
    ok, reason = store.redeem(ticket, "live", "stop")
    assert not ok and "another server" in reason
    assert store.redeem(ticket, "test", "stop")[0] is False


def test_expired_redeem_burns(store: TicketStore, clock: FakeClock) -> None:
    ticket = store.issue("test", "stop")
    clock.now += 120
    assert store.redeem(ticket, "test", "stop")[0] is False
    clock.now -= 120  # even if the clock went back, the ticket is gone
    assert store.redeem(ticket, "test", "stop")[0] is False


def test_tickets_are_independent(store: TicketStore) -> None:
    a = store.issue("test", "stop")
    b = store.issue("test", "stop")
    assert store.redeem(a, "test", "wrong")[0] is False
    assert store.redeem(b, "test", "stop") == (True, "ok")


def test_invalid_ttl() -> None:
    with pytest.raises(ValueError):
        TicketStore(ttl_seconds=0)
