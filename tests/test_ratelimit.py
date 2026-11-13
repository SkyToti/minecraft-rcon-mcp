from __future__ import annotations

import pytest

from minecraft_rcon_mcp.ratelimit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 50.0

    def __call__(self) -> float:
        return self.now


def test_burst_then_limited() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=3, clock=clock)
    assert [limiter.allow("test")[0] for _ in range(3)] == [True, True, True]
    allowed, retry_after = limiter.allow("test")
    assert not allowed
    assert retry_after == pytest.approx(20.0)  # one token every 20 s


def test_refill_over_time() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=6, clock=clock)  # one token every 10 s
    for _ in range(6):
        assert limiter.allow("s") == (True, 0.0)
    assert limiter.allow("s")[0] is False
    clock.now += 4
    allowed, retry_after = limiter.allow("s")
    assert not allowed and retry_after == pytest.approx(6.0)
    clock.now += 6
    assert limiter.allow("s")[0] is True
    assert limiter.allow("s")[0] is False


def test_refill_caps_at_capacity() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=2, clock=clock)
    clock.now += 3600
    assert [limiter.allow("s")[0] for _ in range(3)] == [True, True, False]


def test_keys_are_independent() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=1, clock=clock)
    assert limiter.allow("test")[0] is True
    assert limiter.allow("test")[0] is False
    assert limiter.allow("live")[0] is True


def test_clock_going_backwards_does_not_add_tokens() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=1, clock=clock)
    assert limiter.allow("s")[0] is True
    clock.now -= 100
    assert limiter.allow("s")[0] is False


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_invalid_rate(bad) -> None:
    with pytest.raises(ValueError):
        RateLimiter(per_minute=bad)
