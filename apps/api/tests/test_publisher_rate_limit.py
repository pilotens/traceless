from starlette.responses import Response

from traceless_api.publisher.rate_limit import PublisherRateLimitMiddleware


def test_rate_limiter_bounds_and_expires_buckets(monkeypatch) -> None:
    clock = [100.0]
    monkeypatch.setattr("traceless_api.publisher.rate_limit.monotonic", lambda: clock[0])
    limiter = PublisherRateLimitMiddleware(
        Response(),
        feed_per_minute=10,
        admin_per_minute=10,
        max_buckets=100,
    )
    for index in range(150):
        assert limiter._consume(f"feed:{index}", 10)[0] is True
    assert len(limiter._requests) == 100
    clock[0] += 61
    assert limiter._consume("feed:fresh", 10)[0] is True
    assert list(limiter._requests) == ["feed:fresh"]
