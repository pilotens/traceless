#!/usr/bin/env python3
"""Bounded publisher feed load test with explicit acceptance thresholds."""

from __future__ import annotations

import argparse
import concurrent.futures
import statistics
import time
import urllib.parse
import urllib.request


def _percentile(values: list[float], percentile: float) -> float:
    index = max(0, min(len(values) - 1, int(len(values) * percentile) - 1))
    return values[index]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--max-error-rate", type=float, default=0.0)
    parser.add_argument("--max-p95-ms", type=float, default=1_000.0)
    parser.add_argument("--max-p99-ms", type=float, default=2_000.0)
    parser.add_argument("--min-rps", type=float, default=1.0)
    args = parser.parse_args()
    if not 1 <= args.requests <= 10_000 or not 1 <= args.concurrency <= 200:
        raise SystemExit("requests/concurrency are outside the bounded test range")
    if not 0 <= args.max_error_rate <= 1:
        raise SystemExit("max-error-rate must be between 0 and 1")

    url = args.url + ("&" if "?" in args.url else "?") + urllib.parse.urlencode({"limit": 1})

    def one() -> tuple[int, float]:
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {args.token}",
                "Accept": "application/json",
            },
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response.read()
                return response.status, (time.perf_counter() - started) * 1_000
        except Exception:
            return 0, (time.perf_counter() - started) * 1_000

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(lambda _: one(), range(args.requests)))
    elapsed = max(time.perf_counter() - started, 0.000_001)
    latencies = sorted(value for _, value in results)
    failures = sum(status != 200 for status, _ in results)
    error_rate = failures / len(results)
    p95 = _percentile(latencies, 0.95)
    p99 = _percentile(latencies, 0.99)
    rps = len(results) / elapsed
    metrics = {
        "requests": len(results),
        "failures": failures,
        "error_rate": round(error_rate, 4),
        "rps": round(rps, 2),
        "mean_ms": round(statistics.fmean(latencies), 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "max_ms": round(max(latencies), 2),
    }
    print(metrics)
    violations = []
    if error_rate > args.max_error_rate:
        violations.append(f"error_rate {error_rate:.4f} > {args.max_error_rate:.4f}")
    if p95 > args.max_p95_ms:
        violations.append(f"p95 {p95:.2f}ms > {args.max_p95_ms:.2f}ms")
    if p99 > args.max_p99_ms:
        violations.append(f"p99 {p99:.2f}ms > {args.max_p99_ms:.2f}ms")
    if rps < args.min_rps:
        violations.append(f"throughput {rps:.2f}rps < {args.min_rps:.2f}rps")
    if violations:
        raise SystemExit("; ".join(violations))


if __name__ == "__main__":
    main()
