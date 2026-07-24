"""Command-line entry point for the central intelligence publisher."""

from __future__ import annotations

import argparse
import os

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Traceless intelligence publisher")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument(
        "--surface",
        choices=("combined", "admin", "ingest", "review", "feed"),
        default=None,
        help="Expose one publisher trust surface or all routes for development.",
    )
    args = parser.parse_args()
    if args.surface is not None:
        os.environ["TRACELESS_PUBLISHER_SURFACE"] = args.surface
    uvicorn.run(
        "traceless_api.publisher.app:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        proxy_headers=True,
        forwarded_allow_ips=os.getenv(
            "TRACELESS_PUBLISHER_FORWARDED_ALLOW_IPS",
            "127.0.0.1",
        ),
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
