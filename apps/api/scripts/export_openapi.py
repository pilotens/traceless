"""Export a deterministic OpenAPI document for frontend contract generation."""

import argparse
import json
from pathlib import Path

from traceless_api.core.config import Settings
from traceless_api.main import create_app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    app = create_app(
        Settings(
            environment="test",
            database_url="sqlite+pysqlite:///:memory:",
            allowed_hosts=["testserver"],
        )
    )
    payload = json.dumps(
        app.openapi(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"{payload}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
