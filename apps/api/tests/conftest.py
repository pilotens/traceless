from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from traceless_api.core.config import Settings
from traceless_api.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(
        Settings(
            environment="test",
            enable_docs=True,
            cors_origins=["http://localhost:3000"],
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            auto_create_schema=True,
        )
    )
    with TestClient(app) as test_client:
        yield test_client
