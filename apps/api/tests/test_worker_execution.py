import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from traceless_api.worker import _configured_binary, _run_process, process_next_scan


def test_bounded_process_runner_captures_separate_output_streams() -> None:
    completed = _run_process(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stdout.buffer.write(b'xml-output'); "
                "sys.stderr.buffer.write(b'diagnostic')"
            ),
        ],
        timeout_seconds=5,
        max_stdout_bytes=1_024,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"xml-output"
    assert completed.stderr == b"diagnostic"


def test_bounded_process_runner_terminates_excess_output() -> None:
    with pytest.raises(RuntimeError, match="stdout exceeds"):
        _run_process(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"],
            timeout_seconds=5,
            max_stdout_bytes=128,
        )


def test_bounded_process_runner_enforces_timeout() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        _run_process(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout_seconds=0,
            max_stdout_bytes=128,
        )


@pytest.mark.parametrize("value", ["", "relative/path", "bad\x00binary"])
def test_scanner_binary_rejects_ambiguous_or_invalid_paths(value: str) -> None:
    with pytest.raises(ValueError):
        _configured_binary(value)


def test_scanner_binary_accepts_plain_name_and_absolute_path() -> None:
    assert _configured_binary("nmap") == "nmap"
    assert _configured_binary("/usr/bin/nmap") == "/usr/bin/nmap"


def test_worker_requires_explicit_enablement_and_reports_an_empty_queue(
    client: TestClient,
) -> None:
    with pytest.raises(RuntimeError, match="disabled"):
        process_next_scan(
            settings=client.app.state.settings,
            session_factory=client.app.state.session_factory,
        )

    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert (
        process_next_scan(
            settings=enabled,
            session_factory=client.app.state.session_factory,
        )
        is False
    )
