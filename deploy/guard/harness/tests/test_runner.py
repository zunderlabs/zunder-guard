import sys
from pathlib import Path

import pytest

from guard_harness.runner import RunError, run


def test_success_retains_both_streams(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "import sys\nprint('out')\nprint('err', file=sys.stderr)"],
        log=tmp_path / "step.log",
        timeout=10,
    )
    assert result.output == "out\n"
    assert result.log.read_text() == "out\nerr\n"


def test_failure_retains_redacted_output(tmp_path: Path) -> None:
    log = tmp_path / "failure.log"
    with pytest.raises(RunError, match="exit 7"):
        run(
            [
                sys.executable,
                "-c",
                "import os\nprint(os.environ['TEST_SECRET'])\nraise SystemExit(7)",
            ],
            env={"TEST_SECRET": "synthetic-sensitive-value"},
            secrets=["synthetic-sensitive-value"],
            log=log,
            timeout=10,
        )
    assert log.read_text() == "[REDACTED]\n"


def test_timeout_keeps_partial_output(tmp_path: Path) -> None:
    log = tmp_path / "timeout.log"
    with pytest.raises(RunError, match="exit 124"):
        run(
            [sys.executable, "-c", "import time\nprint('started', flush=True)\ntime.sleep(30)"],
            log=log,
            timeout=0.2,
        )
    assert "started" in log.read_text()
    assert "timed out" in log.read_text()


def test_secret_arguments_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="secret in command"):
        run(
            ["example", "synthetic-key"], log=tmp_path / "log", timeout=1, secrets=["synthetic-key"]
        )
    assert not (tmp_path / "log").exists()


def test_newly_generated_key_never_enters_log(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "print('synthetic-generated-key')"],
        log=tmp_path / "pair.log",
        timeout=10,
        sensitive_output=True,
    )
    assert result.output.strip() == "synthetic-generated-key"
    assert "synthetic-generated-key" not in result.log.read_text()
    assert "synthetic-generated-key" not in repr(result)


def test_stdin_secret_is_redacted_from_both_streams(tmp_path: Path) -> None:
    secret = "fixture-stdin-sensitive-value"
    result = run(
        [
            sys.executable,
            "-c",
            "import sys\nvalue=sys.stdin.read()\nprint(value)\nprint(value,file=sys.stderr)",
        ],
        stdin=secret.encode(),
        secrets=[secret],
        log=tmp_path / "stdin.log",
        timeout=10,
    )
    assert secret not in result.output
    assert secret not in result.log.read_text()
    assert "[REDACTED]" in result.output
