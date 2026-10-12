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


@pytest.mark.parametrize(
    "label,expected",
    [
        ("rules", "rules"),
        ("container-readiness-risk", "container-readiness-risk"),
        ("container-readiness-status-json", "container-readiness-status-json"),
        ("container-readiness-risk-private-body", "unknown"),
        ("private-body-fragment", "unknown"),
        ("0x" + "a" * 40, "unknown"),
    ],
)
def test_sensitive_failure_classifier_logs_only_fixed_categories(
    tmp_path: Path, label: str, expected: str
) -> None:
    log = tmp_path / "diagnostic.log"
    sentinel = "fake-key-private-body-private-path"
    with pytest.raises(RunError) as error:
        run(
            [
                sys.executable,
                "-c",
                "import sys; s=sys.stdin.read(); print(s); print(s,file=sys.stderr); sys.exit(2)",
            ],
            log=log,
            timeout=10,
            stdin=sentinel.encode(),
            sensitive_output=True,
            failure_classifier=lambda output: label,
        )
    assert (
        log.read_text()
        == "[sensitive command output withheld]\nfailure category: " + expected + "\n"
    )
    assert str(error.value) == "command failed with exit 2; failure category: " + expected
    assert sentinel not in log.read_text() + str(error.value)
    assert str(log) not in str(error.value)


def test_classifier_exception_cannot_expose_diagnostic_input(tmp_path: Path) -> None:
    def classifier(output: str) -> str:
        raise ValueError("private-prefix-" + output)

    with pytest.raises(RunError, match="category: unknown") as error:
        run(
            [sys.executable, "-c", "print('private-body'); raise SystemExit(2)"],
            log=tmp_path / "log",
            timeout=10,
            sensitive_output=True,
            failure_classifier=classifier,
        )
    assert "private" not in str(error.value) + (tmp_path / "log").read_text()


def test_classifier_string_subclass_cannot_override_fixed_label_formatting(tmp_path: Path) -> None:
    class PrivateLabel(str):
        def __format__(self, format_spec: str) -> str:
            return "private-body"

    with pytest.raises(RunError, match="category: unknown") as error:
        run(
            [sys.executable, "-c", "raise SystemExit(2)"],
            log=tmp_path / "log",
            timeout=10,
            sensitive_output=True,
            failure_classifier=lambda output: PrivateLabel("rules"),
        )
    assert "private" not in str(error.value) + (tmp_path / "log").read_text()


def test_failure_classifier_requires_withholding_and_is_not_called_on_success(
    tmp_path: Path,
) -> None:
    def classifier(output: str) -> str:
        pytest.fail("successful output must not be classified")

    with pytest.raises(ValueError, match="complete output withholding"):
        run(
            [sys.executable, "-c", "pass"],
            log=tmp_path / "unsafe",
            timeout=10,
            failure_classifier=classifier,
        )
    assert not (tmp_path / "unsafe").exists()
    run(
        [sys.executable, "-c", "print('private-success')"],
        log=tmp_path / "safe",
        timeout=10,
        sensitive_output=True,
        failure_classifier=classifier,
    )
    assert (tmp_path / "safe").read_text() == "[sensitive command output withheld]\n"


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


@pytest.mark.parametrize("timeout", [False, True])
def test_private_stdout_retains_only_redacted_stderr(tmp_path: Path, timeout: bool) -> None:
    code = (
        "import sys,time\nprint('new-pair-key',flush=True)\n"
        "print(sys.stdin.read()+' stderr-failure',file=sys.stderr,flush=True)\n"
        + ("time.sleep(30)" if timeout else "raise SystemExit(9)")
    )
    log = tmp_path / "private.log"
    with pytest.raises(RunError):
        run(
            [sys.executable, "-c", code],
            log=log,
            timeout=0.2 if timeout else 5,
            sensitive_stdout=True,
            stdin=b"synthetic-private",
            secrets=["synthetic-private"],
        )
    retained = log.read_text()
    assert "new-pair-key" not in retained
    assert "synthetic-private" not in retained
    assert "[REDACTED] stderr-failure" in retained


def test_all_private_output_takes_precedence(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "import sys;print('secret',file=sys.stderr)"],
        log=tmp_path / "private.log",
        timeout=5,
        sensitive_stdout=True,
        sensitive_output=True,
    )
    assert result.log.read_text() == "[sensitive command output withheld]\n"
