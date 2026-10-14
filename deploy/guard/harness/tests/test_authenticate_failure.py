"""Release authentication: a bounded GitHub retry and a fixed failure label, never raw output."""

import io
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import test_testnet_run as fixture

from guard_harness import testnet_run as command
from guard_harness.runner import RunError

SCRIPT = command.ROOT / "github/verify-release-assets.sh"


@pytest.mark.parametrize(
    ("log", "label"),
    [
        # rc.16 verify 38569322248, T2 attempt 1: its assets.log, verbatim.
        (
            "Verified OK\nHTTP 500 (https://api.github.com/repos/zunderlabs/zunder-guard/"
            "releases/assets/640414673)\n",
            "github-http-5xx",
        ),
        ("gh: API rate limit exceeded (HTTP 429)\n", "github-http-429"),
        ("HTTP 404: Not Found (https://api.github.com/repos/x/y/commits/v1)\n", "github-http-4xx"),
        ("cannot resolve release commit\n", "commit-unresolved"),
        (
            "ci has no successful completed push run for main at "
            + "a" * 40
            + "; publication stopped\n",
            "ci-run-missing",
        ),
        ("release has no successful completed push run for v1.0.0\n", "release-run-missing"),
        ("zunder-guard-v1.0.0-linux-amd64.tar.gz: FAILED\n", "checksum-mismatch"),
        ("sha256sum: WARNING: 1 computed checksum did NOT match\n", "checksum-mismatch"),
        ("FAILED: SLSA verification failed: private detail\n", "slsa"),
        ("Error: none of the expected identities matched PRIVATE\n", "sigstore-or-tool-error"),
        ("zunder-guard.rb is missing or repeated in the signed checksums\n", "checksum-inventory"),
        ("invalid signed image reference\n", "image-reference"),
        ("partial output\ncommand timed out\n", "timeout"),
        # A 5xx a retry overcame never hides the later, real failure.
        ("HTTP 502 (https://api.github.com/x)\nSLSA provenance is missing\n", "provenance-missing"),
        (
            "Verified draft assets v1 at x and y; native readiness not yet checked\n",
            "release-archive",
        ),
        ("PRIVATE-TOKEN something nobody wrote down\n", "unknown"),
        ("", "unknown"),
    ],
)
def test_fixed_label_names_the_last_known_failure_and_copies_nothing(
    tmp_path: Path, log: str, label: str
) -> None:
    path = tmp_path / "assets.log"
    path.write_text(log)
    assert command.authenticate_failure(path) == label
    assert label in command.AUTHENTICATE_LABELS


def test_missing_link_or_huge_log_is_unreadable(tmp_path: Path) -> None:
    assert command.authenticate_failure(tmp_path / "absent.log") == "unreadable-log"
    target = tmp_path / "real.log"
    target.write_text("cannot resolve release commit\n")
    (tmp_path / "link.log").symlink_to(target)
    assert command.authenticate_failure(tmp_path / "link.log") == "unreadable-log"


def test_receipt_records_only_the_label_when_authentication_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def verify(argv: list[str], **kwargs: Any) -> None:
        kwargs["log"].write_text(
            "Verified OK\nHTTP 500 (https://api.github.com/repos/PRIVATE/releases/assets/1)\n"
        )
        raise RunError("command failed with exit 1; diagnostics: PRIVATE")

    monkeypatch.setattr(command, "run", verify)
    key = io.BytesIO(b"FIXTURE-PRIVATE-INPUT")
    assert command.execute_release(**fixture.args(tmp_path, key)) == 1
    text = (tmp_path / "run/receipt.json").read_text()
    receipt = json.loads(text)
    assert receipt["stage"] == "authenticate"
    assert receipt["authenticate_failure"] == "github-http-5xx"
    assert receipt["failure"] == "journey_incomplete_keep_protection"
    assert "PRIVATE" not in text and key.tell() == 0


def _gh_retry(tmp_path: Path, answers: list[tuple[int, str, str]]) -> tuple[int, str, str, int]:
    """Run only the script's own gh_retry with a fake gh replaying fixed answers."""
    source = SCRIPT.read_text()
    function = re.search(r"# BEGIN gh_retry\n(.*?)# END gh_retry\n", source, re.S)
    assert function is not None
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    state = tmp_path / "calls"
    state.write_text("0")
    lines = ["#!/bin/sh", f'n=$(cat "{state}")', f'echo $((n + 1)) > "{state}"', 'case "$n" in']
    for index, (status, out, err) in enumerate(answers):
        lines.append(
            f"  {index}) printf '%s' '{out}'; printf '%s\\n' '{err}' >&2; exit {status} ;;"
        )
    lines += ["esac", "exit 99"]
    gh = bin_dir / "gh"
    gh.write_text("\n".join(lines) + "\n")
    gh.chmod(0o700)
    result = subprocess.run(
        ["bash", "-c", function[1] + 'gh_retry api "repos/x/y/commits/v1" --jq .sha'],
        env={"PATH": f"{bin_dir}:{os.defpath}", "GH_RETRY_PAUSE": "0"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr, int(state.read_text())


def test_gh_retry_rides_out_github_5xx_and_429_and_passes_only_the_good_answer(
    tmp_path: Path,
) -> None:
    status, out, err, calls = _gh_retry(
        tmp_path,
        [
            (1, '{"message":"Server Error"}', "HTTP 500 (https://api.github.com/x)"),
            (1, "", "gh: rate limited (HTTP 429)"),
            (0, "a" * 40, ""),
        ],
    )
    assert (status, out, calls) == (0, "a" * 40, 3)
    assert "Server Error" not in out and "HTTP 500" in err


def test_gh_retry_stops_at_three_tries_and_never_retries_other_failures(tmp_path: Path) -> None:
    status, _, _, calls = _gh_retry(tmp_path, [(1, "", "HTTP 503 (x)")] * 4)
    assert status == 1 and calls == 3
    for answer in ("HTTP 404: Not Found (x)", "HTTP 401: Bad credentials (x)", "x509: bad"):
        (tmp_path / "bin").rename(tmp_path / f"old-{calls}-{len(answer)}")
        status, _, _, calls = _gh_retry(tmp_path, [(1, "", answer), (0, "ok", "")])
        assert status == 1 and calls == 1


def test_only_gh_calls_are_retried_and_downloads_overwrite_partial_files() -> None:
    source = SCRIPT.read_text()
    body = source.split("# END gh_retry\n", 1)[1]
    assert "gh_retry api" in body and "gh_retry release download" in body
    assert re.search(r"(?m)^\s*(COMMIT=\$\(|runs=\$\(|)gh (api|release)", body) is None
    assert body.count("--clobber") == 2
    for verifier in ("cosign verify", "slsa-verifier", "sha256sum -c"):
        assert all("gh_retry" not in line for line in body.splitlines() if verifier in line)
