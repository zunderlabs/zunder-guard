import base64
import json
from pathlib import Path
from typing import Any

import pytest

import guard_harness.homebrew_stage as publisher
from guard_harness.runner import RunResult


class Fake(publisher.Tap):
    def __init__(self, *, existing: bool = False, same: bool = False) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.existing, self.same, self.fail_read, self.race = existing, same, False, False

    def request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        self.calls.append((method, endpoint, body))
        if endpoint.startswith("branches"):
            if self.fail_read:
                raise RuntimeError("read failed")
            return [
                {"name": name, "commit": {"sha": "a" * 40}}
                for name in (["main", "staging"] if self.existing else ["main"])
            ]
        if endpoint.startswith("git/commits/"):
            return {"tree": {"sha": "b" * 40}}
        if endpoint == "git/blobs":
            return {"sha": "c" * 40}
        if endpoint == "git/trees":
            return {"sha": ("b" if self.same else "d") * 40}
        if endpoint == "git/commits":
            return {"sha": "e" * 40}
        if self.race:
            raise RuntimeError("concurrent update refused")
        return {"ref": "refs/heads/staging", "object": {"sha": "e" * 40}}


@pytest.mark.parametrize("existing", [True, False])
def test_stage_changes_only_staging_formula(existing: bool) -> None:
    tap = Fake(existing=existing)
    formula = b"class ZunderGuard < Formula\nend\n"
    assert publisher.stage(tap, formula, tag="v1.0.0-rc.1") == "e" * 40
    writes = [(method, endpoint, body) for method, endpoint, body in tap.calls if method != "GET"]
    assert writes[0][2] == {"encoding": "base64", "content": base64.b64encode(formula).decode()}
    assert writes[1][2] == {
        "base_tree": "b" * 40,
        "tree": [
            {"path": "Formula/zunder-guard.rb", "mode": "100644", "type": "blob", "sha": "c" * 40}
        ],
    }
    assert writes[2][2] == {
        "message": "Stage zunder-guard v1.0.0-rc.1",
        "tree": "d" * 40,
        "parents": ["a" * 40],
    }
    assert writes[3] == (
        ("PATCH", "git/refs/heads/staging", {"sha": "e" * 40, "force": False})
        if existing
        else ("POST", "git/refs", {"ref": "refs/heads/staging", "sha": "e" * 40})
    )


def test_identical_formula_avoids_commit_and_ref_update() -> None:
    tap = Fake(existing=True, same=True)
    assert publisher.stage(tap, b"formula", tag="v1.0.0") == "a" * 40
    assert not any(
        endpoint in {"git/commits", "git/refs/heads/staging"} for _, endpoint, _ in tap.calls
    )


def test_failed_read_never_means_absent_branch() -> None:
    tap = Fake()
    tap.fail_read = True
    with pytest.raises(RuntimeError):
        publisher.stage(tap, b"formula", tag="v1.0.0")
    assert len(tap.calls) == 1 and tap.calls[0][0] == "GET"


def test_competing_ref_update_is_not_forced_or_retried() -> None:
    tap = Fake(existing=True)
    tap.race = True
    with pytest.raises(RuntimeError):
        publisher.stage(tap, b"formula", tag="v1.0.0")
    assert tap.calls[-1] == ("PATCH", "git/refs/heads/staging", {"sha": "e" * 40, "force": False})
    assert sum(method == "PATCH" for method, _, _ in tap.calls) == 1


@pytest.mark.parametrize(
    "tag,formula",
    [
        ("main", b"formula"),
        ("v1.0.0-rc.0", b"formula"),
        ("v1.0.0", b""),
        ("v1.0.0", b"x" * (1024 * 1024 + 1)),
    ],
)
def test_invalid_input_never_reads_or_writes(tag: str, formula: bytes) -> None:
    tap = Fake()
    with pytest.raises(ValueError):
        publisher.stage(tap, formula, tag=tag)
    assert tap.calls == []


def test_scoped_token_is_only_env_and_redaction_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "FIXTURE-TAP-CREDENTIAL"

    def invoke(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv == [
            "gh",
            "api",
            "--method",
            "POST",
            "repos/zunderlabs/homebrew-tap/git/blobs",
            "--input",
            "-",
        ]
        assert token not in " ".join(argv)
        assert kwargs["env"]["GH_TOKEN"] == token and kwargs["secrets"] == [token]
        assert json.loads(kwargs["stdin"]) == {"content": "public-formula"}
        return RunResult(0, '{"sha":"' + "a" * 40 + '"}', kwargs["log"])

    monkeypatch.setattr(publisher, "run", invoke)
    assert (
        publisher.Tap(token=token, logs=tmp_path).request(
            "POST", "git/blobs", {"content": "public-formula"}
        )["sha"]
        == "a" * 40
    )


def test_cli_authentication_failure_never_issues_tap_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    monkeypatch.setattr(
        sys,
        "argv",
        ["stage", "--tag", "v1.0.0-rc.1", "--commit", "a" * 40, "--work", str(tmp_path / "work")],
    )

    def refuse(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv[1].endswith("github/verify-release-assets.sh")
        assert kwargs["stdin"] == b"" and kwargs["timeout"] == 600
        assert kwargs["env"]["GITHUB_REPOSITORY"] == "zunderlabs/zunder-guard"
        assert "HOMEBREW_TAP_TOKEN" not in kwargs["env"]
        raise RuntimeError("authentication refused")

    monkeypatch.setattr(publisher, "run", refuse)
    monkeypatch.setattr(publisher, "Tap", lambda **kw: pytest.fail("no write credential yet"))
    with pytest.raises(RuntimeError, match="authentication refused"):
        publisher.main()
    assert not (tmp_path / "work/receipt.json").exists()
