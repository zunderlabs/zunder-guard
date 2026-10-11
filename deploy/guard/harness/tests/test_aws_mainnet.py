import hashlib
import json
from pathlib import Path

import pytest

import guard_harness.aws_paper as module
from guard_harness.mainnet_terminal import TerminalError


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(module, "BASE", tmp_path)
    monkeypatch.setattr(module, "MAINNET_HOME", tmp_path / "home")
    monkeypatch.setattr(module, "MAINNET_CREDENTIAL", tmp_path / "credential")
    monkeypatch.setattr(module, "MAINNET_UNIT", tmp_path / "unit")
    monkeypatch.setattr(module, "MAINNET_BINARY", tmp_path / "binary")
    (tmp_path / "binary").write_bytes(b"signed binary fixture")
    (tmp_path / "expected.json").write_text(json.dumps({"account": "fixture", "rules": "rules"}))
    return tmp_path


def test_aws_activation_uses_actual_candidate_loader_and_separate_mainnet_profile(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def terminal(words: list[str], account: str, *, log: Path) -> tuple[str, int]:
        assert words[:2] == ["/bin/sh", str(workspace / "candidate-i")]
        for flag, expected in {
            "--network": "mainnet",
            "--service-instance": "mainnet",
            "--account": "fixture",
            "--rules": "rules",
            "--equity-cap": "100",
            "--ip-share": "0.1",
            "--listen": "127.0.0.1:18549",
        }.items():
            assert words[words.index(flag) + 1] == expected
        assert "--key-file" not in words and "--key-stdin" not in words
        return "is not an API wallet of [ACCOUNT]", 1

    monkeypatch.setattr("guard_harness.mainnet_terminal.refusal", terminal)
    value = module.mainnet(hashlib.sha256((workspace / "binary").read_bytes()).hexdigest())
    assert value["stage"] == "refused" and value["service_started"] is False


@pytest.mark.parametrize("state", ["unit", "credential"])
def test_aws_existing_mainnet_state_refuses_before_terminal(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    (workspace / state).write_bytes(b"retained customer state")
    monkeypatch.setattr(
        "guard_harness.mainnet_terminal.refusal", lambda *args, **kwargs: pytest.fail()
    )
    with pytest.raises(TerminalError, match="already exists"):
        module.mainnet("a" * 64)


def test_aws_mutated_runtime_image_cannot_earn_refusal_receipt(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "guard_harness.mainnet_terminal.refusal",
        lambda *args, **kwargs: ("is not an API wallet of [ACCOUNT]", 1),
    )
    with pytest.raises(TerminalError, match="different executable"):
        module.mainnet("a" * 64)
