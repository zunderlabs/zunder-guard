from pathlib import Path

import pytest

from guard_harness.mainnet_terminal import TerminalError, refusal


def test_local_terminal_activation_refuses_before_generating_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("RUNNER_ENVIRONMENT", raising=False)
    monkeypatch.setattr(
        "guard_harness.mainnet_terminal.secrets.token_hex",
        lambda count: pytest.fail("local key generation is forbidden"),
    )
    with pytest.raises(TerminalError, match="hosted disposable only"):
        refusal(["/never/execute"], "fixture-account", log=tmp_path / "refusal.log")
    assert not (tmp_path / "refusal.log").exists()


@pytest.mark.parametrize("environment", ["self-hosted", "", "github-hosted-other"])
def test_self_hosted_refuses_even_when_actions_is_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", environment)
    with pytest.raises(TerminalError, match="hosted disposable only"):
        refusal(["/never/execute"], "fixture-account", log=tmp_path / "refusal.log")
