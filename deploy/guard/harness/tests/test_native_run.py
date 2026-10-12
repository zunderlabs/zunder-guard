import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import native_run
from guard_harness.native_release import Release
from guard_harness.testnet_process import ProcessError


def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, Any]]:
    subjects = tmp_path / "subjects"
    subjects.mkdir()
    identity = dict(
        tag="v1.0.0",
        commit="b" * 40,
        previous_tag="v0.9.0",
        previous_commit="c" * 40,
        harness_commit="b" * 40,
        diagnostic=False,
        loader_channel="staging",
    )
    (subjects / "input.json").write_text(json.dumps(identity))
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    monkeypatch.setenv("WALLET_FRAME", "e" * 64)
    monkeypatch.setenv("UNRELATED_TOKEN", "inert-token-fixture")
    monkeypatch.setattr(Release, "asset", lambda self, name: b"public-manifest-fixture")
    monkeypatch.setattr(native_run, "flat_scan", lambda *args: None)
    monkeypatch.setattr(
        native_run,
        "channel_execute",
        lambda *args, **kwargs: {"channel": "D2", "cleanup_complete": True},
    )
    return subjects, identity


@pytest.mark.parametrize("prefix", ["", "0x"])
@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_modes_receive_private_stdin_only_and_preserve_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str, prefix: str
) -> None:
    subjects, _ = setup(tmp_path, monkeypatch)
    monkeypatch.setenv("WALLET_FRAME", prefix + "e" * 64)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    scans: list[object] = []
    monkeypatch.setattr(native_run, "flat_scan", lambda *args: scans.append(args))

    def child(argv: list[str], **kwargs: Any) -> None:
        calls.append((argv, kwargs))

    monkeypatch.setattr("guard_harness.native_run.subprocess.run", child)
    output = tmp_path / "output"
    native_run.execute(
        subjects=subjects,
        output=output,
        scenario=scenario,
        account="inert-private-account",
        shell="pwsh.exe",
    )
    assert len(calls) == 2 and len(scans) == 2
    assert calls[0][1]["input"] == b"" and calls[1][1]["input"] == b"e" * 64 + b"\n"
    for argv, options in calls:
        assert argv[argv.index("--scenario") + 1] == scenario
        assert "e" * 64 not in " ".join(argv)
        assert "WALLET_FRAME" not in options["env"] and "UNRELATED_TOKEN" not in options["env"]
        assert options["check"] is True
    receipt = json.loads((output / "identities.json").read_bytes())
    assert receipt["scenario"] == scenario
    assert ("previous_tag" in receipt) is (scenario == "upgrade")
    assert ("previous_commit" in receipt) is (scenario == "upgrade")
    assert (output / "channels/D2.json").exists() is (scenario == "fresh")


def test_child_failure_never_discloses_argv_and_still_scans_finally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subjects, _ = setup(tmp_path, monkeypatch)
    scans: list[object] = []
    monkeypatch.setattr(native_run, "flat_scan", lambda *args: scans.append(args))

    def child(argv: list[str], **kwargs: Any) -> None:
        raise subprocess.CalledProcessError(2, argv)

    monkeypatch.setattr("guard_harness.native_run.subprocess.run", child)
    with pytest.raises(ProcessError) as error:
        native_run.execute(
            subjects=subjects,
            output=tmp_path / "output",
            scenario="upgrade",
            account="inert-private-account",
            shell="pwsh.exe",
        )
    assert "inert-private-account" not in str(error.value) and len(scans) == 2
    assert not (tmp_path / "output/identities.json").exists()


@pytest.mark.parametrize(
    "mutation", ["diagnostic", "source", "profile", "channel", "serialization"]
)
def test_unadmitted_native_input_refuses_before_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    subjects, identity = setup(tmp_path, monkeypatch)
    if mutation in {"diagnostic", "source", "channel"}:
        changes: dict[str, dict[str, Any]] = {
            "diagnostic": {"diagnostic": True},
            "source": {"commit": "a" * 40},
            "channel": {"loader_channel": "canonical"},
        }
        identity.update(changes[mutation])
        (subjects / "input.json").write_text(json.dumps(identity))
    elif mutation == "profile":
        monkeypatch.setenv("INSTALL_MATRIX_PROFILE", "unknown")
    else:
        monkeypatch.delenv("GUARD_C6_SERIALIZED")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("unadmitted input started a child or scanner")

    monkeypatch.setattr("guard_harness.native_run.subprocess.run", forbidden)
    monkeypatch.setattr(native_run, "flat_scan", forbidden)
    with pytest.raises(ProcessError):
        native_run.execute(
            subjects=subjects,
            output=tmp_path / "output",
            scenario="fresh",
            account="inert-private-account",
            shell="pwsh.exe",
        )
