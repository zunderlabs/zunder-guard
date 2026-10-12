import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from guard_harness import install_run
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT

COMMIT = "a" * 40
KEY = "b" * 64


def prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: str
) -> tuple[Path, list[tuple[list[str], dict[str, Any]]]]:
    subjects = tmp_path / "subjects"
    subjects.mkdir()
    for directory in ("candidate/assets", "previous/assets"):
        (subjects / directory).mkdir(parents=True)
    (subjects / "i-staging").write_bytes(b"signed candidate loader")
    (subjects / "previous/assets/install.sh").write_bytes(b"signed previous installer")
    (subjects / "input.json").write_text(
        json.dumps(
            dict(
                diagnostic=False,
                harness_commit=COMMIT,
                commit=COMMIT,
                tag="v1.0.0",
                previous_commit="c" * 40,
                previous_tag="v0.9.0",
                loader_channel="staging",
            )
        )
    )
    monkeypatch.setenv("GITHUB_SHA", COMMIT)
    monkeypatch.setenv("INSTALL_MATRIX_PROFILE", "all")
    monkeypatch.setenv("GUARD_C6_SERIALIZED", "1")
    monkeypatch.setenv("WALLET_FRAME", KEY)
    monkeypatch.setenv("GH_TOKEN", "caller-token-fixture")
    monkeypatch.setenv("E2E_TESTNET_OWNER_KEY", "caller-owner-fixture")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "install_run",
            "--row",
            row,
            "--scenario",
            "upgrade",
            "--subjects",
            str(subjects),
            "--output",
            str(tmp_path / "evidence"),
            "--account",
            "approved-runtime-account",
            "--paper-account",
            "public-paper-account",
        ],
    )

    class AuthenticatedRelease:
        def __init__(self, tag: str, commit: str, assets: Path) -> None:
            self.tag, self.commit, self.assets = tag, commit, assets

        def asset(self, name: str) -> bytes:
            if name == "i":
                assert self.tag == "v1.0.0" and self.commit == COMMIT
                return b"signed candidate loader"
            if name == "install.sh":
                assert self.tag == "v0.9.0" and self.commit == "c" * 40
                return b"signed previous installer"
            if name.endswith(".tar.gz"):
                assert self.tag == "v1.0.0"
                return b"authenticated archive fixture"
            assert name == "release-manifest.json"
            digest = "d" * 64 if self.tag == "v1.0.0" else "e" * 64
            return json.dumps(
                {
                    "distribution": {
                        "docker": {
                            "image": "ghcr.io/zunderlabs/zunder-guard",
                            "digest": "sha256:" + digest,
                        }
                    }
                }
            ).encode()

        def binary(self, target: str) -> bytes:
            assert target == ("linux-arm64" if row == "I2" else "linux-amd64")
            return (self.tag + target).encode()

    calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, kwargs))
        assert KEY not in repr(argv)
        assert KEY not in repr(kwargs.get("env"))
        assert set(kwargs["env"]) <= {"PATH", "HOME", "GUARD_C6_SERIALIZED"}
        assert "WALLET_FRAME" not in os.environ
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(install_run, "Release", AuthenticatedRelease)
    monkeypatch.setattr("guard_harness.install_run.subprocess.run", run)
    return subjects, calls


@pytest.mark.parametrize("row", ["I1", "I2", "I6"])
@pytest.mark.parametrize("prefix", ["", "0x"])
def test_both_modes_use_exact_subjects_and_only_private_testnet_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: str, prefix: str
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, row)
    monkeypatch.setenv("WALLET_FRAME", prefix + KEY)
    install_run.main()
    lifecycle = [(argv, kwargs) for argv, kwargs in calls if "-m" in argv]
    assert len(lifecycle) == 2
    paper, testnet = lifecycle
    assert "public-paper-account" in paper[0] and "approved-runtime-account" in testnet[0]
    assert paper[1].get("input") == b""
    assert testnet[1]["input"] == KEY.encode() + b"\n"
    for argv, kwargs in lifecycle:
        assert kwargs["check"] is True
        assert str(subjects / "i-staging") in argv
        assert str(subjects / "previous/assets/install.sh") in argv
        assert "v1.0.0" in argv and "v0.9.0" in argv
    target = "linux-arm64" if row == "I2" else "linux-amd64"
    for flag, tag in (("--binary-sha256", "v1.0.0"), ("--previous-binary-sha256", "v0.9.0")):
        assert (
            testnet[0][testnet[0].index(flag) + 1]
            == hashlib.sha256((tag + target).encode()).hexdigest()
        )
    if row == "I2":
        assert len(calls) == 3
        assert calls[0][0] == ["sudo", "tee", "/etc/zunder-native-disposable"]
        assert calls[0][1]["stdout"] == subprocess.DEVNULL
        assert "--phase" in paper[0] and "all-no-reboot" in paper[0]
        assert (
            paper[0][paper[0].index("--installer-sha256") + 1]
            == hashlib.sha256(b"signed candidate loader").hexdigest()
        )
        assert (
            testnet[0][testnet[0].index("--previous-installer-sha256") + 1]
            == hashlib.sha256(b"signed previous installer").hexdigest()
        )
    else:
        assert "--testnet-lifecycle" in testnet[0]
        for argv, _ in lifecycle:
            assert argv[argv.index("--harness-root") + 1] == str(ROOT / "harness")
            assert argv[argv.index("--mode") + 1] == ("container" if row == "I6" else "native")
    if row == "I6":
        for flag, digest in (("--release-image", "d" * 64), ("--previous-release-image", "e" * 64)):
            assert (
                testnet[0][testnet[0].index(flag) + 1]
                == "ghcr.io/zunderlabs/zunder-guard@sha256:" + digest
            )


@pytest.mark.parametrize(
    "mutation", ["diagnostic", "source", "harness", "channel", "unserialized", "key", "loader"]
)
def test_invalid_identity_or_custody_inputs_refuse_before_any_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, "I1")
    if mutation in {"diagnostic", "source", "harness", "channel"}:
        path = subjects / "input.json"
        identity = json.loads(path.read_bytes())
        identity.update(
            {
                "diagnostic": {"diagnostic": True},
                "source": {"commit": "f" * 40},
                "harness": {"harness_commit": "f" * 40},
                "channel": {"loader_channel": "unexpected"},
            }[mutation]
        )
        path.write_text(json.dumps(identity))
    elif mutation == "unserialized":
        monkeypatch.delenv("GUARD_C6_SERIALIZED")
    elif mutation == "key":
        monkeypatch.setenv("WALLET_FRAME", "invalid-frame")
    else:
        (subjects / "i-staging").write_bytes(b"different loader")
    with pytest.raises(ProcessError):
        install_run.main()
    assert calls == []


@pytest.mark.parametrize("failed_mode", ["paper", "testnet"])
def test_child_failure_redacts_arguments_and_no_receipt_is_invented(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_mode: str
) -> None:
    _, calls = prepared(tmp_path, monkeypatch, "I1")

    def fail(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, kwargs))
        if (failed_mode == "paper") or "--testnet-lifecycle" in argv:
            assert kwargs.get("input") == (b"" if failed_mode == "paper" else KEY.encode() + b"\n")
            raise subprocess.CalledProcessError(1, argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("guard_harness.install_run.subprocess.run", fail)
    with pytest.raises(ProcessError) as caught:
        install_run.main()
    assert "public-paper-account" not in str(caught.value)
    assert "approved-runtime-account" not in str(caught.value)
    assert KEY not in str(caught.value)
    assert len(calls) == (1 if failed_mode == "paper" else 2)
    assert not list((tmp_path / "evidence").rglob("*.json"))


def test_nightly_canonical_runs_promoted_source_with_current_trusted_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, "I1")
    path = subjects / "input.json"
    value = json.loads(path.read_bytes())
    value.update(harness_commit="f" * 40, loader_channel="canonical")
    path.write_text(json.dumps(value))
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    monkeypatch.setenv("INSTALL_MATRIX_PROFILE", "nightly")
    install_run.main()
    assert len(calls) == 2
    assert calls[-1][1]["input"] == KEY.encode() + b"\n"
    assert not list((tmp_path / "evidence").rglob("*.json"))


@pytest.mark.parametrize("profile", ["", "unexpected", "ALL", "Nightly"])
def test_unknown_profile_cannot_relax_source_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    _, calls = prepared(tmp_path, monkeypatch, "I1")
    monkeypatch.setenv("INSTALL_MATRIX_PROFILE", profile)
    with pytest.raises(ProcessError):
        install_run.main()
    assert calls == []


@pytest.mark.parametrize("row", ["I1", "I6"])
@pytest.mark.parametrize("scenario", ["fresh", "upgrade", "both"])
def test_guest_scenario_outputs_match_independent_and_combined_artifact_layouts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: str, scenario: str
) -> None:
    _, calls = prepared(tmp_path, monkeypatch, row)
    args = list(sys.argv)
    args[args.index("--scenario") + 1] = scenario
    monkeypatch.setattr(sys, "argv", args)
    previous_runner = subprocess.run

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        result: subprocess.CompletedProcess[bytes] = previous_runner(argv, **kwargs)
        if row == "I1" and scenario in {"fresh", "both"} and "--testnet-lifecycle" not in argv:
            output = Path(argv[argv.index("--output") + 1])
            folder = output / "channels" if scenario == "fresh" else output / "fresh/channels"
            folder.mkdir(parents=True)
            for channel in ("D1", "D5"):
                (folder / (channel + ".json")).write_text(
                    json.dumps(
                        dict(
                            channel=channel,
                            tag="v1.0.0",
                            commit=COMMIT,
                            result="passed",
                        )
                    )
                )
        return result

    monkeypatch.setattr("guard_harness.install_run.subprocess.run", run)
    install_run.main()
    assert len(calls) == 2
    for mode, (argv, kwargs) in zip(("paper", "testnet"), calls, strict=True):
        expected = tmp_path / "evidence" / mode
        if scenario != "both":
            expected /= scenario
        assert argv[argv.index("--output") + 1] == str(expected)
        assert argv[argv.index("--scenario") + 1] == scenario
        assert kwargs.get("input", b"") == (KEY.encode() + b"\n" if mode == "testnet" else b"")
    if row == "I1" and scenario in {"fresh", "both"}:
        for channel in ("D1", "D5"):
            receipt = json.loads(
                (tmp_path / "evidence/channels" / (channel + ".json")).read_bytes()
            )
            assert receipt["channel"] == channel and receipt["commit"] == COMMIT
