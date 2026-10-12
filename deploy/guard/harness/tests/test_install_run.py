import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from guard_harness import install_run
from guard_harness.install_evidence import EvidenceError, predicate
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
    monkeypatch.setenv("DIAGNOSTIC", "false")
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
        return subprocess.CompletedProcess(argv, 0, stdout=b"{}")

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
        assert "--diagnostic" not in argv
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
        assert len(calls) == 5
        assert calls[0][0] == ["sudo", "tee", "/etc/zunder-native-disposable"]
        assert calls[0][1]["stdout"] == subprocess.DEVNULL
        assert "--phase" in paper[0] and "all-no-reboot" in paper[0]
        for argv, _ in lifecycle:
            assert Path(argv[argv.index("--output") + 1]).is_relative_to(install_run.I2_PRIVATE)
        assert (tmp_path / "evidence/paper/upgrade").is_dir()
        assert (tmp_path / "evidence/testnet/upgrade").is_dir()
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
    if mutation != "key":
        assert os.environ["WALLET_FRAME"] == KEY
        assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("row", ["I1", "I2", "I6"])
def test_explicit_diagnostic_runs_authenticated_old_release_with_current_bound_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: str
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, row)
    identity_path = subjects / "input.json"
    identity = json.loads(identity_path.read_bytes())
    harness = "f" * 40
    identity.update(diagnostic=True, harness_commit=harness)
    identity_path.write_text(json.dumps(identity))
    monkeypatch.setenv("GITHUB_SHA", harness)
    monkeypatch.setenv("DIAGNOSTIC", "true")
    install_run.main()
    lifecycle = [(argv, kwargs) for argv, kwargs in calls if "-m" in argv]
    assert len(lifecycle) == 2
    for argv, _ in lifecycle:
        assert ("--diagnostic" in argv) is (row != "I2")
        assert str(subjects / "i-staging") in argv
        assert "v1.0.0" in argv and "v0.9.0" in argv
    assert lifecycle[0][1]["input"] == b""
    assert lifecycle[1][1]["input"] == KEY.encode() + b"\n"
    marker = json.loads((tmp_path / "evidence/diagnostic-only.json").read_bytes())
    assert marker == {
        "schema": 1,
        "status": "diagnostic_only",
        "diagnostic": True,
        "row": row,
        "scenario": "upgrade",
        "commit": COMMIT,
        "harness_commit": harness,
    }
    assert KEY not in json.dumps(marker)
    # Formal admission refuses at the identity boundary, before attempting
    # runtime receipts or a manifest, even after the diagnostic completed.
    with pytest.raises(EvidenceError, match="released source and harness identity differ"):
        predicate(row, tmp_path / "evidence", subjects, tmp_path / "unused-manifest", COMMIT)


@pytest.mark.parametrize(
    "mutation",
    [
        "true-with-false-subject",
        "false-with-true-subject",
        "numeric-true",
        "numeric-false",
        "string-true",
        "missing-diagnostic",
        "missing-harness",
        "harness-mismatch",
        "missing-github-sha",
        "invalid-github-sha",
        "nightly-diagnostic",
        "nonliteral-true",
        "nonliteral-false",
        "empty-mode",
        "unknown-profile",
        "malformed-object",
    ],
)
def test_diagnostic_admission_mismatch_refuses_before_wallet_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, "I1")
    path = subjects / "input.json"
    identity = json.loads(path.read_bytes())
    if mutation == "true-with-false-subject":
        monkeypatch.setenv("DIAGNOSTIC", "true")
    elif mutation == "false-with-true-subject":
        identity["diagnostic"] = True
    elif mutation in {"numeric-true", "numeric-false", "string-true"}:
        identity["diagnostic"] = {"numeric-true": 1, "numeric-false": 0, "string-true": "true"}[
            mutation
        ]
        monkeypatch.setenv("DIAGNOSTIC", "true" if mutation != "numeric-false" else "false")
    elif mutation in {"missing-diagnostic", "missing-harness"}:
        identity.pop("diagnostic" if mutation == "missing-diagnostic" else "harness_commit")
    elif mutation == "harness-mismatch":
        identity.update(diagnostic=True, harness_commit="f" * 40)
        monkeypatch.setenv("DIAGNOSTIC", "true")
    elif mutation == "missing-github-sha":
        monkeypatch.delenv("GITHUB_SHA")
        identity.update(diagnostic=True, harness_commit=None)
        monkeypatch.setenv("DIAGNOSTIC", "true")
    elif mutation == "invalid-github-sha":
        monkeypatch.setenv("GITHUB_SHA", "invalid")
        identity.update(diagnostic=True, harness_commit="invalid")
        monkeypatch.setenv("DIAGNOSTIC", "true")
    elif mutation == "nightly-diagnostic":
        identity.update(diagnostic=True, loader_channel="canonical")
        monkeypatch.setenv("DIAGNOSTIC", "true")
        monkeypatch.setenv("INSTALL_MATRIX_PROFILE", "nightly")
    elif mutation in {"nonliteral-true", "nonliteral-false", "empty-mode"}:
        monkeypatch.setenv(
            "DIAGNOSTIC",
            {"nonliteral-true": "True", "nonliteral-false": "0", "empty-mode": ""}[mutation],
        )
    elif mutation == "unknown-profile":
        monkeypatch.setenv("INSTALL_MATRIX_PROFILE", "unexpected")
    path.write_text(json.dumps([] if mutation == "malformed-object" else identity))
    with pytest.raises(ProcessError):
        install_run.main()
    assert calls == []
    assert os.environ["WALLET_FRAME"] == KEY
    assert not (tmp_path / "evidence").exists()


def test_diagnostic_loader_is_still_authenticated_before_wallet_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, "I6")
    path = subjects / "input.json"
    identity = json.loads(path.read_bytes())
    identity.update(diagnostic=True, harness_commit="f" * 40)
    path.write_text(json.dumps(identity))
    monkeypatch.setenv("DIAGNOSTIC", "true")
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    (subjects / "i-staging").write_bytes(b"unauthenticated override")
    with pytest.raises(ProcessError, match="loader snapshot differs from signed release"):
        install_run.main()
    assert calls == []
    assert os.environ["WALLET_FRAME"] == KEY
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("previous", [False, True])
def test_diagnostic_cannot_skip_released_binary_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, previous: bool
) -> None:
    subjects, calls = prepared(tmp_path, monkeypatch, "I6")
    path = subjects / "input.json"
    identity = json.loads(path.read_bytes())
    identity.update(diagnostic=True, harness_commit="f" * 40)
    path.write_text(json.dumps(identity))
    monkeypatch.setenv("DIAGNOSTIC", "true")
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    release_type = vars(install_run)["Release"]
    original_binary: Callable[[Any, str], bytes] = release_type.binary

    def refused_binary(release: Any, target: str) -> bytes:
        if (release.tag == "v0.9.0") is previous:
            raise ProcessError("release snapshot differs from authenticated C2 bytes")
        return original_binary(release, target)

    monkeypatch.setattr(release_type, "binary", refused_binary)
    with pytest.raises(ProcessError, match="release snapshot differs from authenticated C2 bytes"):
        install_run.main()
    assert calls == []
    assert os.environ["WALLET_FRAME"] == KEY
    assert not (tmp_path / "evidence").exists()


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


def test_private_export_allowlist_redacts_logs_without_touching_custody(tmp_path: Path) -> None:
    source = tmp_path / "private"
    source.mkdir(mode=0o700)
    receipt = '{"stage":"passed","binary_sha256":"' + "a" * 64 + '"}\n'
    (source / "testnet-lifecycle.json").write_text(receipt)
    (source / "testnet-service-install.log").write_text(
        "account=0x" + "1" * 40 + " key=0x" + "2" * 64
    )
    (source / "pair.json").write_text("private pairing fixture")
    (source / "guard.toml").write_text("private custody fixture")
    before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in source.iterdir()}
    payload = install_run.evidence_payload(source)
    assert set(payload) == {"testnet-lifecycle.json", "testnet-service-install.log"}
    assert payload["testnet-lifecycle.json"] == receipt
    assert payload["testnet-service-install.log"] == "[sensitive command output withheld]\n"
    assert before == {p.name: (p.read_bytes(), p.stat().st_mode) for p in source.iterdir()}
    assert source.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "attack", ["symlink", "hardlink", "oversize", "directory", "identifier", "escaped-identifier"]
)
def test_private_export_refuses_unsafe_allowlisted_file(tmp_path: Path, attack: str) -> None:
    source = tmp_path / "private"
    source.mkdir(mode=0o700)
    target = source / "testnet-lifecycle.json"
    if attack == "symlink":
        hidden = tmp_path / "hidden"
        hidden.write_text("private")
        target.symlink_to(hidden)
    elif attack == "hardlink":
        hidden = tmp_path / "hidden"
        hidden.write_text("{}")
        target.hardlink_to(hidden)
    elif attack == "directory":
        target.mkdir()
    elif attack == "oversize":
        target.write_bytes(b" " * 65537)
    else:
        target.write_text(
            json.dumps({"account": "0x" + "1" * 40}).replace("0x", "\\u0030\\u0078")
            if attack == "escaped-identifier"
            else json.dumps({"account": "0x" + "1" * 40})
        )
    with pytest.raises(ProcessError):
        install_run.evidence_payload(source)


def test_i2_failure_exports_readable_safe_diagnostics_and_preserves_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "root-private"
    source.mkdir(mode=0o700)
    (source / "testnet-service-install.log").write_text("[sensitive command output withheld]\n")
    destination = tmp_path / "runner-evidence"
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        if "--output" in argv:
            raise subprocess.CalledProcessError(2, argv)
        assert kwargs["stdout"] == subprocess.PIPE and kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["input"] == b"" and KEY not in repr(argv)
        return subprocess.CompletedProcess(
            argv, 0, stdout=json.dumps(install_run.evidence_payload(source)).encode()
        )

    monkeypatch.setattr("guard_harness.install_run.subprocess.run", run)
    with pytest.raises(ProcessError, match="exit 2"):
        install_run.i2_child(
            ["sudo", "fixture", "--output", str(source)],
            destination=destination,
            env={},
            input=KEY.encode(),
        )
    assert len(calls) == 2
    assert (destination / "testnet-service-install.log").read_text().startswith("[sensitive")
    assert (destination / "testnet-service-install.log").stat().st_uid == os.geteuid()
    assert source.stat().st_mode & 0o777 == 0o700
    assert not list(destination.rglob("*.json"))


def test_raw_nonhex_credentials_are_withheld(tmp_path: Path) -> None:
    source = tmp_path / "private"
    source.mkdir(mode=0o700)
    (source / "service-journal.log").write_text("zgl1_private-sentinel bearer=private-token")
    assert install_run.evidence_payload(source) == {
        "service-journal.log": "[sensitive command output withheld]\n"
    }


@pytest.mark.parametrize("error_type", [ProcessError, OSError, ValueError])
def test_secondary_export_refusal_preserves_primary_child_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    def fail_child(*args: Any, **kwargs: Any) -> None:
        raise ProcessError("install lifecycle child failed (exit 2)")

    def fail_export(*args: Any, **kwargs: Any) -> None:
        raise error_type("export failed")

    monkeypatch.setattr(install_run, "child", fail_child)
    monkeypatch.setattr(install_run, "export_i2", fail_export)
    with pytest.raises(ProcessError, match=r"exit 2.*diagnostic export refused"):
        install_run.i2_child(
            ["fixture", "--output", str(tmp_path / "private")],
            destination=tmp_path / "public",
            env={},
        )
