import json
import platform
from pathlib import Path

import pytest
from test_testnet_run import COMMIT

from guard_harness.native_evidence import PAPER, PERUSER, TESTNET, VARIANTS, predicate
from guard_harness.native_paper import LifecycleError
from guard_harness.native_refusals import refuse
from guard_harness.testnet_run import ROOT


def fixture(root: Path, row: str) -> Path:
    manifest = root / "release-manifest.json"
    manifest.write_bytes((ROOT / "release/examples/build-v2.json").read_bytes())
    for variant in VARIANTS[row]:
        directory = root / variant
        directory.mkdir()
        (directory / "identities.json").write_text(
            json.dumps({"diagnostic": False, "release_commit": COMMIT, "harness_commit": COMMIT})
        )
        for name, coverage, mode in (
            ("paper/paper.receipt.json", PAPER, "paper"),
            ("testnet/testnet.receipt.json", TESTNET, "testnet"),
            ("testnet/per-user/receipt.json", PERUSER, "testnet"),
        ):
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"result": "passed", "coverage": sorted(coverage), "mode": mode})
            )
    return manifest


@pytest.mark.parametrize("row", ["I3", "I4"])
def test_complete_exact_source_row(row: str, tmp_path: Path) -> None:
    manifest = fixture(tmp_path, row)
    value = predicate(row, tmp_path, manifest, COMMIT)
    assert value["journey"] == row and value["result"] == "passed"
    assert VARIANTS[row] <= set(value["coverage"])


@pytest.mark.parametrize(
    "mutation", ["diagnostic", "other-harness", "missing-mode", "partial", "missing-variant"]
)
def test_no_credit_for_partial_or_diagnostic_receipts(mutation: str, tmp_path: Path) -> None:
    manifest = fixture(tmp_path, "I4")
    variant = tmp_path / "windows2022-ps51"
    identity = variant / "identities.json"
    if mutation == "diagnostic":
        value = json.loads(identity.read_bytes())
        value["diagnostic"] = True
        identity.write_text(json.dumps(value))
    elif mutation == "other-harness":
        value = json.loads(identity.read_bytes())
        value["harness_commit"] = "a" * 40
        identity.write_text(json.dumps(value))
    elif mutation == "missing-variant":
        identity.unlink()
    else:
        path = variant / "testnet/testnet.receipt.json"
        value = json.loads(path.read_bytes())
        if mutation == "missing-mode":
            value["mode"] = "paper"
        else:
            value["coverage"].remove("native-custody-readback")
        path.write_text(json.dumps(value))
    with pytest.raises((LifecycleError, FileNotFoundError)):
        predicate("I4", tmp_path, manifest, COMMIT)


def test_exit_failure_alone_is_not_a_refusal(tmp_path: Path) -> None:
    # A real, harmless process fails with the wrong message; it must not earn refusal credit.
    import sys

    with pytest.raises(LifecycleError):
        refuse(
            Path(sys.executable),
            tmp_path,
            ["--nonexistent-option"],
            expected="mainnet refusal",
            log=tmp_path / "refusal.log",
        )


def test_candidate_uses_real_loader_stdin_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typing import Any

    import guard_harness.native_testnet as native
    from guard_harness.native_paper import Paper
    from guard_harness.native_release import Release
    from guard_harness.native_testnet import NativeTestnet, candidate_user_setup

    monkeypatch.setenv("ProgramData", str(tmp_path))
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    release = Release("v1.0.0", COMMIT, tmp_path / "assets")
    controller = NativeTestnet(release, release, tmp_path, "0x" + "a" * 40, "pwsh.exe")
    paper = Paper(release=release, previous=release, work=tmp_path, shell="pwsh.exe")
    calls: list[tuple[list[str], bool, bool]] = []

    def invoke(words: list[str], *, key: bool = False, sensitive: bool = False) -> str:
        calls.append((words, key, sensitive))
        return ""

    def loader(release: Release, *, windows: bool, output: Path, channel: str = "staging") -> Any:
        assert windows is True
        assert channel == "staging"
        output.write_bytes(b"captured authenticated candidate loader")
        return output

    monkeypatch.setattr(controller, "command", invoke)
    monkeypatch.setattr(native, "staged_loader", loader)
    candidate_user_setup(controller, paper, tmp_path, "zr1_fixture")
    words, key, sensitive = calls[0]
    assert key is True and sensitive is True
    assert "-File" in words and str(tmp_path / "candidate-setup.ps1") in words
    assert words[words.index("-Network") + 1] == "testnet"
    assert "-NonInteractive" in words and "-KeyStdin" in words
    assert "init" not in words and "--key-store" not in words


def test_macos_binding_stdout_is_withheld_from_artifact_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from guard_harness.native_release import Release
    from guard_harness.native_testnet import NativeTestnet

    account, wallet = "0x" + "a" * 40, "0x" + "b" * 40
    binding = json.dumps(
        {"executable": "/fixture/released/zunder-guard", "account": account, "api_wallet": wallet}
    ).encode()
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        "guard_harness.runner.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, binding, b""),
    )
    release = Release("v1.0.0", COMMIT, tmp_path / "assets")
    native = NativeTestnet(release, release, tmp_path, account, "sh")
    assert native.installed() == Path("/fixture/released/zunder-guard")
    body = (tmp_path / "step-1.log").read_text()
    assert body == "[sensitive command output withheld]\n"
    assert account not in body and wallet not in body


def test_failed_native_execution_scrubs_all_nested_artifact_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import sys

    import guard_harness.native_testnet as native

    account, wallet = "0x" + "a" * 40, "0X" + "B" * 40
    frame = b"f" * 64 + b"\n"  # inert fixture: no crypto, key store, venue or subprocess
    nested = tmp_path / "output/nested"
    nested.mkdir(parents=True)
    log = nested / "runtime.log"
    # Exercise the Windows controller explicitly on every pytest host, including Linux.
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("ProgramData", str(tmp_path / "windows-program-data"))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(frame)))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "native-test",
            "--tag",
            "v1.0.0",
            "--commit",
            COMMIT,
            "--previous-tag",
            "v0.9.0",
            "--previous-commit",
            COMMIT,
            "--account",
            account,
            "--assets",
            str(tmp_path / "assets"),
            "--work",
            str(tmp_path / "output"),
        ],
    )

    def fail(self: native.NativeTestnet, key: bytes) -> dict[str, object]:
        assert self.base == tmp_path / "windows-program-data/ZunderGuard"
        assert key == frame
        log.write_text(
            "read-only runtime failed: "
            + account
            + " "
            + wallet
            + " "
            + frame.decode().strip().upper()
        )
        raise LifecycleError("fixture failure before lifecycle completion")

    monkeypatch.setattr(native.NativeTestnet, "execute", fail)
    with pytest.raises(LifecycleError, match="fixture failure"):
        native.main()
    body = log.read_text()
    assert "read-only runtime failed:" in body
    assert body.count("[ADDRESS]") == 2 and "[REDACTED]" in body
    assert account not in body and wallet not in body and frame.decode().strip().upper() not in body


def test_per_user_predecessor_init_has_only_supported_command_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import guard_harness.native_testnet as module
    from guard_harness.native_paper import Paper
    from guard_harness.native_release import Release

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setenv("ProgramData", str(tmp_path / "windows-program-data"))
    monkeypatch.setattr(Release, "asset", lambda self, name: b"inert released-loader fixture")
    release = Release("v1.0.0", COMMIT, tmp_path / "assets")
    controller = module.NativeTestnet(release, release, tmp_path, "fixture-account", "pwsh.exe")
    binary = tmp_path / "fixture-bin/zunder-guard.exe"
    monkeypatch.setattr(Paper, "install", lambda self, release: setattr(self, "binary", binary))
    captured: list[list[str]] = []

    def capture(words: list[str], *, key: bool = False, sensitive: bool = False) -> str:
        captured.append(words)
        assert key is True and sensitive is True
        raise LifecycleError("stop before executing predecessor init")

    monkeypatch.setattr(controller, "command", capture)
    work = tmp_path / "per-user"
    with pytest.raises(LifecycleError, match="stop before executing"):
        module.per_user(controller, work, b"inert-fixture-no-live-key")
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    assert captured == [
        [
            str(binary),
            "--home",
            str(work / "home"),
            "init",
            "--non-interactive",
            "--network",
            "testnet",
            "--key-stdin",
            "--key-store",
            "credential-manager",
            "--rules",
            rules,
            "--account",
            "fixture-account",
        ]
    ]
    assert "candidate-loader-stdin" in PERUSER  # evidence token remains coverage only
    assert not (work / "receipt.json").exists()


@pytest.mark.parametrize("existing", [True, False])
def test_macos_lifecycle_preserves_setup_journal_and_initializes_only_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    import subprocess

    from guard_harness.native_release import Release
    from guard_harness.native_testnet import NativeTestnet

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    release = Release("v1.0.0", COMMIT, tmp_path / "assets")
    controller = NativeTestnet(release, release, tmp_path / "work", "fixture-account", "sh")
    controller.home = tmp_path / "service-state"
    controller.home.mkdir()
    journal = controller.home / "risk.jsonl"
    original = b"retained setup journal prefix\n"
    if existing:
        journal.write_bytes(original)
    initialized: list[list[str]] = []

    def command(words: list[str], *, key: bool = False, sensitive: bool = False) -> str:
        if words[:2] == ["sudo", "/bin/sh"]:
            # Execute the production read-only probe on fixture files without sudo.
            completed = subprocess.run(words[1:], capture_output=True, check=True)
            return completed.stdout.decode()
        initialized.append(words)
        assert words == [
            "sudo",
            "-u",
            "_zunder_guard_testnet",
            "/fixture/released/zunder-guard",
            "--home",
            str(controller.home),
            "journal-init",
            "--mode",
            "testnet",
            "--note",
            "released installer lifecycle read-only test",
        ]
        assert not journal.exists()
        journal.write_bytes(b"fixture journal initialized once\n")
        return ""

    monkeypatch.setattr(controller, "command", command)
    monkeypatch.setattr(controller, "install", lambda release, *, fresh=False: None)
    monkeypatch.setattr(controller, "installed", lambda: Path("/fixture/released/zunder-guard"))

    def stop_before_start() -> None:
        raise LifecycleError("stop before native service or venue access")

    monkeypatch.setattr(controller, "start", stop_before_start)
    with pytest.raises(LifecycleError, match="stop before native service"):
        controller.execute(b"")
    if existing:
        assert initialized == [] and journal.read_bytes() == original
    else:
        assert (
            len(initialized) == 1 and journal.read_bytes() == b"fixture journal initialized once\n"
        )


@pytest.mark.parametrize("kind", ["empty", "directory", "symlink"])
def test_macos_ambiguous_journal_is_never_initialized_or_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    import subprocess

    from guard_harness.native_release import Release
    from guard_harness.native_testnet import NativeTestnet

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    release = Release("v1.0.0", COMMIT, tmp_path / "assets")
    controller = NativeTestnet(release, release, tmp_path / "work", "fixture-account", "sh")
    controller.home = tmp_path
    journal = tmp_path / "risk.jsonl"
    if kind == "empty":
        journal.touch()
    elif kind == "directory":
        journal.mkdir()
    else:
        journal.symlink_to(tmp_path / "missing")

    def probe(words: list[str], *, key: bool = False, sensitive: bool = False) -> str:
        assert words[:2] == ["sudo", "/bin/sh"]
        subprocess.run(words[1:], capture_output=True, check=True)
        pytest.fail("ambiguous journal must not permit initialization")

    monkeypatch.setattr(controller, "command", probe)
    with pytest.raises(subprocess.CalledProcessError):
        controller.ensure_macos_journal()
    assert journal.exists() or journal.is_symlink()
