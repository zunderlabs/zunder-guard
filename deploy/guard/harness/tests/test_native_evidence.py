import hashlib
import json
import platform
from pathlib import Path

import pytest
from test_install_evidence import release, write
from test_testnet_run import COMMIT

from guard_harness.channel_evidence import commands, required
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.lifecycle_coverage import WINDOWS_TESTNET_SCOPE as WINDOWS_SCOPE
from guard_harness.native_evidence import PAPER, PERUSER, TESTNET, VARIANTS, predicate
from guard_harness.native_paper import LifecycleError
from guard_harness.native_refusals import refuse
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT


def fixture(root: Path, row: str) -> Path:
    subjects = root / "subjects"
    current = release(subjects / "candidate/assets")
    previous = release(subjects / "previous/assets", old=True)
    manifest = current.assets / "release-manifest.json"
    sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    write(
        subjects / "input.json",
        dict(
            tag=current.tag,
            commit=COMMIT,
            previous_tag=previous.tag,
            previous_commit=previous.commit,
            harness_commit=COMMIT,
            diagnostic=False,
            loader_channel="staging",
        ),
    )
    for variant in VARIANTS[row]:
        target = "darwin-arm64" if row == "I3" else "windows-amd64"
        for scenario in ("fresh", "upgrade"):
            directory = root / variant / scenario
            write(
                directory / "identities.json",
                dict(
                    diagnostic=False,
                    release_commit=COMMIT,
                    harness_commit=COMMIT,
                    tag=current.tag,
                    manifest_sha256=sha,
                    scenario=scenario,
                    **(
                        dict(previous_tag=previous.tag, previous_commit=previous.commit)
                        if scenario == "upgrade"
                        else {}
                    ),
                ),
            )
            identities = {
                item.tag: dict(
                    commit=item.commit,
                    version="zunder-guard " + item.tag.removeprefix("v"),
                    binary_sha256=hashlib.sha256(item.binary(target)).hexdigest(),
                )
                for item in ((current,) if scenario == "fresh" else (previous, current))
            }
            for name, coverage, mode in (
                ("paper/paper.receipt.json", PAPER, "paper"),
                ("testnet/testnet.receipt.json", TESTNET, "testnet"),
                ("testnet/per-user/receipt.json", PERUSER, "testnet"),
            ):
                checks = coverage - {"upgrade"}
                checks |= {"fresh-candidate" if scenario == "fresh" else "upgrade"}
                if row == "I4" and mode == "paper":
                    checks = checks - {"crash-recovery"} | {"manual-crash-restart"}
                if name.startswith("testnet/per-user"):
                    checks = checks - {"candidate-loader-stdin"} | {
                        "candidate-loader-stdin" if scenario == "fresh" else "previous-release-init"
                    }
                write(
                    directory / name,
                    dict(
                        schema=1,
                        result="passed",
                        coverage=sorted(checks),
                        mode=mode,
                        scenario=scenario,
                        tag=current.tag,
                        commit=COMMIT,
                        manifest_sha256=sha,
                        observed_releases=identities,
                        decision_journal_sha256="e" * 64,
                        no_exchange=True,
                        channel_coverage=["D3:homebrew"]
                        if row == "I3" and scenario == "fresh"
                        else [],
                    ),
                )
            if row == "I4":
                # Guard 1.0: the Windows testnet receipt is the per-user receipt, scoped.
                value = json.loads((directory / "testnet/per-user/receipt.json").read_bytes())
                write(directory / "testnet/testnet.receipt.json", dict(value, scope=WINDOWS_SCOPE))
            if scenario == "fresh":
                channel = "D1" if row == "I3" else "D2"
                url = "https://zunderlabs.com/i-staging" + (".ps1" if row == "I4" else "")
                write(
                    directory / f"channels/{channel}.json",
                    dict(
                        schema=1,
                        result="passed",
                        channel=channel,
                        scenario=scenario,
                        mode="paper",
                        tag=current.tag,
                        commit=COMMIT,
                        manifest_sha256=sha,
                        installed_binary_sha256=hashlib.sha256(current.binary(target)).hexdigest(),
                        version=current.tag.removeprefix("v"),
                        cleanup_complete=True,
                        coverage=sorted(required(channel, target)),
                        command=("irm " + url + " | iex")
                        if row == "I4"
                        else ("curl -fsSL " + url + " | sh"),
                        loader_sha256=hashlib.sha256(
                            current.asset("i.ps1" if row == "I4" else "i")
                        ).hexdigest(),
                        executions=[
                            dict(
                                form=form,
                                command=command,
                                result="passed",
                                installed_binary_sha256=hashlib.sha256(
                                    current.binary(target)
                                ).hexdigest(),
                                version=current.tag.removeprefix("v"),
                                mode="paper",
                                account_network="testnet",
                                health=True,
                                paper_roundtrip=True,
                                owned_process_stopped=True,
                                cleanup_complete=True,
                                setup_identity="runner-user",
                                configuration_home="user-default",
                                cleanup_method="owned-manual-cleanup"
                                if row == "I3"
                                else "released-per-user-uninstall",
                            )
                            for form, command in commands(channel).items()
                        ],
                    ),
                )
    return manifest


@pytest.mark.parametrize("row", ["I3", "I4"])
def test_complete_exact_source_row(row: str, tmp_path: Path) -> None:
    manifest = fixture(tmp_path, row)
    value = predicate(row, tmp_path, manifest, COMMIT, tmp_path / "subjects")
    assert value["journey"] == row and value["result"] == "passed"
    assert value["coverage"] == sorted(LIFECYCLE_COVERAGE[row])


def test_i4_admits_exactly_the_windows_per_user_scope() -> None:
    # Guard 1.0 (decisions.md, 15 Oct 2026): no SCM service, so no crash recovery under it.
    from guard_harness.lifecycle_coverage import MODES

    assert LIFECYCLE_COVERAGE["I4"] - MODES == {
        "manual-crash-restart",
        "D2:irm-iex",
        "windows2022-ps51",
        "windows2022-ps7",
        "windows2025-ps51",
        "windows2025-ps7",
        "per-user:credential-manager",
    }
    assert PERUSER == {
        "credential-manager",
        "candidate-loader-stdin",
        "stored-key-runtime",
        "read-only-health",
        "restart",
        "upgrade",
        "reinstall",
        "uninstall",
        "no-exchange",
    }


@pytest.mark.parametrize("mutation", ["absent", "upgrade-only", "token-in-lifecycle"])
def test_d3_requires_fresh_homebrew_measurement(tmp_path: Path, mutation: str) -> None:
    manifest = fixture(tmp_path, "I3")
    path = tmp_path / "macos/fresh/paper/paper.receipt.json"
    value = json.loads(path.read_bytes())
    value.pop("channel_coverage")
    if mutation == "upgrade-only":
        value["channel_coverage"] = []
        upgrade = tmp_path / "macos/upgrade/paper/paper.receipt.json"
        previous = json.loads(upgrade.read_bytes())
        previous["channel_coverage"] = ["D3:homebrew"]
        write(upgrade, previous)
    elif mutation == "token-in-lifecycle":
        value["coverage"].append("D3:homebrew")
    write(path, value)
    with pytest.raises(LifecycleError):
        predicate("I3", tmp_path, manifest, COMMIT, tmp_path / "subjects")


@pytest.mark.parametrize(
    "mutation",
    [
        "diagnostic",
        "other-harness",
        "missing-mode",
        "partial",
        "missing-variant",
        "missing-scope",
        "other-scope",
        "relabelled",
        "scm-tokens",
        "scm-receipt",
    ],
)
def test_no_credit_for_partial_or_diagnostic_receipts(mutation: str, tmp_path: Path) -> None:
    manifest = fixture(tmp_path, "I4")
    variant = tmp_path / "windows2022-ps51/upgrade"
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
        elif mutation == "missing-scope":
            value.pop("scope")
        elif mutation == "other-scope":
            value["scope"] = "windows-scm"
        elif mutation == "relabelled":
            value["decision_journal_sha256"] = "f" * 64  # Not the per-user measurement.
        elif mutation == "scm-tokens":
            # The 1.0.1 service tokens are refused, not merely ignored, in the 1.0 scope.
            value["coverage"] += ["windows-crash-policy-refusal", "windows-crash-policy-removed"]
        elif mutation == "scm-receipt":
            # A machine-service receipt cannot stand in for the per-user scope.
            value["coverage"] = sorted(TESTNET)
        else:
            value["coverage"].remove("stored-key-runtime")
        path.write_text(json.dumps(value))
    with pytest.raises((LifecycleError, FileNotFoundError, ValueError)):
        predicate("I4", tmp_path, manifest, COMMIT, tmp_path / "subjects")


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


@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_paper_driver_emits_exact_admitted_history_and_applicable_crash_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    from guard_harness import native_paper
    from guard_harness.cli import GuardCLI, Pair

    current = release(tmp_path / "current/assets")
    previous = release(tmp_path / "previous/assets", old=True)
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    driver = native_paper.Paper(
        release=current,
        previous=previous,
        work=tmp_path / "paper",
        shell="fixture-shell",
        scenario=scenario,
    )

    def install(item: object, **kwargs: object) -> None:
        driver.binary.parent.mkdir(parents=True, exist_ok=True)
        driver.binary.write_bytes(b"inert fixture executable never invoked")

    def command(argv: list[str], *, sensitive: bool = False) -> str:
        if "init" in argv:
            for name in ("guard.toml", "risk-paper.jsonl", "decisions-paper.jsonl"):
                (driver.home / name).write_bytes(b"inert retained fixture bytes")
        if "-Uninstall" in argv:
            driver.binary.unlink()
        return ""

    monkeypatch.setattr(driver, "install", install)
    monkeypatch.setattr(driver, "command", command)
    for action in ("start", "stop", "crash"):
        monkeypatch.setattr(driver, action, lambda: None)
    monkeypatch.setattr(
        GuardCLI, "pair", lambda self: Pair("fixture-address", "fixture-client-key")
    )
    monkeypatch.setattr(native_paper, "healthy", lambda *args, **kwargs: {})
    monkeypatch.setattr(native_paper, "round_trip", lambda *args: None)
    monkeypatch.setattr("guard_harness.native_refusals.setup_refusals", lambda *args, **kwargs: [])
    value = driver.execute("fixture-account")
    expected = PAPER - {"crash-recovery", "upgrade"} | {
        "manual-crash-restart",
        "fresh-candidate" if scenario == "fresh" else "upgrade",
    }
    checks = value["coverage"]
    assert isinstance(checks, list)
    assert set(checks) == expected
    assert value["scenario"] == scenario and not driver.binary.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "binary",
        "version",
        "scenario",
        "tag",
        "journal",
        "exchange",
        "fresh-missing",
        "fresh-predecessor-echo",
        "unrecognized-coverage",
        "channel-command",
        "channel-binary",
        "channel-cleanup",
    ],
)
def test_measured_native_identity_and_fresh_channel_cannot_be_relabelled(
    tmp_path: Path, mutation: str
) -> None:
    manifest = fixture(tmp_path, "I3")
    root = tmp_path / "macos/fresh"
    path = root / "testnet/testnet.receipt.json"
    if mutation == "fresh-missing":
        (root / "identities.json").unlink()
    else:
        if mutation.startswith("channel-"):
            path = root / "channels/D1.json"
        elif mutation == "fresh-predecessor-echo":
            path = root / "identities.json"
        value = json.loads(path.read_bytes())
        if mutation == "binary":
            value["observed_releases"]["v1.0.0"]["binary_sha256"] = "f" * 64
        elif mutation == "version":
            value["observed_releases"]["v1.0.0"]["version"] = "zunder-guard 0.9.0"
        else:
            value.update(
                {
                    "scenario": {"scenario": "upgrade"},
                    "tag": {"tag": "v0.9.0"},
                    "journal": {"decision_journal_sha256": ""},
                    "exchange": {"no_exchange": False},
                    "unrecognized-coverage": {
                        "coverage": value.get("coverage", []) + ["unmeasured-check"]
                    },
                    "fresh-predecessor-echo": {
                        "previous_tag": "v0.9.0",
                        "previous_commit": "c" * 40,
                    },
                    "channel-command": {"command": "download then execute local file"},
                    "channel-binary": {"installed_binary_sha256": "f" * 64},
                    "channel-cleanup": {"cleanup_complete": False},
                }[mutation]
            )
        path.write_text(json.dumps(value))
    with pytest.raises((LifecycleError, ProcessError, ValueError)):
        predicate("I3", tmp_path, manifest, COMMIT, tmp_path / "subjects")


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

    monkeypatch.setattr(module, "flat_scan", lambda *args: None)

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


@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_windows_default_is_per_user_scope_without_policy_or_scm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    import guard_harness.native_testnet as native

    monkeypatch.setenv("ProgramData", str(tmp_path / "program-data"))
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    current = release(tmp_path / "current/assets")
    previous = release(tmp_path / "previous/assets", old=True)
    controller = native.NativeTestnet(
        current, previous, tmp_path / "work", "fixture-account", "pwsh.exe", scenario
    )
    assert native.WINDOWS_SERVICE is False and controller.windows_service is False
    frame = b"inert fixture frame never used for custody"
    measured: dict[str, object] = {"result": "passed", "coverage": ["credential-manager"]}

    def per_user(driver: native.NativeTestnet, work: Path, key: bytes) -> dict[str, object]:
        assert driver is controller and work == controller.work / "per-user"
        assert key == frame
        driver.key = b""
        return measured

    def refused(*args: object, **kwargs: object) -> None:
        pytest.fail("Guard 1.0 Windows must not remove crash policy or touch the SCM")

    monkeypatch.setattr(native, "per_user", per_user)
    monkeypatch.setattr("guard_harness.windows_policy.prepare", refused)
    for name in ("install", "start", "stop", "crash", "action", "healthy", "audit"):
        monkeypatch.setattr(controller, name, refused)
    receipt = controller.execute(frame)
    assert receipt == {**measured, "scope": "windows-per-user"}
    assert not (controller.work / "windows-policy").exists()
    assert controller.key == b""


def test_windows_service_route_is_refused_on_macos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import guard_harness.native_testnet as native

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    current = release(tmp_path / "assets")
    with pytest.raises(LifecycleError, match="Windows service route refused"):
        native.NativeTestnet(
            current, current, tmp_path / "work", "fixture-account", "sh", windows_service=True
        )


@pytest.mark.parametrize("scenario", ["fresh", "upgrade"])
def test_per_user_receipt_precedes_independent_scm_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    import guard_harness.native_testnet as native

    monkeypatch.setenv("ProgramData", str(tmp_path / "program-data"))
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    current = release(tmp_path / "current/assets")
    previous = release(tmp_path / "previous/assets", old=True)
    controller = native.NativeTestnet(
        current,
        previous,
        tmp_path / "work",
        "fixture-account",
        "pwsh.exe",
        scenario,
        windows_service=True,  # The 1.0.1 SCM route, off by default in 1.0.
    )
    frame = b"inert fixture frame never used for custody"
    calls: list[str] = []

    def per_user(driver: native.NativeTestnet, work: Path, key: bytes) -> dict[str, object]:
        assert driver is controller and work == controller.work / "per-user"
        assert key == frame and controller.work.is_dir()
        work.mkdir()
        (work / "receipt.json").write_text("inert completed per-user evidence")
        driver.key = b""  # The real per-user driver clears its private frame on exit.
        calls.append("per-user")
        return {}

    def scm_install(item: object, *, fresh: bool = False) -> None:
        assert calls == ["per-user", "policy"] and fresh is True
        assert controller.key == frame  # SCM receives its own frame after per-user cleanup.
        calls.append("scm-refusal")
        raise LifecycleError("fixture independent SCM policy refusal")

    def prepare(subject: object, work: Path, env: object) -> dict[str, object]:
        assert calls == ["per-user"]  # W7's hosted policy step follows per-user custody.
        calls.append("policy")
        return {}

    monkeypatch.setattr(native, "per_user", per_user)
    monkeypatch.setattr("guard_harness.windows_policy.prepare", prepare)
    monkeypatch.setattr(controller, "install", scm_install)
    with pytest.raises(LifecycleError, match="independent SCM policy refusal"):
        controller.execute(frame)
    assert calls == ["per-user", "policy", "scm-refusal"]
    assert (controller.work / "per-user/receipt.json").is_file()
    assert controller.key == b""
