import hashlib
import io
import json
import subprocess
import sys
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from guard_harness import linux_channels as channels
from guard_harness.cli import Pair
from guard_harness.linux_lifecycle import Inputs, LifecycleError, authenticated_file
from guard_harness.runner import RunResult


def inputs(tmp_path: Path) -> Inputs:
    loader = tmp_path / "signed-i"
    loader.write_bytes(b"signed loader snapshot")
    return Inputs(
        loader,
        hashlib.sha256(loader.read_bytes()).hexdigest(),
        tmp_path / "old",
        "b" * 64,
        "v1.2.3",
        "v1.2.2",
        "rules",
        "0x" + "1" * 40,
        tmp_path,
        "a" * 32,
        scenario="fresh",
        release_commit="c" * 40,
        manifest_sha256="d" * 64,
        binary_sha256="e" * 64,
    )


def test_actual_literal_curl_pipe_and_two_bound_head_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = inputs(tmp_path)
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> RunResult:
        assert argv[:3] == ["curl", "-fsSL", "https://zunderlabs.com/i-staging"]
        Path(argv[-1]).write_bytes(value.installer.read_bytes())
        assert kwargs["sensitive_output"] is True
        return RunResult(0, "", kwargs["log"])

    monkeypatch.setattr(channels, "run", run)
    monkeypatch.setattr(channels, "dialogue", lambda args, *rest, **kwargs: calls.append(args))
    authenticate = authenticated_file
    monkeypatch.setattr(
        channels,
        "authenticated_file",
        lambda path, sha: (
            None if path == Path("/usr/local/bin/zunder-guard") else authenticate(path, sha)
        ),
    )
    channels.curl_install(value)
    assert calls == [["/bin/sh", "-c", "curl -fsSL https://zunderlabs.com/i-staging | sh"]]
    channels.curl_receipt(value, dict(form="website-parameter", result="passed"))
    receipt = json.loads((tmp_path / "channels/D1.json").read_bytes())
    assert receipt["tag"] == value.version and receipt["scenario"] == "fresh"
    assert receipt["loader_sha256"] == value.installer_sha256
    assert receipt["installed_binary_sha256"] == value.binary_sha256


def test_interactive_literal_command_has_controlling_tty_and_only_paper_replies(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "dialogue.py"
    fixture.write_text("""import os
assert os.isatty(0)
prompts=[("Keep these? [Y/edit]", ""), ("Hyperliquid account address", "0x"+"1"*40),
         ("Mode: paper", "paper"), ("Paper mode reads which network's account", "testnet")]
for prompt, expected in prompts:
    answer=input(prompt)
    assert answer == expected
print("untracked synthetic pairing output must stay withheld")
""")
    channels.dialogue([sys.executable, str(fixture)], "0x" + "1" * 40, "testnet", timeout=5)


def test_interactive_failure_never_replays_output(tmp_path: Path) -> None:
    fixture = tmp_path / "failure.py"
    fixture.write_text('print("private-output-needle", flush=True)\nraise SystemExit(1)\n')
    with pytest.raises(LifecycleError) as error:
        channels.dialogue([sys.executable, str(fixture)], "0x" + "1" * 40, "testnet", timeout=5)
    assert "private-output-needle" not in str(error.value)


def test_manual_requires_real_admitted_archive_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = inputs(tmp_path)
    monkeypatch.setattr(
        channels, "run", lambda *a, **k: pytest.fail("network before archive admission")
    )
    with pytest.raises(LifecycleError, match="archive"):
        channels.manual(value)


@pytest.mark.parametrize("hang", [False, True])
def test_manual_channel_verifies_extracts_exercises_and_reaps_only_owned_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hang: bool
) -> None:
    value = inputs(tmp_path)
    binary_bytes, verifier_bytes = b"fixture released executable", b"fixture pinned verifier"
    value.installer.write_text(
        " C=v3.1.3 R=fixture\nP=linux-amd64 H=" + hashlib.sha256(verifier_bytes).hexdigest()
    )
    archive = tmp_path / "admitted.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo("zunder-guard")
        member.size = len(binary_bytes)
        tar.addfile(member, io.BytesIO(binary_bytes))
    value = replace(
        value,
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        binary_sha256=hashlib.sha256(binary_bytes).hexdigest(),
    )
    calls: list[list[str]] = []
    roots: list[Path] = []

    def run(argv: list[str], **kwargs: Any) -> RunResult:
        calls.append(argv)
        root = kwargs["cwd"]
        roots.append(root)
        assert kwargs["sensitive_output"] is True and kwargs["stdin"] == b""
        output = ""
        if argv[0] == "curl":
            target = Path(argv[-1])
            target.write_bytes(
                archive.read_bytes()
                if target.name.endswith(".tar.gz")
                else verifier_bytes
                if target.name == "cosign"
                else b"fixture signed checksums"
            )
        elif argv[0] == "tar":
            with tarfile.open(root / argv[-1]) as source:
                source.extractall(root, filter="data")
        elif "pair" in argv:
            output = json.dumps({"client_address": "0x" + "1" * 40, "client_key": "0x" + "2" * 64})
        elif "status" in argv:
            output = json.dumps(
                dict(
                    mode="paper",
                    network="paper",
                    account=value.account,
                    version="1.2.3",
                    halted=False,
                    kill_switch=False,
                    journal={"ok": True},
                    licence=dict(
                        state="none",
                        licensee=None,
                        expires_at_ms=None,
                        fee_free=False,
                        source="file",
                    ),
                )
            )
        return RunResult(0, output, kwargs["log"])

    def init(argv: list[str], account: str, network: str, **kwargs: Any) -> None:
        assert argv[-1] == "init" and account == value.account and network == "mainnet"
        home = kwargs["home"]
        home.mkdir()
        (home / "guard.toml").write_bytes(b"private fixture pairing")

    class Process:
        returncode: int | None = None
        terminated = killed = False

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: int) -> int:
            if hang and not self.killed:
                raise subprocess.TimeoutExpired("owned fixture", timeout)
            self.returncode = -9 if self.killed else 0
            return self.returncode

    process = Process()
    monkeypatch.setattr(channels, "run", run)
    monkeypatch.setattr(channels, "dialogue", init)
    monkeypatch.setattr("guard_harness.linux_channels.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("guard_harness.linux_channels.subprocess.Popen", lambda *a, **k: process)
    monkeypatch.setattr(channels, "wait_healthy", lambda *a: {})
    decisions: list[str] = []
    monkeypatch.setattr(channels, "round_trip", lambda guard, pair: decisions.append(pair.address))
    if hang:
        with pytest.raises(LifecycleError, match="did not stop cleanly"):
            channels.manual(value)
        assert process.killed and not (tmp_path / "channels/D5.json").exists()
    else:
        channels.manual(value)
        receipt = json.loads((tmp_path / "channels/D5.json").read_bytes())
        assert receipt["archive_sha256"] == value.archive_sha256 and decisions
        assert any("verify-blob" in argv for argv in calls)
        assert ["sha256sum", "--ignore-missing", "-c", "SHA256SUMS"] in calls
    assert process.terminated and process.returncode is not None
    assert roots and all(not root.exists() for root in roots)


def test_website_parameter_form_omits_mode_prompt_with_real_controlling_tty(tmp_path: Path) -> None:
    fixture = tmp_path / "parameter.py"
    fixture.write_text("""import os
assert os.isatty(0)
prompts=[("Keep these? [Y/edit]", ""),
 ("Hyperliquid account address", "0x"+"1"*40),
 ("Paper mode reads which network's account", "testnet")]
for prompt, expected in prompts:
    assert input(prompt) == expected
""")
    channels.dialogue(
        [sys.executable, str(fixture)], "0x" + "1" * 40, "testnet", timeout=5, mode_supplied=True
    )


def test_container_published_pipe_binds_both_heads_and_keeps_account_out_of_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = replace(inputs(tmp_path), account_network="testnet")
    calls: list[list[str]] = []

    def invoke(argv: list[str], **kwargs: Any) -> RunResult:
        calls.append(argv)
        assert kwargs["sensitive_output"] is True
        if argv[0] == "curl":
            Path(argv[-1]).write_bytes(value.installer.read_bytes())
        else:
            assert value.account not in " ".join(argv)
            assert kwargs["env"]["GUARD_CHANNEL_ACCOUNT"] == value.account
            assert kwargs["stdin"] == b""
        return RunResult(0, "", kwargs["log"])

    monkeypatch.setattr(channels, "run", invoke)
    command = channels.container_curl_install(value)
    assert len(calls) == 3
    assert (
        command
        == "curl -fsSL https://zunderlabs.com/i-staging | sh -s -- --container --network paper"
    )
    assert calls[1][:2] == ["/bin/sh", "-c"] and calls[1][2].startswith(command)


@pytest.mark.parametrize("uninstall_mutates_state", [False, True])
def test_second_linux_website_install_has_fresh_data_measured_pair_and_released_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uninstall_mutates_state: bool
) -> None:
    from types import SimpleNamespace
    from typing import cast

    from guard_harness.linux_lifecycle import NativeLifecycle

    value = replace(inputs(tmp_path), account_network="testnet")
    home, binary = tmp_path / "data", tmp_path / "binary"
    home.mkdir()
    (home / "guard.toml").write_bytes(b"bare retained config")
    monkeypatch.setattr(channels, "HOME", home)
    monkeypatch.setattr(channels, "BINARY", binary)
    monkeypatch.setattr(channels, "CHANNEL_PRIVATE", tmp_path)
    events: list[str] = []
    pair = Pair("0x" + "1" * 40, "0x" + "2" * 64)

    def install(arg: Inputs, *, website: bool = False) -> None:
        assert website and not home.exists() and arg == value
        home.mkdir()
        (home / "guard.toml").write_bytes(b"website fresh config")
        binary.write_bytes(b"fixture measured binary")
        events.append("fresh install")

    def command(name: str, argv: list[str]) -> str:
        if name == "D1-website-pair-owner":
            assert argv == ["chown", "-R", "zunder-guard:zunder-guard", str(home)]
            events.append("restore service ownership")
            return ""
        assert name == "D1-website-uninstall" and "--uninstall" in argv
        events.append("released uninstall")
        binary.unlink()
        if uninstall_mutates_state:
            (home / "guard.toml").write_bytes(b"unexpected uninstall mutation")
        return ""

    def issue_pair() -> Pair:
        events.append("pair")
        return pair

    def systemctl(label: str, verb: str) -> None:
        events.append(verb)
        if verb == "stop":
            with (home / "risk-paper.jsonl").open("a") as stream:
                stream.write("fixture stopped event\n")

    def paper_roundtrip(guard: object, observed: Pair) -> None:
        assert observed == pair
        events.append("pair roundtrip")
        with (home / "decisions-paper.jsonl").open("a") as stream:
            stream.write("fixture measured veto/allow/resize\n")

    lifecycle = cast(
        NativeLifecycle,
        SimpleNamespace(
            inputs=value,
            cli=SimpleNamespace(pair=issue_pair),
            guard=object(),
            version=lambda v: events.append("version"),
            healthy=lambda: events.append("health"),
            systemctl=systemctl,
            command=command,
        ),
    )
    monkeypatch.setattr(channels, "curl_install", install)
    monkeypatch.setattr(channels, "round_trip", paper_roundtrip)
    if uninstall_mutates_state:
        with pytest.raises(LifecycleError, match="changed persistent state"):
            channels.website_install(lifecycle)
        assert not (tmp_path / "channels/D1.json").exists()
        return
    result = channels.website_install(lifecycle)
    assert events == [
        "fresh install",
        "version",
        "health",
        "stop",
        "pair",
        "restore service ownership",
        "start",
        "health",
        "pair roundtrip",
        "restart",
        "health",
        "pair roundtrip",
        "stop",
        "released uninstall",
    ]
    assert (home / "guard.toml").read_bytes() == b"bare retained config"
    assert (
        tmp_path / (".guard-channel-data-" + value.marker) / "website-data/guard.toml"
    ).read_bytes() == b"website fresh config"
    retained = tmp_path / (".guard-channel-data-" + value.marker) / "website-data"
    assert (retained / "decisions-paper.jsonl").read_text().count("measured") == 2
    assert (retained / "risk-paper.jsonl").read_text().count("stopped") == 2
    assert (
        result["cleanup_method"] == "released-native-uninstall"
        and result["form"] == "website-parameter"
    )
    channels.curl_receipt(value, result)
    saved = json.loads((tmp_path / "channels/D1.json").read_bytes())
    assert [entry["form"] for entry in saved["executions"]] == [
        "manifest-bare",
        "website-parameter",
    ]
