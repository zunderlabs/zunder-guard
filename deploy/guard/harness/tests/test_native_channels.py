import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_install_evidence import release

from guard_harness import native_channels
from guard_harness.cli import GuardCLI, Pair
from guard_harness.native_paper import LifecycleError


@pytest.mark.parametrize(
    "case,expected",
    [
        ("eof", "outcome=child-nonzero, phase=account, exit=2"),
        ("incomplete", "outcome=incomplete-dialogue, phase=account, exit=0"),
        ("deadline", "outcome=deadline, phase=account, exit=unknown"),
        ("oversized-status", "outcome=child-nonzero, phase=account, exit=unknown"),
        ("private", "paper channel output/private prompt refused"),
    ],
)
def test_conpty_failure_exposes_only_fixed_progress(
    monkeypatch: pytest.MonkeyPatch, case: str, expected: str
) -> None:
    class Child:
        fileobj = object()
        exitstatus = 0 if case == "incomplete" else 1000000 if case == "oversized-status" else 2

        def __init__(self) -> None:
            self.reads = 0
            self.closed = False
            self.replies: list[str] = []

        def read(self, size: int) -> str:
            self.reads += 1
            if self.reads > 1:
                raise EOFError
            return "private-transcript-sentinel Keep these? [Y/edit]" + (
                " API wallet private prompt" if case == "private" else ""
            )

        def write(self, value: str) -> None:
            self.replies.append(value)

        def isalive(self) -> bool:
            return case == "deadline" or self.reads < 2

        def close(self, force: bool) -> None:
            assert force
            self.closed = True

    child = Child()
    monkeypatch.setitem(
        sys.modules,
        "winpty",
        SimpleNamespace(
            Backend=SimpleNamespace(ConPTY=1),
            PtyProcess=SimpleNamespace(spawn=lambda *args, **kwargs: child),
        ),
    )
    monkeypatch.setattr(
        "guard_harness.native_channels.select.select", lambda *args: ([child.fileobj], [], [])
    )
    ticks = iter([0.0, 0.0, 0.1, 2.0])
    monkeypatch.setattr("guard_harness.native_channels.time.monotonic", lambda: next(ticks))
    with pytest.raises(LifecycleError) as error:
        native_channels.dialogue(
            ["private-argv-sentinel"], "private-account-sentinel", env={}, windows=True, timeout=1
        )
    assert expected in str(error.value)
    assert "sentinel" not in str(error.value)
    assert child.closed
    assert child.replies == ([] if case == "private" else ["\r\n"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX owned manual cleanup")
@pytest.mark.parametrize(
    "mutation", [None, "extra-notice", "tampered-notice", "binary-changed", "symlink"]
)
def test_macos_manual_cleanup_checks_signed_owned_inventory_before_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str | None
) -> None:
    current = release(tmp_path / "assets")
    binary_bytes = current.binary("darwin-arm64")
    bodies = {
        "zunder-guard": binary_bytes,
        "LICENSE": b"inert license fixture",
        "NOTICE": b"inert notice fixture",
        "THIRD_PARTY_LICENSES.md": b"inert third party fixture",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, body in bodies.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    filename = "zunder-guard-v1.0.0-darwin-arm64.tar.gz"
    (current.assets / filename).write_bytes(buffer.getvalue())
    manifest = json.loads((current.assets / "release-manifest.json").read_bytes())
    manifest["assets"][filename]["sha256"] = hashlib.sha256(buffer.getvalue()).hexdigest()
    (current.assets / "release-manifest.json").write_text(json.dumps(manifest))
    sums = current.assets / "SHA256SUMS"
    sums.write_text(
        "".join(
            hashlib.sha256((current.assets / line.split()[1]).read_bytes()).hexdigest()
            + "  "
            + line.split()[1]
            + "\n"
            for line in sums.read_text().splitlines()
        )
    )
    binary = tmp_path / "prefix/bin/zunder-guard"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(binary_bytes)
    notices = binary.parent.parent / "share/licenses/zunder-guard"
    notices.mkdir(parents=True)
    for name, body in bodies.items():
        if name != "zunder-guard":
            (notices / name).write_bytes(body)
    if mutation == "extra-notice":
        (notices / "customer-file").write_text("preserve")
    elif mutation == "tampered-notice":
        (notices / "NOTICE").write_text("changed")
    elif mutation == "binary-changed":
        binary.write_bytes(b"changed")
    elif mutation == "symlink":
        (notices / "NOTICE").unlink()
        (notices / "NOTICE").symlink_to(tmp_path / "untouched")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("user-owned fixture must not invoke privileged subprocess")

    monkeypatch.setattr(native_channels, "run", forbidden)
    if mutation:
        with pytest.raises(LifecycleError):
            native_channels.remove_macos_paper(current, binary, env={}, work=tmp_path)
        assert binary.exists()
    else:
        native_channels.remove_macos_paper(current, binary, env={}, work=tmp_path)
        assert not binary.exists() and not notices.exists()


def test_default_user_home_cleanup_refuses_links(tmp_path: Path) -> None:
    home = tmp_path / "owned"
    home.mkdir()
    outside = tmp_path / "untouched"
    outside.write_text("preserve")
    (home / "guard.toml").symlink_to(outside)
    with pytest.raises(LifecycleError):
        native_channels.clear_home(home)
    assert outside.read_text() == "preserve"


@pytest.mark.skipif(os.name == "nt", reason="native POSIX terminal branch")
@pytest.mark.parametrize("private_prompt", [False, True])
@pytest.mark.parametrize("parameter_form", [False, True])
def test_public_paper_dialogue_executes_real_terminal_and_refuses_key_prompt(
    private_prompt: bool,
    parameter_form: bool,
) -> None:
    code = "import sys\n"
    if private_prompt:
        code += "print('API wallet private key:',flush=True);sys.stdin.readline()\n"
    else:
        for prompt in (
            "Keep these? [Y/edit]",
            "Hyperliquid account address",
            "Mode: paper",
            "Paper mode reads which network's account",
        ):
            if parameter_form and prompt == "Mode: paper":
                continue
            code += f"print({prompt!r},flush=True);sys.stdin.readline()\n"
    if private_prompt:
        with pytest.raises(LifecycleError, match="private prompt"):
            native_channels.dialogue(
                [sys.executable, "-c", code],
                "inert-account",
                env={"PATH": os.environ["PATH"]},
                windows=False,
                timeout=5,
                mode_prompt=not parameter_form,
            )
    else:
        native_channels.dialogue(
            [sys.executable, "-c", code],
            "inert-account",
            env={"PATH": os.environ["PATH"]},
            windows=False,
            timeout=5,
            mode_prompt=not parameter_form,
        )


@pytest.mark.parametrize("windows", [False, True])
def test_native_executes_both_literal_user_forms_and_measured_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    current = release(tmp_path / "assets")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "user"))
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.setenv("WALLET_FRAME", "inert-must-not-pass")
    monkeypatch.setattr(
        "guard_harness.native_channels.platform.system", lambda: "Windows" if windows else "Darwin"
    )
    if not windows:
        monkeypatch.setattr("guard_harness.native_channels.os.geteuid", lambda: 501)
    binary = tmp_path / "local/Programs/zunder-guard/zunder-guard.exe"
    dialogues: list[list[str]] = []
    heads: list[str] = []
    calls: list[list[str]] = []
    target = "windows-amd64" if windows else "darwin-arm64"
    monkeypatch.setattr(native_channels, "destinations", lambda *args: (binary,))

    def staged(release: Any, *, windows: bool, output: Path, channel: str) -> Path:
        assert channel == "staging"
        heads.append(output.name)
        output.write_bytes(release.asset("i.ps1"))
        return output

    def dialogue(argv: list[str], account: str, **kwargs: Any) -> None:
        dialogues.append(argv)
        assert "WALLET_FRAME" not in kwargs["env"]
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(current.binary(target))
        home = tmp_path / "user/.zunder-guard"
        home.mkdir(parents=True)
        (home / "guard.toml").write_text(
            'mode="paper"\nnetwork="testnet"\naccount="inert-account"\n'
        )
        assert "ZUNDER_GUARD_HOME" not in kwargs["env"]

    def command(argv: list[str], **kwargs: Any) -> Any:
        from types import SimpleNamespace

        calls.append(argv)
        if "-Uninstall" in argv:
            binary.unlink()
        return SimpleNamespace(output="zunder-guard 1.0.0")

    class Process:
        pid = 4242

        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            calls.append(argv)
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert "WALLET_FRAME" not in kwargs["env"]

        def terminate(self) -> None:
            pass

        def wait(self, *, timeout: int) -> int:
            return 0

    monkeypatch.setattr(native_channels, "staged_loader", staged)
    monkeypatch.setattr(native_channels, "dialogue", dialogue)
    monkeypatch.setattr(native_channels, "run", command)
    monkeypatch.setattr("guard_harness.native_channels.subprocess.Popen", Process)
    if not windows:
        monkeypatch.setattr("guard_harness.native_channels.os.killpg", lambda *args: None)
        monkeypatch.setattr(
            native_channels, "remove_macos_paper", lambda *args, **kwargs: binary.unlink()
        )
    monkeypatch.setattr(GuardCLI, "pair", lambda self: Pair("inert-address", "inert-client-key"))
    monkeypatch.setattr(
        native_channels,
        "healthy",
        lambda *args, **kwargs: {"mode": "paper", "account": "inert-account"},
    )
    monkeypatch.setattr(native_channels, "round_trip", lambda *args: None)
    result = native_channels.execute(
        current, tmp_path / "work", account="inert-account", shell="pwsh.exe"
    )
    expected_windows = [
        [
            "pwsh.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "irm https://zunderlabs.com/i-staging.ps1 | iex",
        ],
        [
            "pwsh.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "& ([scriptblock]::Create((irm https://zunderlabs.com/i-staging.ps1))) -Network paper",
        ],
    ]
    assert dialogues == (
        expected_windows
        if windows
        else [
            ["/bin/sh", "-c", "curl -fsSL https://zunderlabs.com/i-staging | sh"],
            [
                "/bin/sh",
                "-c",
                "curl -fsSL https://zunderlabs.com/i-staging | sh -s -- --network paper",
            ],
        ]
    )
    assert (
        heads == (["before.ps1", "after.ps1"] if windows else ["before.loader", "after.loader"]) * 2
    )
    if windows:
        assert any(
            "-Uninstall" in call and str(tmp_path / "work/manifest-bare/after.ps1") in call
            for call in calls
        )
    else:
        assert all("sudo" not in call for call in calls)
    assert result["cleanup_complete"] is True and not binary.exists()
    assert [item["form"] for item in result["executions"]] == ["manifest-bare", "website-parameter"]
    assert not (tmp_path / "user/.zunder-guard").exists()
    assert all(
        item["cleanup_method"]
        == ("released-per-user-uninstall" if windows else "owned-manual-cleanup")
        for item in result["executions"]
    )
    if not windows:
        assert "uninstall" not in result["coverage"]
