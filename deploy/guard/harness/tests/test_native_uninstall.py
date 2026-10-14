import ast
import io
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest
from test_macos_uninstall import fixture, module

from guard_harness import native_uninstall
from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release
from guard_harness.native_testnet import NativeTestnet, sanitize_logs
from guard_harness.runner import RunError
from guard_harness.testnet_run import ROOT


@pytest.mark.parametrize("reason", sorted(native_uninstall.INSTALLER_REFUSALS))
def test_installer_fixed_refusals_are_kept(reason: str) -> None:
    assert native_uninstall.failure_reason("install.sh: " + reason + "\n") == reason


@pytest.mark.parametrize("reason", sorted(native_uninstall.HELPER_REFUSALS))
def test_product_helper_emits_only_the_fixed_reason(reason: str) -> None:
    product = module()
    assert (
        native_uninstall.failure_reason(product.refusal_message(product.UninstallRefused(reason)))
        == reason
    )


def test_all_product_refusals_are_allow_listed() -> None:
    product = module()
    assert product.FIXED_REFUSALS == native_uninstall.HELPER_REFUSALS
    tree = ast.parse((ROOT / "macos/uninstall.py").read_text())
    raised = {
        node.exc.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "UninstallRefused"
        and isinstance(node.exc.args[0], ast.Constant)
    }
    assert raised == native_uninstall.HELPER_REFUSALS
    source = (ROOT / "install.sh").read_text()
    block = source[
        source.index("# Uninstall is entirely local:") : source.index(
            'if [ "$UNINSTALL" -eq 1 ]; then'
        )
    ]
    assert set(re.findall(r'die "([^"$]+)"', block)) == native_uninstall.INSTALLER_REFUSALS


def test_product_cli_exposes_fixed_refusal_without_running_a_service() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "macos/uninstall.py"), "--network", "paper"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 1 and result.stdout == b""
    assert native_uninstall.failure_reason(result.stderr.decode()) == (
        "offline owned Testnet LaunchDaemon uninstall only"
    )


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, OSError, KeyError])
def test_unexpected_product_exception_text_is_never_emitted(error_type: type[Exception]) -> None:
    product = module()
    secret = "private-fixture-" + "e" * 64
    assert product.refusal_message(error_type(secret)) == native_uninstall.LEGACY
    assert product.refusal_message(product.UninstallRefused(secret)) == native_uninstall.LEGACY


@pytest.mark.parametrize(
    "text",
    [
        "private-fixture-" + "e" * 64,
        "install.sh: untrusted macOS uninstall path /private/fixture",
        "prefix install.sh: untrusted macOS uninstall path",
        "install.sh: writable macOS uninstall path\ninstall.sh: untrusted macOS uninstall path",
        "Owned macOS Testnet uninstall refused: arbitrary private value; retain state for review",
    ],
)
def test_unrecognized_or_ambiguous_stderr_has_only_unknown_reason(text: str) -> None:
    assert native_uninstall.failure_reason(text) == native_uninstall.UNKNOWN


@pytest.mark.parametrize("kind", ["installer", "helper", "legacy", "unknown", "stdout", "timeout"])
def test_failed_uninstall_artifact_keeps_only_fixed_reason_and_withholds_all_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    secret = "e" * 64
    reason = "foreground release notices differ"
    stderr = (
        "Owned macOS Testnet uninstall refused: " + reason + "; retain state for review\n"
    ).encode()
    if kind == "installer":
        reason = "untrusted macOS uninstall path"
        stderr = ("install.sh: " + reason + "\n").encode()
    elif kind == "legacy":
        reason = native_uninstall.LEGACY
        stderr = reason.encode()
    elif kind in {"unknown", "stdout", "timeout"}:
        reason = native_uninstall.UNKNOWN
        stderr = secret.encode()
    stdout = b"install.sh: writable macOS uninstall path\n" + secret.encode()
    release = Release("v1.0.0", "b" * 40, tmp_path)
    monkeypatch.setattr(Release, "asset", lambda self, name: b"inert installer fixture")

    def child(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["input"] == b"" and kwargs["capture_output"] is True
        assert secret not in repr(argv) and "--uninstall" in argv
        if kind == "timeout":
            raise subprocess.TimeoutExpired(argv, 600, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, 1, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", child)
    log = tmp_path / "step-64.log"
    with pytest.raises(RunError) as failure:
        native_uninstall.execute(release, tmp_path, {}, log)
    sanitize_logs(tmp_path, secret.encode())
    assert log.read_text() == (
        "[sensitive command output withheld]\nfailure category: unknown\n"
        + "uninstall failure reason: "
        + reason
        + "\n"
    )
    assert secret not in str(failure.value) + log.read_text()


def test_successful_uninstall_has_no_failure_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = Release("v1.0.0", "b" * 40, tmp_path)
    monkeypatch.setattr(Release, "asset", lambda self, name: b"inert installer fixture")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, b"private output", b""),
    )
    native_uninstall.execute(release, tmp_path, {}, tmp_path / "step-64.log")
    assert not (tmp_path / "uninstall-failure.json").exists()
    assert (tmp_path / "step-64.log").read_text() == "[sensitive command output withheld]\n"


def modeled_owners(monkeypatch: pytest.MonkeyPatch, mutable: dict[Path, tuple[int, int]]) -> None:
    original = Path.lstat

    def info(path: Path) -> os.stat_result:
        fields = list(original(path))
        # Model a stock root-owned protected ancestor tree without sudo: owner and
        # write bits both, or pytest's basetemp under Linux's 1777 /tmp is refused.
        fields[4] = 0
        fields[0] = int(fields[0]) & ~0o022
        if path in mutable:
            owner, mode = mutable[path]
            fields[4], fields[0] = owner, stat.S_IFMT(int(fields[0])) | mode
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", info)


def signed_fixture_release(
    monkeypatch: pytest.MonkeyPatch, root: Path, executable: bytes
) -> Release:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
            member = tarfile.TarInfo(name)
            body = name.encode()
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    monkeypatch.setattr(Release, "asset", lambda self, name: buffer.getvalue())
    monkeypatch.setattr(Release, "binary", lambda self, target: executable)
    return Release("v1.0.0", "b" * 40, root)


@pytest.mark.parametrize("ancestor", ["bin", "share"])
def test_runner_ancestor_reproduces_helper_refusal_then_measured_cleanup_allows_service_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ancestor: str
) -> None:
    root = tmp_path.resolve()
    product, base, plist, binary, old_notices, release_dir, calls = fixture(root, monkeypatch)
    notices = binary.parent.parent / "share/licenses/zunder-guard"
    notices.parent.mkdir(parents=True)
    old_notices.rename(notices)
    release = signed_fixture_release(monkeypatch, root, binary.read_bytes())
    # Use the actual product trust check, not the fixture's symlink-only stub.
    monkeypatch.setattr(product, "trusted", module().trusted)
    # GitHub's image has runner-owned bin (775) and runner-owned share (775).
    # Use a nonzero synthetic UID, so the reproduction is also valid as root in CI.
    monkeypatch.setattr(os, "getuid", lambda: 501)
    modeled_owners(
        monkeypatch, {binary.parent if ancestor == "bin" else notices.parent.parent: (501, 0o775)}
    )
    with pytest.raises(RuntimeError, match="plain root-owned protected state"):
        product.remove(base, plist, binary, notices)
    assert calls == [] and plist.exists() and release_dir.exists() and binary.exists()
    # Cleanup is tested as the fixture owner: no sudo or service command runs.
    monkeypatch.setattr(os, "getuid", lambda: binary.stat().st_uid)
    mutable = binary.parent if ancestor == "bin" else notices.parent.parent
    modeled_owners(monkeypatch, {mutable: (binary.stat().st_uid, 0o775)})
    assert (
        native_uninstall.prepare_foreground(release, root, {}, binary=binary)
        == "owned-manual-cleanup-runner-ancestors"
    )
    assert not binary.exists() and not notices.exists()
    product.remove(base, plist, binary, notices)
    assert not plist.exists() and not release_dir.exists()
    assert (base / "state-testnet/guard.toml").read_bytes() == b"retained configuration fixture"
    assert (base / "state-testnet/risk.jsonl").read_bytes() == b"retained risk history fixture"
    assert (base / "bindings-testnet/active.json").exists()
    assert [argv[1] for argv in calls] == ["bootout", "print"]


@pytest.mark.parametrize(
    "mutation",
    [
        "stock",
        "world-writable",
        "unexpected-owner",
        "foreign-binary",
        "foreign-notice",
        "symlink",
        "extra-notice",
        "hardlink",
    ],
)
def test_cleanup_preserves_stock_or_refuses_unknown_foreground_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    root = tmp_path.resolve()
    _, _, _, binary, old_notices, _, calls = fixture(root, monkeypatch)
    notices = binary.parent.parent / "share/licenses/zunder-guard"
    notices.parent.mkdir(parents=True)
    old_notices.rename(notices)
    release = signed_fixture_release(monkeypatch, root, binary.read_bytes())
    mutable = {} if mutation == "stock" else {binary.parent: (binary.stat().st_uid, 0o775)}
    if mutation == "world-writable":
        mutable[binary.parent] = (0, 0o777)
    elif mutation == "unexpected-owner":
        mutable[binary.parent] = (99999, 0o775)
    elif mutation == "foreign-binary":
        binary.write_bytes(b"unrelated executable")
    elif mutation == "foreign-notice":
        (notices / "NOTICE").write_bytes(b"unrelated notice")
    elif mutation == "extra-notice":
        (notices / "unknown").write_bytes(b"unrelated file")
    elif mutation == "symlink":
        binary.unlink()
        binary.symlink_to(notices / "NOTICE")
    elif mutation == "hardlink":
        os.link(binary, root / "extra-link")
    modeled_owners(monkeypatch, mutable)
    if mutation == "stock":
        assert (
            native_uninstall.prepare_foreground(release, root, {}, binary=binary)
            == "product-uninstall"
        )
    else:
        # Each mutation must be refused for its own reason, not by an unrelated ancestor.
        refusal = {
            "world-writable": "hosted foreground ancestor is not a protected directory",
            "unexpected-owner": "unexpected hosted foreground ancestor ownership",
            "foreign-binary": "owned foreground binary changed before manual cleanup",
            "foreign-notice": "owned paper notice differs from signed release",
            "symlink": "owned foreground software is not plain installed files",
            "extra-notice": "owned paper notice inventory differs",
            "hardlink": "owned foreground software is not plain installed files",
        }[mutation]
        with pytest.raises(LifecycleError, match="^" + re.escape(refusal) + "$"):
            native_uninstall.prepare_foreground(release, root, {}, binary=binary)
    assert (binary.exists() or binary.is_symlink()) and notices.exists() and calls == []


def test_macos_lifecycle_records_manual_cleanup_before_product_uninstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    release = Release("v1.0.0", "b" * 40, tmp_path)
    monkeypatch.setattr(Release, "asset", lambda self, name: b"inert release manifest")
    controller = NativeTestnet(
        release, release, tmp_path / "work", "fixture-account", "sh", "fresh"
    )
    controller.plist = tmp_path / "daemon.plist"
    controller.plist.touch()
    events: list[str] = []
    monkeypatch.setattr(controller, "install", lambda *args, **kwargs: events.append("install"))
    monkeypatch.setattr(controller, "snapshot", lambda: {"fixture": b"retained"})
    monkeypatch.setattr(controller, "retained", lambda old: events.append("retained"))
    for name in ("ensure_macos_journal", "start", "stop", "crash", "audit", "healthy"):
        monkeypatch.setattr(controller, name, lambda *args, event=name: events.append(event))

    def cleanup(*args: Any) -> str:
        assert events[-1] == "audit"
        events.append("foreground-cleanup")
        return "owned-manual-cleanup-runner-ancestors"

    def uninstall(*args: Any) -> None:
        assert events[-1] == "foreground-cleanup"
        events.append("service-uninstall")
        controller.plist.unlink()

    monkeypatch.setattr(native_uninstall, "prepare_foreground", cleanup)
    monkeypatch.setattr(native_uninstall, "execute", uninstall)
    receipt = controller.execute(b"inert private fixture")
    assert receipt["foreground_cleanup"] == "owned-manual-cleanup-runner-ancestors"
    assert events[-3:] == ["foreground-cleanup", "service-uninstall", "retained"]
    assert (controller.work / "foreground-cleanup.log").read_text() == (
        "foreground cleanup: " + str(receipt["foreground_cleanup"]) + "\n"
    )
