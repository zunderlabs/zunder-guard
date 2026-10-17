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
from types import ModuleType
from typing import Any

import pytest
from test_macos_uninstall import fixture, modeled_ownership, module

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


def runner_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, Path, Path, Path, Path, Path, list[list[str]]]:
    root = tmp_path.resolve()
    product, base, plist, binary, old_notices, release_dir, calls = fixture(root, monkeypatch)
    notices = binary.parent.parent / "share/licenses/zunder-guard"
    notices.parent.mkdir(parents=True)
    old_notices.rename(notices)
    # Use the actual product trust check, not the fixture's symlink-only stub.
    monkeypatch.setattr(product, "trusted", module().trusted)
    return product, base, plist, binary, notices, release_dir, calls


@pytest.mark.parametrize("ancestor", ["bin", "share", "both"])
def test_runner_or_homebrew_ancestor_product_removes_the_verified_copy_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ancestor: str
) -> None:
    product, base, plist, binary, notices, release_dir, calls = runner_layout(tmp_path, monkeypatch)
    share = notices.parent.parent
    # The fixture's stand-ins for /usr/local/bin and /usr/local/share.
    monkeypatch.setattr(product, "MUTABLE_FOREGROUND", frozenset({binary.parent, share}))
    # GitHub's image has runner-owned bin and share (775); Homebrew on Intel Macs owns them.
    mutable = {"bin": [binary.parent], "share": [share], "both": [binary.parent, share]}
    modeled_owners(monkeypatch, {})
    monkeypatch.setattr(
        product,
        "ownership",
        modeled_ownership({path: (501, 0o775) for path in mutable[ancestor]}),
    )
    product.remove(base, plist, binary, notices)
    assert not binary.exists() and not notices.exists() and notices.parent.is_dir()
    assert not plist.exists() and not release_dir.exists()
    assert (base / "state-testnet/guard.toml").read_bytes() == b"retained configuration fixture"
    assert (base / "state-testnet/risk.jsonl").read_bytes() == b"retained risk history fixture"
    assert (base / "bindings-testnet/active.json").exists()
    assert [argv[1] for argv in calls] == ["bootout", "print"]


@pytest.mark.parametrize("ancestor", ["bin", "share", "licenses", "parent", "production"])
def test_other_mutable_or_world_writable_ancestor_still_refuses_before_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ancestor: str
) -> None:
    product, base, plist, binary, notices, release_dir, calls = runner_layout(tmp_path, monkeypatch)
    share = notices.parent.parent
    if ancestor != "production":  # else: only the real /usr/local/bin and share are mutable
        monkeypatch.setattr(product, "MUTABLE_FOREGROUND", frozenset({binary.parent, share}))
    modeled_owners(monkeypatch, {})
    # bin and share may be writable by others, never by everyone; licenses/ and the
    # stand-in for /usr/local stay root-owned and writable by root only.
    model = {
        "bin": {binary.parent: (0, 0o777)},
        "share": {share: (501, 0o777)},
        "licenses": {notices.parent: (501, 0o755)},
        "parent": {binary.parent.parent: (501, 0o755)},
        "production": {binary.parent: (501, 0o775)},
    }[ancestor]
    monkeypatch.setattr(product, "ownership", modeled_ownership(model))
    with pytest.raises(RuntimeError, match="plain root-owned protected state"):
        product.remove(base, plist, binary, notices)
    assert calls == [] and plist.exists() and release_dir.exists()
    assert binary.exists() and notices.exists()


@pytest.mark.parametrize("ancestor", ["bin", "share"])
def test_older_helper_route_measured_cleanup_then_service_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ancestor: str
) -> None:
    # The harness still cleans up first for the 1.0 and 1.0.1 helpers, which refuse here.
    product, base, plist, binary, notices, release_dir, calls = runner_layout(tmp_path, monkeypatch)
    release = signed_fixture_release(monkeypatch, tmp_path.resolve(), binary.read_bytes())
    # Cleanup is tested as the fixture owner: no sudo or service command runs.
    monkeypatch.setattr(os, "getuid", lambda: binary.stat().st_uid)
    mutable = binary.parent if ancestor == "bin" else notices.parent.parent
    modeled_owners(monkeypatch, {mutable: (binary.stat().st_uid, 0o775)})
    assert (
        native_uninstall.prepare_foreground(release, tmp_path.resolve(), {}, binary=binary)
        == "owned-manual-cleanup-runner-ancestors"
    )
    assert not binary.exists() and not notices.exists()
    product.remove(base, plist, binary, notices)
    assert not plist.exists() and not release_dir.exists()
    assert (base / "bindings-testnet/active.json").exists()
    assert [argv[1] for argv in calls] == ["bootout", "print"]


def homebrew_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, Path, Path, Path, Path, Path, list[list[str]]]:
    """Intel Mac with Homebrew: bin and share belong to the admin user (501, 0775)."""
    layout = runner_layout(tmp_path, monkeypatch)
    product, binary, notices = layout[0], layout[3], layout[4]
    share = notices.parent.parent
    monkeypatch.setattr(product, "MUTABLE_FOREGROUND", frozenset({binary.parent, share}))
    modeled_owners(monkeypatch, {})
    owners = {binary.parent: (501, 0o775), share: (501, 0o775)}
    monkeypatch.setattr(product, "ownership", modeled_ownership(owners))
    return layout


@pytest.mark.parametrize(
    "mutation,refusal",
    [
        ("symlink", "foreground executable is not one regular file"),
        ("hardlink", "foreground executable is not one regular file"),
        ("user-owned", "foreground executable is not one regular file"),
        ("group-writable", "foreground executable is not one regular file"),
        ("fifo", "foreground executable is not one regular file"),
        ("directory", "foreground executable is not one regular file"),
        ("foreign-binary", "foreground executable belongs to another installation"),
        ("extra-notice", "foreground release notices differ"),
        ("missing-notices", "foreground release notices differ"),
        ("foreign-notice", "foreground release notice identity differs"),
        ("notice-symlink", "foreground notice is not a regular file"),
        ("licenses-symlink", "uninstall path is not plain root-owned protected state"),
    ],
)
def test_writable_ancestor_still_refuses_unknown_foreground_state_before_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, refusal: str
) -> None:
    product, base, plist, binary, notices, release_dir, calls = homebrew_layout(
        tmp_path, monkeypatch
    )
    victim = tmp_path.resolve() / "victim"
    victim.mkdir()
    (victim / "NOTICE").write_bytes(b"NOTICE")
    if mutation == "symlink":
        binary.rename(victim / "zunder-guard")
        binary.symlink_to(victim / "zunder-guard")
    elif mutation == "hardlink":
        os.link(binary, victim / "extra-link")
    elif mutation in {"user-owned", "group-writable"}:
        owner, mode = (501, 0o755) if mutation == "user-owned" else (0, 0o775)
        model = {binary.parent: (501, 0o775), notices.parent.parent: (501, 0o775)}
        model[binary] = (owner, mode)
        monkeypatch.setattr(product, "ownership", modeled_ownership(model))
    elif mutation == "fifo":
        binary.unlink()
        os.mkfifo(binary)
    elif mutation == "directory":
        binary.unlink()
        binary.mkdir()
    elif mutation == "foreign-binary":
        binary.write_bytes(b"unrelated executable")
    elif mutation == "extra-notice":
        (notices / "unknown").write_bytes(b"unrelated file")
    elif mutation == "missing-notices":
        for path in notices.iterdir():
            path.unlink()
        notices.rmdir()
    elif mutation == "foreign-notice":
        (notices / "NOTICE").write_bytes(b"unrelated notice")
    elif mutation == "notice-symlink":
        (notices / "NOTICE").unlink()
        (notices / "NOTICE").symlink_to(victim / "NOTICE")
    else:
        licenses = notices.parent
        licenses.rename(victim / "licenses")
        licenses.symlink_to(victim / "licenses", target_is_directory=True)
    with pytest.raises(RuntimeError, match="^" + re.escape(refusal) + "$"):
        product.remove(base, plist, binary, notices)
    assert calls == [] and plist.exists() and release_dir.exists()
    assert binary.exists() or binary.is_symlink()
    assert (victim / "NOTICE").read_bytes() == b"NOTICE"


@pytest.mark.parametrize("swap", ["replaced", "symlink", "hardlink", "removed"])
def test_foreground_changed_after_verification_is_refused_and_can_be_run_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str
) -> None:
    product, base, plist, binary, notices, release_dir, calls = homebrew_layout(
        tmp_path, monkeypatch
    )
    victim = tmp_path.resolve() / "victim"
    victim.mkdir()
    (victim / "protected").write_bytes(b"protected fixture")
    unload = subprocess.run

    def race(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        # The owner of bin changes the verified name while the daemon is being unloaded.
        if argv[1] == "bootout":
            moved = binary.parent / "moved-away"
            if swap == "replaced":
                binary.rename(moved)
                binary.write_bytes(moved.read_bytes())
            elif swap == "symlink":
                binary.rename(moved)
                binary.symlink_to(victim / "protected")
            elif swap == "hardlink":
                os.link(binary, moved)
            else:
                binary.rename(moved)
        result: subprocess.CompletedProcess[bytes] = unload(argv, **kwargs)
        return result

    monkeypatch.setattr("subprocess.run", race)
    with pytest.raises(RuntimeError, match="^foreground copy changed during removal$"):
        product.remove(base, plist, binary, notices)
    assert [argv[1] for argv in calls] == ["bootout", "print"]
    # Nothing that is not ours was removed or followed, and the service files are intact.
    assert (victim / "protected").read_bytes() == b"protected fixture"
    assert (binary.parent / "moved-away").exists()
    assert plist.exists() and release_dir.exists()
    assert (base / "management/uninstall-testnet.py").exists()
    if swap == "hardlink":
        # Our name was removed; the other name is the bin owner's to delete.
        assert not binary.exists()
    elif swap != "removed":
        assert binary.exists() or binary.is_symlink()
    # Run again once the bin directory is back to what the uninstaller can judge.
    if binary.exists() or binary.is_symlink():
        binary.unlink()
    (binary.parent / "moved-away").unlink()
    monkeypatch.setattr("subprocess.run", unload)
    product.remove(base, plist, binary, notices)
    assert not plist.exists() and not release_dir.exists()
    assert notices.exists()  # no foreground copy, so its notices are not judged or removed


def test_licences_directory_swapped_after_verification_removes_only_the_verified_notices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product, base, plist, binary, notices, release_dir, calls = homebrew_layout(
        tmp_path, monkeypatch
    )
    # A protected directory holding byte-identical notices, as a swap target.
    victim = tmp_path.resolve() / "victim"
    (victim / "zunder-guard").mkdir(parents=True)
    for path in notices.iterdir():
        (victim / "zunder-guard" / path.name).write_bytes(path.read_bytes())
    unload = subprocess.run
    licenses = notices.parent

    def race(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[1] == "bootout":  # the owner of share swaps licenses/ for a link
            licenses.rename(licenses.parent / "licenses-moved")
            licenses.symlink_to(victim, target_is_directory=True)
        result: subprocess.CompletedProcess[bytes] = unload(argv, **kwargs)
        return result

    monkeypatch.setattr("subprocess.run", race)
    product.remove(base, plist, binary, notices)
    # The verified directory was emptied and removed where it now is; the link was not followed.
    assert sorted(path.name for path in (victim / "zunder-guard").iterdir()) == [
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_LICENSES.md",
    ]
    assert list((licenses.parent / "licenses-moved").iterdir()) == []
    assert not binary.exists() and not plist.exists() and not release_dir.exists()


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


@pytest.mark.parametrize(
    "cleanup_result,left",
    [
        ("owned-manual-cleanup-runner-ancestors", False),
        ("product-uninstall", False),
        ("product-uninstall", True),
    ],
)
def test_macos_lifecycle_records_manual_cleanup_before_product_uninstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup_result: str, left: bool
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
        return cleanup_result

    def uninstall(*args: Any) -> None:
        assert events[-1] == "foreground-cleanup"
        events.append("service-uninstall")
        controller.plist.unlink()

    def removed() -> None:
        assert events[-1] == "service-uninstall"
        events.append("foreground-removed-checked")
        if left:
            raise LifecycleError("product uninstall left the foreground copy or its notices")

    monkeypatch.setattr(native_uninstall, "prepare_foreground", cleanup)
    monkeypatch.setattr(native_uninstall, "execute", uninstall)
    monkeypatch.setattr(native_uninstall, "assert_foreground_removed", removed)
    if left:
        # A product uninstall that leaves the copy fails the journey before any receipt.
        with pytest.raises(LifecycleError, match="left the foreground copy"):
            controller.execute(b"inert private fixture")
        return
    receipt = controller.execute(b"inert private fixture")
    assert receipt["foreground_cleanup"] == cleanup_result
    checked = ["foreground-removed-checked"] if cleanup_result == "product-uninstall" else []
    assert events[-3 - len(checked) :] == [
        "foreground-cleanup",
        "service-uninstall",
        *checked,
        "retained",
    ]
    assert (controller.work / "foreground-cleanup.log").read_text() == (
        "foreground cleanup: " + str(receipt["foreground_cleanup"]) + "\n"
    )


def helper_release(monkeypatch: pytest.MonkeyPatch, root: Path, helper: bytes) -> Release:
    release = signed_fixture_release(monkeypatch, root, b"signed executable fixture")
    archive = Release.asset

    def asset(self: Release, name: str) -> bytes:
        return helper if name == "uninstall-macos-testnet.py" else archive(self, name)

    monkeypatch.setattr(Release, "asset", asset)
    return release


@pytest.mark.parametrize(
    "helper,capable",
    [
        ((ROOT / "macos/uninstall.py").read_bytes(), True),
        (b'FIXED_REFUSALS = frozenset({"Testnet uninstall requires root"})\n', False),
        (b'# CAPABILITIES = frozenset({"writable-usr-local-foreground"})\n', False),
        (b'CAPABILITIES = frozenset({"another-capability"})\n', False),
    ],
)
def test_capability_is_read_from_the_signed_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, helper: bytes, capable: bool
) -> None:
    release = helper_release(monkeypatch, tmp_path, helper)
    assert native_uninstall.product_removes_foreground(release) is capable
    if capable:
        assert "writable-usr-local-foreground" in module().CAPABILITIES


@pytest.mark.parametrize("ancestor", ["bin", "share"])
def test_capable_helper_leaves_runner_ancestor_copy_to_the_product(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ancestor: str
) -> None:
    root = tmp_path.resolve()
    _, _, _, binary, old_notices, _, calls = fixture(root, monkeypatch)
    notices = binary.parent.parent / "share/licenses/zunder-guard"
    notices.parent.mkdir(parents=True)
    old_notices.rename(notices)
    release = helper_release(monkeypatch, root, (ROOT / "macos/uninstall.py").read_bytes())
    monkeypatch.setattr(os, "getuid", lambda: binary.stat().st_uid)
    mutable = binary.parent if ancestor == "bin" else notices.parent.parent
    modeled_owners(monkeypatch, {mutable: (binary.stat().st_uid, 0o775)})

    def manual(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("manual cleanup must not run for a capable helper")

    monkeypatch.setattr(native_uninstall, "remove_macos_paper", manual)
    assert (
        native_uninstall.prepare_foreground(release, root, {}, binary=binary) == "product-uninstall"
    )
    assert binary.exists() and notices.exists() and calls == []
    # Unexpected ancestors still stop the journey, capable helper or not.
    modeled_owners(monkeypatch, {binary.parent.parent: (binary.stat().st_uid, 0o775)})
    with pytest.raises(LifecycleError, match="unexpected hosted foreground ancestor ownership"):
        native_uninstall.prepare_foreground(release, root, {}, binary=binary)


@pytest.mark.parametrize("left", ["none", "binary", "notices", "binary-link"])
def test_after_product_uninstall_neither_copy_nor_notices_may_remain(
    tmp_path: Path, left: str
) -> None:
    binary = tmp_path / "bin/zunder-guard"
    notices = tmp_path / "share/licenses/zunder-guard"
    binary.parent.mkdir()
    notices.parent.mkdir(parents=True)
    if left == "binary":
        binary.write_bytes(b"left behind")
    elif left == "notices":
        notices.mkdir()
    elif left == "binary-link":
        binary.symlink_to(tmp_path / "missing")
    if left == "none":
        native_uninstall.assert_foreground_removed(binary)
    else:
        with pytest.raises(LifecycleError, match="left the foreground copy or its notices"):
            native_uninstall.assert_foreground_removed(binary)
