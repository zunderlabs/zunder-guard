import hashlib
import importlib.util
import json
import os
import plistlib
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from guard_harness.testnet_run import ROOT


def module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "guard_macos_uninstall", ROOT / "macos/uninstall.py"
    )
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def modeled_ownership(
    mutable: dict[Path, tuple[int, int]] | None = None,
) -> Callable[[int], os.stat_result]:
    """The helper's owner/mode view of an open entry, as on a stock root-owned tree.

    Without sudo the fixture belongs to the test user; every entry is modeled root-owned and
    writable by root only, except the given directories (owner, mode), matched by inode so
    that a renamed or replaced entry keeps or loses the model exactly as the real one would.
    """
    modeled = {}
    for path, value in (mutable or {}).items():
        info = os.lstat(path)
        modeled[(info.st_dev, info.st_ino)] = value

    def ownership(fd: int) -> os.stat_result:
        info = os.fstat(fd)
        owner, mode = modeled.get((info.st_dev, info.st_ino), (0, info.st_mode & ~0o022))
        fields = list(info)
        fields[4], fields[0] = owner, stat.S_IFMT(info.st_mode) | stat.S_IMODE(mode)
        return os.stat_result(fields)

    return ownership


def fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, Path, Path, Path, Path, Path, list[list[str]]]:
    value = module()
    base, plist = tmp_path / "base", tmp_path / "daemon.plist"
    generic, notices = tmp_path / "bin/zunder-guard", tmp_path / "notices"
    body = b"signed executable fixture"
    release = base / "releases" / hashlib.sha256(body).hexdigest()
    release.mkdir(parents=True)
    for name in ("zunder-guard", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
        (release / name).write_bytes(body if name == "zunder-guard" else name.encode())
    bindings = base / "bindings-testnet"
    bindings.mkdir()
    (bindings / "active.json").write_text(json.dumps({"executable": str(release / "zunder-guard")}))
    (base / "state-testnet").mkdir()
    (base / "state-testnet/guard.toml").write_bytes(b"retained configuration fixture")
    (base / "state-testnet/risk.jsonl").write_bytes(b"retained risk history fixture")
    helper = base / "management/uninstall-testnet.py"
    helper.parent.mkdir()
    helper.write_bytes(b"signed uninstall fixture")
    plist.write_bytes(
        plistlib.dumps(
            dict(
                Label="com.zunderlabs.guard.testnet-native",
                ProgramArguments=[
                    str(release / "zunder-guard"),
                    "service",
                    "run",
                    "--binding",
                    str(bindings / "active.json"),
                ],
            )
        )
    )
    generic.parent.mkdir()
    generic.write_bytes(body)
    notices.mkdir()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
        (notices / name).write_bytes(name.encode())
    calls: list[list[str]] = []

    def command(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["capture_output"] is True and kwargs["timeout"] == 30
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 113 if argv[1] == "print" else 0)

    def trusted(path: Path) -> None:
        assert path.exists() or path.is_symlink()
        if path.is_symlink():
            raise RuntimeError("fixture symlink refused")

    monkeypatch.setattr(value, "trusted", trusted)
    monkeypatch.setattr(value, "ownership", modeled_ownership())
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr("subprocess.run", command)
    return value, base, plist, generic, notices, release, calls


def test_actual_offline_removal_preserves_all_documented_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, base, plist, generic, notices, release, calls = fixture(tmp_path, monkeypatch)
    before = {
        str(path.relative_to(base)): path.read_bytes()
        for path in base.rglob("*")
        if path.is_file() and path.parent.name in {"state-testnet", "bindings-testnet"}
    }
    value.remove(base, plist, generic, notices)
    assert (
        not plist.exists()
        and not release.exists()
        and not generic.exists()
        and not notices.exists()
    )
    assert not (base / "management/uninstall-testnet.py").exists()
    assert all((base / name).read_bytes() == body for name, body in before.items())
    assert [command[1] for command in calls] == ["bootout", "print"]


def test_historical_mainnet_reference_keeps_shared_release_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, base, plist, generic, notices, release, _ = fixture(tmp_path, monkeypatch)
    history = base / "bindings"
    history.mkdir()
    (history / "historical.json").write_text(
        json.dumps({"executable": str(release / "zunder-guard")})
    )
    before = {path.name: path.read_bytes() for path in release.iterdir()}
    value.remove(base, plist, generic, notices)
    assert {path.name: path.read_bytes() for path in release.iterdir()} == before
    assert generic.exists() and notices.exists()
    assert (history / "historical.json").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-file",
        "binary",
        "wrong-executable",
        "extra-arg",
        "wrong-binding",
        "wrong-label",
        "symlink",
        "other-binding-link",
        "other-binding-file",
    ],
)
def test_uninstall_refuses_mutation_before_stopping_or_removing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    value, base, plist, generic, notices, release, calls = fixture(tmp_path, monkeypatch)
    if mutation == "unknown-file":
        (release / "unknown").write_bytes(b"unrelated fixture")
    elif mutation == "binary":
        (release / "zunder-guard").write_bytes(b"replaced executable")
    elif mutation == "other-binding-link":
        target = tmp_path / "empty-foreign-bindings"
        target.mkdir()
        (base / "bindings").symlink_to(target, target_is_directory=True)
    elif mutation == "other-binding-file":
        (base / "bindings").write_bytes(b"incomplete inventory")
    elif mutation == "symlink":
        helper = base / "management/uninstall-testnet.py"
        helper.unlink()
        helper.symlink_to(generic)
    else:
        registration = plistlib.loads(plist.read_bytes())
        if mutation == "wrong-executable":
            registration["ProgramArguments"][0] = str(release / "NOTICE")
        elif mutation == "extra-arg":
            registration["ProgramArguments"].append("--unexpected")
        elif mutation == "wrong-binding":
            registration["ProgramArguments"][-1] = str(base / "bindings/active.json")
        else:
            registration["Label"] = "unrelated-fixture-service"
        plist.write_bytes(plistlib.dumps(registration))
    with pytest.raises(RuntimeError):
        value.remove(base, plist, generic, notices)
    assert not calls and plist.exists() and release.exists() and generic.exists()


@pytest.mark.parametrize("status", [0, 5, 112])
def test_uncertain_daemon_absence_never_deletes_release_or_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    value, base, plist, generic, notices, release, _ = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "subprocess.run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, status)
    )
    with pytest.raises(RuntimeError, match="absence"):
        value.remove(base, plist, generic, notices)
    assert plist.exists() and release.exists() and generic.exists()
