import os
import stat
from pathlib import Path
from typing import Any

import pytest

from guard_harness import native_mainnet
from guard_harness.mainnet_terminal import TerminalError
from guard_harness.native_release import Release


def test_nested_refusal_workspace_is_private_before_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path.resolve() / "mainnet" / "M1"

    def loader(release: Release, **kwargs: Any) -> Path:
        assert kwargs["output"].parent == work
        assert work.is_dir()
        if os.name != "nt":
            assert stat.S_IMODE(work.stat().st_mode) == 0o700
            assert stat.S_IMODE(work.parent.stat().st_mode) == 0o700
        raise RuntimeError("inert loader boundary")

    monkeypatch.setattr(native_mainnet, "staged_loader", loader)
    with pytest.raises(RuntimeError, match="inert loader boundary"):
        native_mainnet.exercise(
            Release("v1.0.0", "a" * 40, tmp_path),
            account="fixture-account",
            work=work,
            shell="fixture-shell",
        )
    assert list(work.iterdir()) == []


@pytest.mark.parametrize("kind", ["existing", "workspace-link", "parent-link", "relative"])
def test_refusal_workspace_rejects_reuse_and_symlinks_before_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    base = tmp_path.resolve()
    work = base / "M1"
    if kind == "existing":
        work.mkdir()
    elif kind in {"workspace-link", "parent-link"}:
        target = base / "target"
        target.mkdir()
        try:
            work.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlink creation unavailable")
        if kind == "parent-link":
            work /= "M1"
    else:
        work = Path("relative-M1")

    def loader(*args: Any, **kwargs: Any) -> Path:
        raise AssertionError("loader must not run for unsafe workspace")

    monkeypatch.setattr(native_mainnet, "staged_loader", loader)
    with pytest.raises(TerminalError, match="workspace"):
        native_mainnet.exercise(
            Release("v1.0.0", "a" * 40, base),
            account="fixture-account",
            work=work,
            shell="fixture-shell",
        )
    assert not (base / "target" / "M1").exists()
