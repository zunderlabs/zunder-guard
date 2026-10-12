import json
from pathlib import Path

import pytest

from guard_harness import failure_scan
from guard_harness.testnet_scan import ScanError


@pytest.mark.parametrize("flat", [True, False])
def test_independent_scan_retains_outcome_without_repair(
    flat: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def scan(read: object, account: str) -> dict[str, object]:
        assert account == "explicit-public-account"
        if not flat:
            raise ScanError("account is not flat")
        return {"network": "testnet", "observations": []}

    monkeypatch.setattr(failure_scan, "flat_scan", scan)
    work = tmp_path / "failure.json"
    if flat:
        failure_scan.observe(work, "explicit-public-account")
    else:
        with pytest.raises(ScanError):
            failure_scan.observe(work, "explicit-public-account")
    receipt = json.loads(work.read_text())
    assert receipt["flat"] is flat and receipt["repair_attempted"] is False
    assert "explicit-public-account" not in work.read_text()
    assert work.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("unsafe", ["symlink", "public-parent", "existing-output"])
def test_scan_refuses_unsafe_output_before_any_venue_read(
    unsafe: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    output = parent / "failure.json"
    if unsafe == "symlink":
        output.symlink_to(tmp_path / "untouched")
    elif unsafe == "public-parent":
        parent.chmod(0o755)
    else:
        output.write_text("retained outcome")
    monkeypatch.setattr(failure_scan, "flat_scan", lambda *a: pytest.fail("unsafe output"))
    with pytest.raises((ValueError, ScanError)):
        failure_scan.observe(output, "explicit-public-account")
    assert not (tmp_path / "untouched").exists()
