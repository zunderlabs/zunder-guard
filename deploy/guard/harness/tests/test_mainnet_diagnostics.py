import json
from pathlib import Path

import pytest

from guard_harness.mainnet_diagnostics import PREFIX, REASONS, guest_failure


@pytest.mark.parametrize("reason", sorted(REASONS))
def test_retains_only_fixed_failure_reason(tmp_path: Path, reason: str) -> None:
    (tmp_path / "host-18.log").write_text("private fixture output\n" + PREFIX + reason + "\n")
    target = tmp_path / "failure.json"
    guest_failure(tmp_path, target)
    assert json.loads(target.read_bytes()) == dict(
        schema=1, diagnostic=True, gate_eligible=False, result="failed", reason=reason
    )
    assert "private fixture" not in target.read_text()


@pytest.mark.parametrize("kind", ["unknown", "oversize", "symlink", "ambiguous", "too-many"])
def test_untrusted_output_is_never_retained(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "host-18.log"
    reason = sorted(REASONS)[0]
    source.write_text(PREFIX + reason + "\n")
    if kind == "unknown":
        source.write_text(PREFIX + "inert private fixture\n")
    elif kind == "oversize":
        source.write_text(source.read_text() + "inert private fixture\n" * 65536)
    elif kind == "symlink":
        moved = tmp_path / "private-fixture"
        source.rename(moved)
        try:
            source.symlink_to(moved)
        except OSError:
            pytest.skip("symlink creation unavailable")
    elif kind == "ambiguous":
        (tmp_path / "host-19.log").write_text(PREFIX + sorted(REASONS)[1] + "\n")
    else:
        for i in range(65):
            (tmp_path / f"host-{i}.log").write_text("inert private fixture\n")
    target = tmp_path / "failure.json"
    guest_failure(tmp_path, target)
    assert json.loads(target.read_bytes())["reason"] == "unclassified guest failure"
    assert "private fixture" not in target.read_text()
