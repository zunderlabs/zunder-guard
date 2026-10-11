import json
import sys
from pathlib import Path

import pytest

from guard_harness.mainnet_evidence import MatrixError
from guard_harness.mainnet_refusals import execute
from guard_harness.native_release import Release


def test_actual_process_failure_is_not_false_refusal_credit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Harmless actual executable with invalid CLI arguments; no key, service or network.
    binary = Path(sys.executable).resolve()
    monkeypatch.setattr(Release, "binary", lambda self, target: binary.read_bytes())
    monkeypatch.setattr(Release, "asset", lambda self, name: b"signed manifest fixture")
    account = "0x" + "a" * 40
    with pytest.raises(MatrixError, match="literal"):
        execute(
            Release("v1.0.0", "b" * 40, tmp_path),
            binary,
            account=account,
            rules="zr1_fixture",
            work=tmp_path / "observed",
            harness_commit="b" * 40,
            diagnostic=False,
        )
    path = next((tmp_path / "observed").glob("*.json"))
    value = json.loads(path.read_bytes())
    assert value["result"] == "failed" and value["exchange_requests"] == 0
    assert "passed" not in value.values()
    assert account not in path.with_suffix(".log").read_text()


@pytest.mark.parametrize(
    "account,rules,source",
    [
        ("private-looking-invalid", "zr1_fixture", "a" * 40),
        ("0x" + "a" * 40, "invalid-rules", "a" * 40),
        ("0x" + "a" * 40, "zr1_fixture", "short-source"),
    ],
)
def test_bad_inputs_fail_before_executing(
    tmp_path: Path, account: str, rules: str, source: str
) -> None:
    with pytest.raises(MatrixError):
        execute(
            Release("v1.0.0", "a" * 40, tmp_path),
            tmp_path / "absent-binary",
            account=account,
            rules=rules,
            work=tmp_path / "absent-home",
            harness_commit=source,
            diagnostic=False,
        )
    assert not (tmp_path / "absent-home").exists()
