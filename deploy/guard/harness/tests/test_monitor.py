import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness import monitor, promotion
from guard_harness.attestation import AttestationError
from guard_harness.native_release import Release
from guard_harness.publication import Publication


def test_admission_binds_expected_pair_and_retains_only_public_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def admit(work: Path) -> tuple[Release, Publication]:
        assert not work.exists()
        work.mkdir()
        return Release("v1.0.0", "a" * 40, work / "assets"), Publication(b"", "b" * 64)

    monkeypatch.setattr(promotion, "admitted_canonical", admit)
    work = tmp_path / "new"
    values = monitor.admitted(work, tag="v1.0.0", commit="a" * 40)
    assert values == json.loads((work / "receipt.json").read_bytes())
    assert values == {
        "tag": "v1.0.0",
        "commit": "a" * 40,
        "state_sha256": "b" * 64,
        "complete_gate_authenticated": True,
        "canonical_readback": True,
    }


def test_mismatched_promoted_pair_never_writes_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        promotion,
        "admitted_canonical",
        lambda work: (Release("v1.0.0", "a" * 40, work), Publication(b"", "b" * 64)),
    )
    with pytest.raises(AttestationError, match="differs"):
        monitor.admitted(tmp_path / "new", tag="v1.0.0", commit="c" * 40)
    assert not (tmp_path / "new/receipt.json").exists()


def test_upgrade_predecessor_authenticated_before_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def admit(work: Path) -> tuple[Release, Publication]:
        work.mkdir()
        return Release("v1.0.0", "a" * 40, work), Publication(b"", "b" * 64)

    monkeypatch.setattr(promotion, "admitted_canonical", admit)
    monkeypatch.setattr(monitor, "select", lambda tag, work: ("v1.0.0-rc.4", "c" * 40))

    def refuse(tag: str, commit: str, work: Path) -> Release:
        raise AttestationError("invalid predecessor C2")

    monkeypatch.setattr(monitor, "authenticate", refuse)
    with pytest.raises(AttestationError, match="invalid predecessor"):
        monitor.admitted(tmp_path / "new", previous=True)
    assert not (tmp_path / "new/receipt.json").exists()


class Response:
    status = 202

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def read(self, size: int) -> bytes:
        assert size == 4097
        return b'{"ok":true,"sent":true}'


def test_alert_has_one_fixed_endpoint_and_no_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    class Opener:
        def open(self, request: Any, *, timeout: int) -> Response:
            calls.append(request)
            assert request.full_url == monitor.ALERT_URL
            assert request.method == "POST" and timeout == 30
            assert request.get_header("Authorization") == "Bearer synthetic"
            assert json.loads(request.data) == {
                "check": "P9.monitor",
                "run_url": "https://github.com/zunderlabs/zunder-guard/actions/runs/123",
            }
            return Response()

    monkeypatch.setattr(
        "guard_harness.monitor.urllib.request.build_opener", lambda handler: Opener()
    )
    monitor.alert(
        token="synthetic",
        check="P9.monitor",
        run_url="https://github.com/zunderlabs/zunder-guard/actions/runs/123",
    )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "token,check,url",
    [
        ("", "P9", ""),
        ("bad token", "P9", ""),
        ("synthetic", "bad/check", "https://github.com/zunderlabs/zunder-guard/actions/runs/1"),
        ("synthetic", "P9", "https://example.com/actions/runs/1"),
    ],
)
def test_alert_invalid_frame_refused_before_http(token: str, check: str, url: str) -> None:
    with pytest.raises(AttestationError, match="frame refused"):
        monitor.alert(token=token, check=check, run_url=url)
