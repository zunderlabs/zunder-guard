"""Focused privacy and same-run byte handoff tests; no released-runtime success fixtures."""

import hashlib
import json
from pathlib import Path

import pytest
from test_testnet_run import COMMIT, NAME, TAG, assets

from guard_harness.attestation import AttestationError
from guard_harness.promotion_smoke import safe_artifacts, transferred
from guard_harness.testnet_process import ProcessError

ACCOUNT = "0x" + "a" * 40
KEY = "0x" + "b" * 64


def test_portable_handoff_checks_original_manifest_and_every_asset(tmp_path: Path) -> None:
    source = tmp_path / "assets"
    assets(source)
    expected = hashlib.sha256((source / "release-manifest.json").read_bytes()).hexdigest()
    assert transferred(TAG, COMMIT, source, expected).asset(NAME)
    (source / NAME).write_bytes(b"tampered same-run binary")
    with pytest.raises(ProcessError, match="differs"):
        transferred(TAG, COMMIT, source, expected)


def test_portable_handoff_does_not_accept_relabelled_manifest(tmp_path: Path) -> None:
    source = tmp_path / "assets"
    assets(source)
    with pytest.raises(AttestationError, match="manifest differs"):
        transferred(TAG, COMMIT, source, "a" * 64)
    with pytest.raises(ProcessError, match="source differs"):
        transferred(TAG, "a" * 40, source, "a" * 64)


def test_artifacts_allowlist_excludes_home_config_journal_and_keys(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    for name in ("guard.toml", "risk.jsonl", "decisions.jsonl", "secret.log"):
        (home / name).write_text(ACCOUNT + " " + KEY)
    (tmp_path / "unlisted.json").write_text(KEY)
    (tmp_path / "pair.json").write_text(KEY)
    (tmp_path / "runtime.log").write_text("account " + ACCOUNT.upper() + " client " + KEY)
    (tmp_path / "paper-decisions.json").write_text(
        json.dumps(
            {"verdicts": ["veto", "allow", "resize"], "sequences": [1, 2, 3], "mode": "paper"}
        )
    )
    safe_artifacts(tmp_path, account=ACCOUNT)
    exported = tmp_path / "public"
    assert {path.name for path in exported.iterdir()} == {
        "paper-decisions.json",
        tmp_path.name + "-runtime.log",
    }
    for path in exported.iterdir():
        assert ACCOUNT.lower() not in path.read_text().lower()
        assert KEY not in path.read_text()
    assert "[ACCOUNT]" in (exported / (tmp_path.name + "-runtime.log")).read_text()


def test_artifacts_refuse_secret_values_in_allowlisted_receipt_fields(tmp_path: Path) -> None:
    (tmp_path / "paper-decisions.json").write_text(
        json.dumps({"verdicts": [KEY], "sequences": [1], "mode": "paper"})
    )
    safe_artifacts(tmp_path, account=ACCOUNT)
    assert not list((tmp_path / "public").iterdir())


def test_artifact_diagnostics_never_follow_symlinks(tmp_path: Path) -> None:
    secret = tmp_path / "private"
    secret.write_text(KEY)
    (tmp_path / "runtime.log").symlink_to(secret)
    safe_artifacts(tmp_path, account=ACCOUNT)
    assert not list((tmp_path / "public").iterdir())
