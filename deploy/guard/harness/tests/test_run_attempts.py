"""Latest-attempt selection within one workflow run (decision of 15 Oct 2026)."""

import sys
from pathlib import Path

import pytest

from guard_harness import run_attempts
from guard_harness.attestation import AttestationError
from guard_harness.run_attempts import AttemptError, attempts, latest


def make(root: Path, *names: str) -> Path:
    root.mkdir(exist_ok=True)
    for name in names:
        (root / name).mkdir()
    return root


def test_highest_attempt_at_or_before_the_consumer_wins(tmp_path: Path) -> None:
    root = make(tmp_path / "art", "P2-123-1", "P2-123-2", "P2-123-3")
    selected = latest(root, "P2", "123", "3")
    assert selected.path == root / "P2-123-3" and selected.attempt == "3"
    # A consumer in attempt 2 never sees, and never admits, attempt 3.
    selected = latest(root, "P2", "123", "2")
    assert selected.path == root / "P2-123-2" and selected.attempt == "2"


def test_attempt_numbers_compare_as_integers_not_names(tmp_path: Path) -> None:
    root = make(tmp_path / "art", "I1-123-2", "I1-123-10", "I1-123-9")
    assert latest(root, "I1", "123", "10").attempt == "10"
    assert latest(root, "I1", "123", "9").attempt == "9"


def test_only_later_attempts_is_refused(tmp_path: Path) -> None:
    root = make(tmp_path / "art", "I7-123-3")
    with pytest.raises(AttemptError, match="at or before this attempt"):
        latest(root, "I7", "123", "2")


def test_missing_row_is_refused(tmp_path: Path) -> None:
    root = make(tmp_path / "art", "P1-123-1")
    with pytest.raises(AttemptError, match="no artifact"):
        latest(root, "P2", "123", "1")


@pytest.mark.parametrize("name", ["P2-124-1", "P2-1230-1", "P2-12-1"])
def test_other_run_is_refused_not_skipped(tmp_path: Path, name: str) -> None:
    root = make(tmp_path / "art", "P2-123-1", name)
    with pytest.raises(AttemptError, match="another workflow run"):
        latest(root, "P2", "123", "1")


@pytest.mark.parametrize(
    "name",
    [
        "P2-123-01",
        "P2-123-0",
        "P2-0123-1",
        "P2-123-",
        "P2-123",
        "P2-123-1-extra",
        "P2-123-1x",
        "P2-123--1",
        "P2-1e3-1",
    ],
)
def test_malformed_names_in_the_row_namespace_are_refused(tmp_path: Path, name: str) -> None:
    root = make(tmp_path / "art", "P2-123-1", name)
    with pytest.raises(AttemptError, match="malformed"):
        latest(root, "P2", "123", "1")


def test_other_artifact_families_sharing_the_prefix_are_ignored(tmp_path: Path) -> None:
    root = make(
        tmp_path / "art",
        "T1-123-1",
        "T1-early-failure-123-2",
        "T1-diagnostic-final-123-2",
        "T12-123-5",
        "signing-subjects-123-1",
    )
    assert latest(root, "T1", "123", "2").path == root / "T1-123-1"
    assert set(attempts(root, "T1", "123")) == {1}


def test_superseded_attempts_are_returned_by_attempts_but_never_selected(tmp_path: Path) -> None:
    root = make(tmp_path / "art", "M3-123-1", "M3-123-2")
    assert set(attempts(root, "M3", "123")) == {1, 2}
    assert latest(root, "M3", "123", "2").path.name == "M3-123-2"


def test_selected_artifact_must_be_a_real_directory(tmp_path: Path) -> None:
    root = make(tmp_path / "art")
    (root / "P2-123-1").write_text("not a directory")
    with pytest.raises(AttemptError, match="real directory"):
        latest(root, "P2", "123", "1")
    other = make(tmp_path / "other", "P2-123-1")
    (root / "P2-123-1").unlink()
    (root / "P2-123-1").symlink_to(other / "P2-123-1")
    with pytest.raises(AttemptError, match="real directory"):
        latest(root, "P2", "123", "1")


def test_flat_single_artifact_download_is_refused(tmp_path: Path) -> None:
    # rc.19: download-artifact extracts a lone pattern match flat into the path, so the
    # artifact's name (its attempt) is gone; selection must refuse, not guess.
    root = make(tmp_path / "art")
    (root / "release-manifest.json").write_text("{}")
    with pytest.raises(AttemptError, match="one real directory per artifact"):
        latest(root, "signing-subjects", "123", "1")
    (root / "release-manifest.json").unlink()
    make(root, "signing-subjects-123-1", "staged-state-123-1")
    assert latest(root, "signing-subjects", "123", "1").attempt == "1"


def test_download_directory_must_exist_and_not_be_a_link(tmp_path: Path) -> None:
    with pytest.raises(AttemptError, match="download directory"):
        latest(tmp_path / "missing", "P2", "123", "1")
    real = make(tmp_path / "real", "P2-123-1")
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(AttemptError, match="download directory"):
        latest(tmp_path / "link", "P2", "123", "1")


@pytest.mark.parametrize(
    "prefix,run_id,attempt",
    [
        ("P2", "0123", "1"),
        ("P2", "123", "0"),
        ("P2", "123", "01"),
        ("P2", "", "1"),
        ("P2", "123", "-1"),
        ("", "123", "1"),
        ("P2-", "123", "1"),
        ("P2/../x", "123", "1"),
        ("P*", "123", "1"),
    ],
)
def test_identity_inputs_must_be_canonical(
    tmp_path: Path, prefix: str, run_id: str, attempt: str
) -> None:
    root = make(tmp_path / "art", "P2-123-1")
    with pytest.raises(AttemptError):
        latest(root, prefix, run_id, attempt)


def test_ambiguous_attempt_is_impossible_by_construction_but_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make(tmp_path / "art", "P2-123-1")
    entry = root / "P2-123-1"
    # A case-folding or otherwise aliasing filesystem listing one name twice.
    monkeypatch.setattr(Path, "iterdir", lambda self: iter([entry, entry]))
    with pytest.raises(AttemptError, match="ambiguous"):
        latest(root, "P2", "123", "1")


def test_attempt_error_is_fail_closed_attestation_error() -> None:
    assert issubclass(AttemptError, AttestationError)


def test_cli_moves_exactly_the_selected_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = make(tmp_path / "art", "signing-subjects-123-1", "signing-subjects-123-2")
    (root / "signing-subjects-123-2" / "release-manifest.json").write_text("{}")
    target = tmp_path / "assets"
    argv = ["run_attempts", "--directory", str(root), "--prefix", "signing-subjects"]
    argv += ["--run-id", "123", "--attempt", "2", "--move-to", str(target)]
    monkeypatch.setattr(sys, "argv", argv)
    run_attempts.main()
    assert (target / "release-manifest.json").read_text() == "{}"
    assert (root / "signing-subjects-123-1").is_dir()
    assert "attempt 2 of run 123" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", argv[:-1] + [str(tmp_path / "art" / "signing-subjects-123-1")])
    with pytest.raises(AttemptError, match="already exists"):
        run_attempts.main()
