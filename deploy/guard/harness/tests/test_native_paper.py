from pathlib import Path

import pytest

from guard_harness.native_paper import LifecycleError, retained, verify_retained


def paper_state(home: Path) -> dict[str, bytes]:
    state = {
        "guard.toml": b"paper configuration and pairing fixture\n",
        "risk-paper.jsonl": b"paper risk prefix\n",
        "decisions-paper.jsonl": b"paper decisions prefix\n",
    }
    for name, value in state.items():
        (home / name).write_bytes(value)
    return state


def test_paper_lifecycle_retains_its_journals_without_using_testnet_history(
    tmp_path: Path,
) -> None:
    expected = paper_state(tmp_path)
    for name in ("risk.jsonl", "decisions.jsonl"):
        (tmp_path / name).write_bytes(b"separate testnet history\n")
    before = retained(tmp_path)
    assert before == expected
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        with (tmp_path / name).open("ab") as output:
            output.write(b"next paper lifecycle record\n")
    verify_retained(before, tmp_path)
    for name in ("risk.jsonl", "decisions.jsonl"):
        assert (tmp_path / name).read_bytes() == b"separate testnet history\n"


def test_testnet_journals_cannot_substitute_for_missing_paper_journals(
    tmp_path: Path,
) -> None:
    for name in ("guard.toml", "risk.jsonl", "decisions.jsonl"):
        (tmp_path / name).write_bytes(b"testnet fixture\n")
    with pytest.raises(LifecycleError, match="configuration or journal missing"):
        retained(tmp_path)


def test_paper_append_consumes_zero_reserve_without_erasing_history(tmp_path: Path) -> None:
    expected = paper_state(tmp_path)
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        (tmp_path / name).write_bytes(expected[name] + b"\x00" * 4096)
    before = retained(tmp_path)
    assert before == expected
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        (tmp_path / name).write_bytes(
            expected[name] + b"durable appended record\n" + b"\x00" * 4000
        )
    verify_retained(before, tmp_path)
    (tmp_path / "decisions-paper.jsonl").write_bytes(
        b"replaced populated prefix\n" + b"\x00" * 4096
    )
    with pytest.raises(LifecycleError, match="journal history changed"):
        verify_retained(before, tmp_path)


@pytest.mark.parametrize("name", ["guard.toml", "risk-paper.jsonl", "decisions-paper.jsonl"])
def test_paper_lifecycle_rejects_replaced_config_or_journal_prefix(
    tmp_path: Path, name: str
) -> None:
    before = paper_state(tmp_path)
    (tmp_path / name).write_bytes(b"replacement\n")
    with pytest.raises(LifecycleError, match="changed across lifecycle"):
        verify_retained(before, tmp_path)
