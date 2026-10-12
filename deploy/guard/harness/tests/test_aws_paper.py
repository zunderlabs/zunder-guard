"""AWS reboot snapshots preserve paper history, never the separate testnet journals."""

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from guard_harness import aws_paper


@pytest.mark.parametrize("reserve", [0, 4096])
def test_reboot_snapshot_and_retention_use_actual_paper_journals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reserve: int
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    paper = {
        "guard.toml": b"paper configuration\n\x00",
        "risk-paper.jsonl": b"paper risk history\n\x00retained interior byte\n",
        "decisions-paper.jsonl": b"paper decisions history\n",
    }
    for name, body in paper.items():
        (home / name).write_bytes(body + (b"\x00" * reserve if name.endswith(".jsonl") else b""))
    for name in ("risk.jsonl", "decisions.jsonl"):
        (home / name).write_bytes(b"unrelated testnet history\n")
    boot = tmp_path / "boot-id"
    boot.write_text("boot-fixture\n")
    monkeypatch.setattr(aws_paper, "HOME", home)
    monkeypatch.setattr(aws_paper, "BASE", tmp_path)
    monkeypatch.setattr(
        aws_paper, "Path", lambda name: boot if name.startswith("/proc/") else Path(name)
    )
    monkeypatch.setattr(aws_paper, "image", lambda digest: None)
    monkeypatch.setattr(aws_paper, "health", lambda version: None)

    def command(words: list[str], name: str) -> str:
        if name == "pair":
            return json.dumps({"client_address": "0x" + "a" * 40, "client_key": "0x" + "b" * 64})
        return "10" if name == "before-crash-pid" else "11"

    monkeypatch.setattr(aws_paper, "command", command)
    monkeypatch.setattr(
        aws_paper,
        "round_trip",
        lambda *args: [SimpleNamespace(verdict=value) for value in ("veto", "allow", "resize")],
    )
    assert aws_paper.before("1.0.0", "a" * 64, "0.9.0", "b" * 64)["stage"] == "before-reboot"
    state_path = tmp_path / "private-state.json"
    state = json.loads(state_path.read_bytes())
    assert {name: base64.b64decode(body) for name, body in state["files"].items()} == paper
    assert state_path.stat().st_mode & 0o077 == 0
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        # A real journal appends over its preallocated zeros after reboot.
        (home / name).write_bytes(paper[name] + b"next paper record\n" + b"\x00" * reserve)
    aws_paper.preserve(state)
    (home / "guard.toml").write_bytes(paper["guard.toml"].rstrip(b"\x00"))
    with pytest.raises(RuntimeError, match="journal history"):
        aws_paper.preserve(state)
    (home / "guard.toml").write_bytes(paper["guard.toml"])
    (home / "risk-paper.jsonl").write_bytes(b"replacement paper history\n")
    with pytest.raises(RuntimeError, match="journal history"):
        aws_paper.preserve(state)
