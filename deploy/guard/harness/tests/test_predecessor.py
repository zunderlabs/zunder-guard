import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness import predecessor


def test_published_predecessor_ignores_drafts_and_newer_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        dict(tag_name="v1.0.0-rc.3", draft=False, published_at="2026-10-11T17:00:00Z"),
        dict(tag_name="v1.0.0-rc.2", draft=False, published_at="2026-10-11T16:00:00Z"),
        dict(tag_name="v1.0.0-rc.4", draft=False, published_at="2026-10-11T18:00:00Z"),
        dict(tag_name="v1.0.0-rc.1", draft=True, published_at="2026-10-11T16:59:00Z"),
    ]
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        calls.append(argv)
        output = rows if len(calls) == 1 else {"sha": "a" * 40}
        return type("Reply", (), {"output": json.dumps(output)})()

    monkeypatch.setattr(predecessor, "run", run)
    assert predecessor.select("v1.0.0-rc.3", tmp_path) == ("v1.0.0-rc.2", "a" * 40)
    assert calls[1][-1].endswith("/commits/v1.0.0-rc.2")


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [dict(tag_name="v1.0.0", draft=True)],
        [dict(tag_name="v1.0.0", draft=False, published_at="2026-10-11T17:00:00Z")],
    ],
)
def test_unknown_or_first_publication_cannot_fake_an_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]
) -> None:
    monkeypatch.setattr(
        predecessor, "run", lambda *a, **k: type("Reply", (), {"output": json.dumps(rows)})()
    )
    with pytest.raises(ValueError):
        predecessor.select("v1.0.0", tmp_path)
