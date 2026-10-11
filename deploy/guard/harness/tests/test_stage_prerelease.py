"""Execute the production shell boundary with fake Git/GitHub, never a live release."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from guard_harness.testnet_run import ROOT


@pytest.mark.parametrize(
    ("case", "success", "writes"),
    [
        ("ok", True, 1),
        ("rc", True, 1),
        ("wrong-repo", False, 0),
        ("wrong-ref", False, 0),
        ("wrong-head", False, 0),
        ("wrong-tag", False, 0),
        ("already-public", False, 0),
        ("read-failure", False, 0),
        ("write-failure", False, 1),
        ("bad-readback", False, 1),
    ],
)
def test_staging_is_source_bound_and_never_latest(
    tmp_path: Path, case: str, success: bool, writes: int
) -> None:
    fake = tmp_path / "bin"
    fake.mkdir()
    command = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
case = os.environ['CASE']
a = sys.argv[1:]
if Path(sys.argv[0]).name == 'git':
    print(('b' if (case == 'wrong-head' and a[1] == 'HEAD') or
           (case == 'wrong-tag' and a[1] != 'HEAD') else 'a') * 40)
else:
    log = Path(os.environ['CALLS'])
    with log.open('a') as stream:
        stream.write(json.dumps(a) + '\\n')
    if a[1] == 'edit':
        if case == 'write-failure': sys.exit(1)
    else:
        if case == 'read-failure': sys.exit(1)
        edited = 'edit' in log.read_text()
        print(json.dumps({'tagName': os.environ['TAG'],
                          'isDraft': not edited and case != 'already-public',
                          'isPrerelease': edited and case != 'bad-readback'}))
"""
    for name in ("git", "gh"):
        path = fake / name
        path.write_text(command)
        path.chmod(0o700)
    tag = "v1.0.0-rc.1" if case == "rc" else "v1.0.0"
    calls = tmp_path / "calls"
    env = {
        **os.environ,
        "PATH": f"{fake}:{os.environ['PATH']}",
        "GITHUB_REPOSITORY": "wrong/repo" if case == "wrong-repo" else "zunderlabs/zunder-guard",
        "GITHUB_REF": "refs/heads/main" if case == "wrong-ref" else f"refs/tags/{tag}",
        "GITHUB_SHA": "a" * 40,
        "CASE": case,
        "CALLS": str(calls),
        "TAG": tag,
    }
    result = subprocess.run(
        ["bash", str(ROOT / "github/stage-prerelease.sh")],
        env=env,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert (result.returncode == 0) is success
    history = (
        [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    )
    edits = [entry for entry in history if entry[1] == "edit"]
    assert len(edits) == writes
    for entry in edits:
        assert entry == [
            "release",
            "edit",
            tag,
            "--repo",
            "zunderlabs/zunder-guard",
            "--draft=false",
            "--prerelease",
            "--latest=false",
        ]
