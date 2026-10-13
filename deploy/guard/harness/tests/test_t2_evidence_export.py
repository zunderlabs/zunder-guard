"""Exercise the workflow's fixed root-read export without privileged local operations."""

import os
import subprocess
from pathlib import Path

import pytest

from guard_harness.testnet_run import ROOT


def workflow(root: Path) -> Path:
    private = root / "github/workflows/journey.yml"
    return private if private.is_file() else root.parents[1] / ".github/workflows/journey.yml"


@pytest.mark.parametrize("exported", [False, True])
def test_export_only_allowlisted_public_evidence_never_custody_or_links(
    tmp_path: Path, exported: bool
) -> None:
    source = tmp_path / "root/guard-release-123-1/T2"
    runtime = source / "runtime"
    runtime.mkdir(parents=True)
    (source / "assets").mkdir()
    (source / "assets/release-manifest.json").write_bytes(b"authenticated manifest fixture")
    (source / "receipt.json").write_bytes(b"sanitized receipt fixture")
    (runtime / "process.log").write_bytes(b"sanitized runtime fixture")
    startup_logs = {"testnet-service-install.log", "service-stop.log", "service-start.log"}
    for name in startup_logs:
        (runtime / name).write_bytes(b"[sensitive command output withheld]\n")
    (runtime / "journal.log").write_bytes(b"private journal fixture")
    (runtime / "i-staging").write_bytes(b"excluded loader fixture")
    (runtime / "entry-response.json").write_bytes(b'{"sent":false,"outcome":"refused"}')
    (runtime / "client-key").write_bytes(b"private pairing fixture")
    (runtime / "guard.toml").write_bytes(b"private custody fixture")
    (runtime / "pair.log").symlink_to(runtime / "client-key")
    tools = tmp_path / "tools"
    tools.mkdir()
    sudo = tools / "sudo"
    sudo.write_text('#!/bin/sh\ncase "$1" in test|/usr/bin/tar) exec "$@" ;; *) exit 91 ;; esac\n')
    sudo.chmod(0o700)
    runner = tmp_path / "runner"
    runner.mkdir(mode=0o700)
    text = workflow(ROOT).read_text()
    if exported:
        # Fresh public shape: no private workflow directory exists in this copy.
        public = tmp_path / "public"
        guard = public / "deploy/guard"
        guard.mkdir(parents=True)
        exported_workflow = public / ".github/workflows/journey.yml"
        exported_workflow.parent.mkdir(parents=True)
        exported_workflow.write_text(text)
        assert not (guard / "github/workflows").exists()
        assert workflow(guard) == exported_workflow
        text = workflow(guard).read_text()
    step = text.split(
        "      - name: Export only fixed public evidence from root-owned custody workspace\n", 1
    )[1].split("      - name:", 1)[0]
    script = step.split("        run: |\n", 1)[1]
    script = "\n".join(line.removeprefix("          ") for line in script.splitlines())
    script = script.replace("/root/guard-release-", str(tmp_path / "root/guard-release-"))
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            "PATH": str(tools) + os.pathsep + os.defpath,
            "RUNNER_TEMP": str(runner),
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
        },
        capture_output=True,
        timeout=10,
        check=True,
    )
    output = runner / "guard-release/T2"
    files = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
    assert files == {
        "assets/release-manifest.json",
        "receipt.json",
        "runtime/process.log",
        "runtime/entry-response.json",
        *("runtime/" + name for name in startup_logs),
    }
    for name in startup_logs:
        assert (output / "runtime" / name).read_bytes() == b"[sensitive command output withheld]\n"
    assert (output / "runtime/entry-response.json").read_bytes() == (
        b'{"sent":false,"outcome":"refused"}'
    )
    assert (output / "receipt.json").read_bytes() == b"sanitized receipt fixture"
    assert not any(path.is_symlink() for path in output.rglob("*"))
    assert (runtime / "client-key").read_bytes() == b"private pairing fixture"
    assert b"private pairing" not in result.stdout + result.stderr


@pytest.mark.parametrize("row", ["T1", "T2"])
def test_finite_failure_upload_precedes_slow_scan_without_custody(row: str) -> None:
    text = workflow(ROOT).read_text()
    label = f"      - name: Retain finite {row} failure evidence before cleanup scan\n"
    step = text.split(label, 1)[1].split("      - name:", 1)[0]
    assert "failure() || cancelled()" in step
    paths = step.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
    files = {line.strip().split(f"/guard-release/{row}/", 1)[1] for line in paths.splitlines()}
    expected = {
        "receipt.json",
        "runtime/entry-attempt.json",
        "runtime/entry-response.json",
        "runtime/ownership.json",
    }
    if row == "T2":
        expected |= {
            "runtime/testnet-service-install.log",
            "runtime/service-stop.log",
            "runtime/service-start.log",
        }
    assert files == expected
    assert text.index(label) < text.index(
        f'guard_harness.failure_scan --work "$RUNNER_TEMP/guard-release/{row}-failure/'
    )
    assert "include-hidden-files" not in step and "attest" not in step
