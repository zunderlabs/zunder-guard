"""Offline verifier replay, loader-download capture and refusal checks."""

import hashlib
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from guard_harness.native_release import Release
from guard_harness.native_verifier import NAMES, LoaderDownloads, verifier_probe
from guard_harness.testnet_run import ROOT


def inputs(tmp_path: Path) -> tuple[Release, LoaderDownloads]:
    assets = tmp_path / "assets"
    assets.mkdir()
    for name, body in zip(NAMES, (b"inert signed checksums", b"inert bundle"), strict=True):
        (assets / name).write_bytes(body)
    release = Release("v1.0.0-rc.15", "a" * 40, assets)
    temp = tmp_path / "temp"
    temp.mkdir()
    return release, LoaderDownloads(release, {"TMP": str(temp), "TEMP": str(temp)})


def downloaded(capture: LoaderDownloads, suffix: str = "a") -> Path:
    root = next(iter(capture.roots)) / ("zunder-guard-" + suffix * 32)
    root.mkdir()
    for name in NAMES:
        (root / name).write_bytes((capture.release.assets / name).read_bytes())
    return root


def test_capture_survives_loader_cleanup_without_changing_environment(tmp_path: Path) -> None:
    _, capture = inputs(tmp_path)
    observed = threading.Event()
    scan = capture.scan

    def notify() -> None:
        scan()
        if capture.bodies is not None:
            observed.set()

    capture.scan = notify  # type: ignore[method-assign]
    with capture:
        directory = downloaded(capture)
        assert observed.wait(3), "watcher must capture before the loader's finally cleanup"
        for name in NAMES:
            (directory / name).unlink()
        directory.rmdir()
    assert capture.bodies == (b"inert signed checksums", b"inert bundle")
    assert capture.status == "captured-loader-downloads-match-authenticated-release"
    assert capture.thread is not None and not capture.thread.is_alive()


def test_capture_ignores_old_partial_and_aliased_files_and_refuses_ambiguity(
    tmp_path: Path,
) -> None:
    _, capture = inputs(tmp_path)
    old = downloaded(capture, "b")
    capture.before = {old}
    capture.expected = tuple((capture.release.assets / name).read_bytes() for name in NAMES)
    directory = downloaded(capture)
    bundle = directory / NAMES[1]
    bundle.write_bytes(b"partial")
    capture.scan()
    assert capture.bodies is None
    bundle.unlink()
    bundle.symlink_to(capture.release.assets / NAMES[1])
    capture.scan()
    assert capture.bodies is None
    bundle.unlink()
    bundle.write_bytes(capture.expected[1])
    capture.scan()
    assert capture.bodies == capture.expected
    downloaded(capture, "c")
    capture.scan()
    assert capture.bodies is None and capture.status == "loader-downloads-ambiguous"


@pytest.mark.parametrize("second", ["success", "nonzero", "timeout", "start-error"])
def test_probe_replays_exact_pinned_command_in_both_environments_and_redacts_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, second: str
) -> None:
    release, capture = inputs(tmp_path)
    capture.bodies = tuple((release.assets / name).read_bytes() for name in NAMES)
    capture.status = "captured-loader-downloads-match-authenticated-release"
    account = "0x" + "ab" * 20
    inert_verifier = b"offline pinned verifier fixture"
    digest = hashlib.sha256(inert_verifier).hexdigest()
    loader = (
        (ROOT / "loader/i.ps1")
        .read_text()
        .replace("9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be", digest)
    )
    monkeypatch.setattr(Release, "asset", lambda self, name: loader.encode())
    clean = {"PATH": "inert-path", "TMP": str(tmp_path / "temp"), "TERM": "dumb"}
    full = {**clean, "APPDATA": "inert-full-profile", "PRIVATE_SENTINEL": "never-log-this"}
    calls: list[list[str]] = []

    def command(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        assert kwargs["input"] == b"" and kwargs["capture_output"]
        assert kwargs["check"] is False and kwargs["timeout"] == 180
        if len(calls) == 1:
            assert kwargs["env"] is clean
            assert argv[:5] == [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ]
            script = Path(argv[-1]).read_text(encoding="utf-8-sig")
            assert "Invoke-WebRequest -UseBasicParsing" in script
            assert "[Net.SecurityProtocolType]::Tls12" in script
            assert "https://github.com/sigstore/cosign/releases/download/v3.1.3/" in script
            assert "-Algorithm SHA256).Hash.ToLowerInvariant()" in script and digest in script
            (tmp_path / "verifier-inputs/cosign-windows-amd64.exe").write_bytes(inert_verifier)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        assert kwargs["env"] is (clean if len(calls) == 2 else full)
        assert argv[1:] == [
            "verify-blob",
            "--bundle",
            str(tmp_path / "verifier-inputs" / NAMES[1]),
            "--certificate-identity",
            "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml"
            "@refs/tags/v1.0.0-rc.15",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            str(tmp_path / "verifier-inputs" / NAMES[0]),
        ]
        assert [Path(argv[index]).read_bytes() for index in (8, 3)] == list(capture.bodies or ())
        if len(calls) == 3 and second == "timeout":
            raise subprocess.TimeoutExpired(argv, 180, b"partial stdout", account.upper().encode())
        if len(calls) == 3 and second == "start-error":
            raise OSError("private exception must never be logged")
        code = 7 if len(calls) == 2 or second == "nonzero" else 0
        return subprocess.CompletedProcess(
            argv, code, b"cosign stdout " + account.encode(), b"cosign stderr"
        )

    monkeypatch.setattr("guard_harness.native_verifier.subprocess.run", command)
    verifier_probe(
        release, capture, tmp_path, clean=clean, full=full, shell="powershell.exe", account=account
    )
    log = (tmp_path / "verifier-probe.log").read_text()
    assert len(calls) == 3 and calls[1] == calls[2]
    assert "environment: native_channels clean environment\nexit status: 7" in log
    assert "environment: runner full environment" in log
    assert "cosign stdout [REDACTED]" in log and "cosign stderr" in log
    assert account.lower() not in log.lower()
    assert (
        "PRIVATE_SENTINEL" not in log
        and "never-log-this" not in log
        and "private exception" not in log
    )
    assert clean == {"PATH": "inert-path", "TMP": str(tmp_path / "temp"), "TERM": "dumb"}
    expected = "0" if second == "success" else "7" if second == "nonzero" else "unavailable"
    assert "environment: runner full environment\nexit status: " + expected in log


@pytest.mark.parametrize("failure", ["not-captured", "pin", "download", "hash"])
def test_probe_refuses_missing_inputs_and_never_executes_unchecked_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    release, capture = inputs(tmp_path)
    if failure != "not-captured":
        capture.bodies = tuple((release.assets / name).read_bytes() for name in NAMES)
    source = b"invalid loader" if failure == "pin" else (ROOT / "loader/i.ps1").read_bytes()
    monkeypatch.setattr(Release, "asset", lambda self, name: source)
    calls = []

    def command(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        assert len(calls) == 1 and "-File" in argv
        (tmp_path / "verifier-inputs/cosign-windows-amd64.exe").write_bytes(b"tampered")
        return subprocess.CompletedProcess(argv, 1 if failure == "download" else 0, b"", b"")

    monkeypatch.setattr("guard_harness.native_verifier.subprocess.run", command)
    verifier_probe(release, capture, tmp_path, clean={}, full={}, shell="pwsh.exe", account="inert")
    assert len(calls) == (0 if failure in {"not-captured", "pin"} else 1)
    assert "probe outcome:" in (tmp_path / "verifier-probe.log").read_text()


@pytest.mark.skipif(os.name == "nt", reason="POSIX inert executable fixture")
def test_probe_runs_real_offline_verifier_for_clean_and_full_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, capture = inputs(tmp_path)
    capture.bodies = tuple((release.assets / name).read_bytes() for name in NAMES)
    verifier = (
        b'#!/bin/sh\necho "fixture-stdout"\necho "fixture-stderr" >&2\nexit "${PROBE_EXIT:-9}"\n'
    )
    digest = hashlib.sha256(verifier).hexdigest()
    loader = (
        (ROOT / "loader/i.ps1")
        .read_text()
        .replace("9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be", digest)
    )
    monkeypatch.setattr(Release, "asset", lambda self, name: loader.encode())
    real_run = subprocess.run

    def command(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "offline-download-shell":
            target = tmp_path / "verifier-inputs/cosign-windows-amd64.exe"
            target.write_bytes(verifier)
            target.chmod(0o700)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return real_run(argv, **kwargs)

    monkeypatch.setattr("guard_harness.native_verifier.subprocess.run", command)
    verifier_probe(
        release,
        capture,
        tmp_path,
        clean={},
        full={"PROBE_EXIT": "0"},
        shell="offline-download-shell",
        account="inert-account",
    )
    log = (tmp_path / "verifier-probe.log").read_text()
    assert "native_channels clean environment\nexit status: 9" in log
    assert "runner full environment\nexit status: 0" in log
    assert log.count("stdout:\nfixture-stdout") == 2
    assert log.count("stderr:\nfixture-stderr") == 2


@pytest.mark.parametrize("download", ["valid", "tampered", "failed"])
def test_generated_download_executes_real_powershell_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, download: str
) -> None:
    shell = shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell unavailable for offline download-script execution")
    release, capture = inputs(tmp_path)
    capture.bodies = tuple((release.assets / name).read_bytes() for name in NAMES)
    body = b"inert pinned Windows verifier"
    digest = hashlib.sha256(body).hexdigest()
    loader = (
        (ROOT / "loader/i.ps1")
        .read_text()
        .replace("9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be", digest)
    )
    monkeypatch.setattr(Release, "asset", lambda self, name: loader.encode())
    fixture = tmp_path / "download-fixture"
    fixture.write_bytes(body if download == "valid" else b"tampered")
    real_run = subprocess.run
    verifications = []

    def quote(value: Path) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    def command(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "offline-download-shell":
            driver = tmp_path / "offline-download-driver.ps1"
            driver.write_text(
                "function Invoke-WebRequest {\n"
                "param([switch]$UseBasicParsing,[string]$Uri,[string]$OutFile)\n"
                "if (-not $UseBasicParsing -or $Uri -cne "
                "'https://github.com/sigstore/cosign/releases/download/v3.1.3/"
                "cosign-windows-amd64.exe') { throw 'download invocation differs' }\n"
                + ("throw 'inert network refusal'\n" if download == "failed" else "")
                + "Copy-Item -LiteralPath "
                + quote(fixture)
                + " -Destination $OutFile\n}\n"
                + ". "
                + quote(Path(argv[-1]))
                + "\nexit $LASTEXITCODE\n",
                encoding="utf-8-sig",
            )
            return real_run([shell, "-NoProfile", "-File", str(driver)], **kwargs)
        verifications.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"inert verifier output", b"")

    monkeypatch.setattr("guard_harness.native_verifier.subprocess.run", command)
    verifier_probe(
        release,
        capture,
        tmp_path,
        clean={"HOME": str(tmp_path)},
        full={},
        shell="offline-download-shell",
        account="inert-account",
    )
    log = (tmp_path / "verifier-probe.log").read_text()
    expected = "0" if download == "valid" else "2" if download == "tampered" else "1"
    assert "pinned download exit status: " + expected in log
    assert len(verifications) == (2 if download == "valid" else 0)
