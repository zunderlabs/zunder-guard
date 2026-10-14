"""Offline execution of the production per-user PowerShell verifier boundary."""

import hashlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from guard_harness.native_channels import paper_failure_category
from guard_harness.testnet_run import ROOT


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe", "pwsh"])
@pytest.mark.parametrize("exit_status,noisy", [(0, True), (7, True), (3, False)])
def test_per_user_verifier_keeps_diagnostics_and_refuses_before_install(
    tmp_path: Path, shell: str, exit_status: int, noisy: bool
) -> None:
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} is unavailable")
    source = ROOT / "loader/i.ps1"
    script = source.read_text()
    start = script.index("    # Stream verifier diagnostics")
    end = script.index('    Write-Host "  signature:', start)
    verifier = tmp_path / ("verifier.cmd" if os.name == "nt" else "verifier")
    if os.name == "nt":
        verifier.write_text(
            "@echo off\n"
            + ("echo verifier-diagnostic-fixture 1>&2\n" if noisy else "")
            + f"exit /b {exit_status}\n"
        )
    else:
        verifier.write_text(
            "#!/bin/sh\n"
            + ("echo verifier-diagnostic-fixture >&2\n" if noisy else "")
            + f"exit {exit_status}\n"
        )
        verifier.chmod(0o700)

    def quote(value: Path) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    command = f"""
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile({quote(source)},[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'loader parse failed' }}
$definition=$ast.Find({{
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-ZgReleaseVerifier'
}},$true)
. ([scriptblock]::Create($definition.Extent.Text))
$Cosign={quote(verifier)}; $Bundle='bundle-fixture'; $Sums='sums-fixture'
$Repo='zunderlabs/zunder-guard'; $V='v1.0.0-rc.15'
$Identity="https://github.com/$Repo/.github/workflows/release.yml@refs/tags/$V"
$ErrorActionPreference='Stop'; $LASTEXITCODE=55
try {{
{script[start:end]}
  Write-Output 'INSTALL-ALLOWED'
}} catch {{
  Write-Output $_.Exception.Message
  Write-Output 'INSTALL-REFUSED'
}}
if ($ErrorActionPreference -ne 'Stop') {{ throw 'error preference was not restored' }}
exit 0
"""
    result = subprocess.run(
        [executable, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        env={**os.environ, "HOME": str(tmp_path), "TEMP": str(tmp_path), "TMP": str(tmp_path)},
    )
    output = result.stdout + result.stderr
    assert ("verifier-diagnostic-fixture" in output) is noisy
    if exit_status:
        assert "INSTALL-REFUSED" in output and "INSTALL-ALLOWED" not in output
        assert "signature check FAILED" in output
        assert "could not be verified" in output
    else:
        assert "INSTALL-ALLOWED" in output and "INSTALL-REFUSED" not in output


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe", "pwsh"])
@pytest.mark.parametrize(
    "mutation,category",
    [
        (None, "unknown"),
        ("checksum-missing", "checksum-missing"),
        ("checksum-mismatch", "checksum"),
        ("invalid-archive", "archive-extraction"),
        ("missing-exe", "archive-missing-binary"),
        ("install-directory", "install-copy"),
        ("install-copy", "install-copy"),
        ("install-inventory", "install-inventory-write"),
    ],
)
def test_post_signature_production_install_block_offline(
    tmp_path: Path,
    shell: str,
    mutation: str | None,
    category: str,
) -> None:
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} is unavailable")
    source = (ROOT / "loader/i.ps1").read_text()
    start = source.index('    Write-Host "  signature:')
    block = source[start : source.index("    $Version =", start)]
    archive_name = "zunder-guard-v1.0.0-rc.16-windows-amd64.zip"
    archive = tmp_path / archive_name
    if mutation == "invalid-archive":
        archive.write_bytes(b"inert-invalid-archive")
    else:
        with zipfile.ZipFile(archive, "w") as bundle:
            if mutation != "missing-exe":
                bundle.writestr("zunder-guard.exe", b"inert-never-executed-binary")
            bundle.writestr("NOTICE", b"inert-notice")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if mutation == "checksum-mismatch":
        digest = "0" * 64
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(
        digest + "  " + ("other.zip" if mutation == "checksum-missing" else archive_name)
    )
    install = tmp_path / "install"
    if mutation == "install-directory":
        blocker = tmp_path / "blocked-parent"
        blocker.write_text("inert-directory-collision")
        install = blocker / "install"
    elif mutation == "install-copy":
        install.write_text("inert-file-collision")
    elif mutation == "install-inventory":
        install.mkdir()
        (install / ".zunder-guard-install.json").mkdir()

    # Use an actual extracted archive and cmdlets, without calling a verifier,
    # binary, init, PATH mutation or network. All bytes and errors are inert.
    def quote(value: Path | str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    command = f"""
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
$ErrorView='NormalView'
$V='v1.0.0-rc.16'; $Repo='zunderlabs/zunder-guard'; $Archive={quote(archive_name)}
$Zip={quote(archive)}; $Sums={quote(sums)}; $Tmp={quote(tmp_path)}; $InstallDir={quote(install)}
function Get-Sha256([string]$Path) {{
  (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}}
try {{
{block}
  Write-Output 'INVENTORY-WRITTEN'
}} catch {{
  throw
}}
"""
    result = subprocess.run(
        [executable, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path), "TEMP": str(tmp_path), "TMP": str(tmp_path)},
    )
    output = result.stdout + result.stderr
    assert (result.returncode == 0) is (mutation is None), output
    assert paper_failure_category(output) == category, output
    if mutation is None:
        import json

        inventory = json.loads(
            (install / ".zunder-guard-install.json").read_text(encoding="utf-8-sig")
        )
        assert inventory == {
            "schema": 1,
            "tag": "v1.0.0-rc.16",
            "files": {
                "zunder-guard.exe": hashlib.sha256(b"inert-never-executed-binary").hexdigest(),
                "NOTICE": hashlib.sha256(b"inert-notice").hexdigest(),
            },
        }
    else:
        assert "INVENTORY-WRITTEN" not in output
