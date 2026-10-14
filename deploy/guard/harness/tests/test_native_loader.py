"""Offline execution of the production per-user PowerShell verifier boundary."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

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
    )
    output = result.stdout + result.stderr
    assert ("verifier-diagnostic-fixture" in output) is noisy
    if exit_status:
        assert "INSTALL-REFUSED" in output and "INSTALL-ALLOWED" not in output
        assert "signature check FAILED" in output
        assert "could not be verified" in output
    else:
        assert "INSTALL-ALLOWED" in output and "INSTALL-REFUSED" not in output
