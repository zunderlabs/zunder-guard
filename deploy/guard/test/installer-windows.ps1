# Tests of the Windows installer (deploy/guard/loader/i.ps1), on a Windows runner (ci.yml):
# a release rendered from this build in -Release, signed with the test double's bundle that
# deploy/guard/test/fake-cosign accepts (a real Sigstore signature needs the release workflow).
#
#   powershell -File deploy/guard/test/installer-windows.ps1 -Release rel\v1.0.0 -Cosign fakebin\cosign.cmd
#   pwsh -File deploy/guard/test/installer-windows.ps1 -Release rel\v1.0.0 -Cosign fakebin\cosign.cmd
#
# Cases: install only; the full non-interactive paper setup, then run and health; a changed
# archive, changed checksums, another release's signature and a missing archive each refused
# before anything is installed; mainnet alternate InstallDir refused; nothing closes the calling PowerShell.
param(
  [Parameter(Mandatory)][string]$Release,
  [Parameter(Mandatory)][string]$Cosign
)
$ErrorActionPreference = 'Stop'
$Release = (Resolve-Path $Release).Path
$Cosign = (Resolve-Path $Cosign).Path
$Script = Get-Content -Raw -LiteralPath (Join-Path $Release 'i.ps1')
$Rules = 'zr1_eyJ2IjoxfQ'
$Account = '0x67f7aa8fb95c47e6ea9c517b623e0701cbf9d9ba'  # a public account; read only
$Failed = @()
$Work = Join-Path ([IO.Path]::GetTempPath()) ("guard-i-ps1-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work | Out-Null

function Invoke-Installer([string]$From, [hashtable]$Arguments) {
  $env:ZUNDER_GUARD_BASE_URL = $From
  $env:ZUNDER_GUARD_COSIGN = $Cosign
  & ([scriptblock]::Create($Script)) @Arguments
}
function Pass([string]$Name) { Write-Host "  ok: $Name" }
function Fail([string]$Name, [string]$Detail) { Write-Host "  FAIL: $Name`n$Detail"; $script:Failed += $Name }
function Expect-Refusal([string]$Name, [string]$From, [hashtable]$Arguments, [string]$Needle) {
  $Dir = $Arguments['InstallDir']
  try {
    Invoke-Installer $From $Arguments
    Fail $Name 'the installer went through'
  } catch {
    if ($_.Exception.Message -like "*$Needle*") {
      if ($Dir -and (Test-Path (Join-Path $Dir 'zunder-guard.exe'))) { Fail $Name 'refused, but a binary was installed' }
      else { Pass "$Name (refused: $Needle)" }
    } else { Fail $Name "refused for another reason: $($_.Exception.Message)" }
  }
}
function Copy-Release([string]$Name) {
  $To = Join-Path $Work $Name
  Copy-Item -LiteralPath $Release -Destination $To -Recurse
  return $To
}

try {
  Write-Host "== i.ps1 on $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
  $Zip = (Get-ChildItem -LiteralPath $Release -Filter 'zunder-guard-*-windows-amd64.zip').Name

  # 1. Install only.
  $Dir = Join-Path $Work 'bin-only'
  Invoke-Installer $Release @{ InstallOnly = $true; InstallDir = $Dir }
  $Exe = Join-Path $Dir 'zunder-guard.exe'
  if ((Test-Path $Exe) -and (Test-Path (Join-Path $Dir 'LICENSE'))) { Pass 'install only: zunder-guard.exe and LICENSE installed' }
  else { Fail 'install only' "nothing at $Exe" }

  # 2. Non-interactive paper setup, then run and health.
  $env:ZUNDER_GUARD_HOME = Join-Path $Work 'home'
  $Dir = Join-Path $Work 'bin'
  Invoke-Installer $Release @{ NonInteractive = $true; Rules = $Rules; Account = $Account; InstallDir = $Dir }
  $Exe = Join-Path $Dir 'zunder-guard.exe'
  $Mode = (& $Exe config get network) -join ''
  if ($Mode -eq 'paper') { Pass 'non-interactive setup: paper' } else { Fail 'non-interactive setup' "mode $Mode" }
  $Guard = Start-Process -FilePath $Exe -ArgumentList 'run', '--network', 'paper' -PassThru -NoNewWindow
  $Healthy = $false
  foreach ($i in 1..30) { & $Exe health 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { $Healthy = $true; break }; Start-Sleep 1 }
  Stop-Process -Id $Guard.Id -ErrorAction SilentlyContinue
  if ($Healthy) { Pass 'zunder-guard run --network paper answers health on 127.0.0.1:8547' } else { Fail 'run' 'not healthy in 30 s' }

  # 3. Tampering, each refused before anything is installed.
  $R = Copy-Release 'tampered-zip'
  Add-Content -LiteralPath (Join-Path $R $Zip) -Value 'x'
  Expect-Refusal 'a changed archive' $R @{ InstallOnly = $true; InstallDir = (Join-Path $Work 't1') } 'checksum mismatch'
  $R = Copy-Release 'tampered-sums'
  Add-Content -LiteralPath (Join-Path $R 'SHA256SUMS') -Value ('0' * 64 + '  extra')
  Expect-Refusal 'changed checksums' $R @{ InstallOnly = $true; InstallDir = (Join-Path $Work 't2') } 'signature check FAILED'
  $R = Copy-Release 'other-signer'
  $Bundle = Join-Path $R 'SHA256SUMS.sigstore.json'
  (Get-Content -Raw $Bundle) -replace 'refs/tags/v', 'refs/tags/x' | Set-Content -NoNewline $Bundle
  Expect-Refusal "another release's signature" $R @{ InstallOnly = $true; InstallDir = (Join-Path $Work 't3') } 'signature check FAILED'
  $R = Copy-Release 'no-archive'
  Remove-Item -LiteralPath (Join-Path $R $Zip)
  Expect-Refusal 'a missing archive' $R @{ InstallOnly = $true; InstallDir = (Join-Path $Work 't4') } ''
  Expect-Refusal 'mainnet' $Release @{ Network = 'mainnet'; InstallDir = (Join-Path $Work 't5') } 'Mainnet refuses NonInteractive, InstallOnly, Force and alternate InstallDir.'
  Expect-Refusal 'bad rules' $Release @{ Rules = 'nope'; InstallDir = (Join-Path $Work 't6') } 'zr1_'
} finally {
  Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($Failed.Count -gt 0) { throw "i.ps1 tests failed: $($Failed -join ', ')" }
Write-Host 'i.ps1 tests passed'
# Expected native verifier refusals leave LASTEXITCODE nonzero.
# Report success only after every assertion above has passed.
exit 0
