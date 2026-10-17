# Disposable hosted Windows runner only. Installs a released Guard as the protected
# Windows (SCM) service with SYNTHETIC inputs and prints what happens at each step.
#
# No E2E secret, no testnet lock, no real account: the account is a placeholder address
# and the API wallet key is the Hyperliquid SDK's public test key (never funded, never approved
# on any venue). Guard only makes read-only info requests for them. Because every input
# is synthetic, the installer's own output is printed in full (the key itself never is).
#
# Stage A runs the released loader exactly as the I4 harness does (testnet, managed
# service, private stdin, captured stdio). Its init refuses the unapproved synthetic
# wallet by design, so every step before init is exercised for real.
# Stage B then writes a synthetic testnet config and journal and resumes with the
# retained, verified helper: service prepare, binding, credential provision, check,
# and an explicit Start, showing whether SCM starts the broker.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$')][string]$Tag,
  [ValidateSet('powershell','pwsh')][string]$Shell = 'powershell',
  [string]$Out = 'scm-diagnostic'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Disposable hosted Windows runner only.' }
$Principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated runner required.' }

$Id = 'testnet-diagnostic'
$Name = "ZunderGuard-$Id"
$Account = '0x00000000000000000000000000000000000000d1'
# The Hyperliquid Python SDK's public signing-test key and its address (also the vectors in
# zunder-hl-protocol's sdk_vectors.rs): synthetic, never funded, never approved.
$Key = '0123456789012345678901234567890123456789012345678901234567890123'
$Wallet = '0x14791697260e4c9a71f18484c9f997b308e59325'
$Out = [IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Work = Join-Path $env:RUNNER_TEMP 'scm-diagnostic'
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$Data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ZunderGuard'
$Bin = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ZunderGuard'
$Root = Join-Path $Data $Id
$Runtime = Join-Path $Root 'runtime'
$Config = Join-Path $Runtime 'guard.toml'
$Exe = Join-Path (Join-Path $Bin $Id) 'zunder-guard.exe'
$Transaction = Join-Path (Join-Path $Data 'management') "$Id.json"
$ShellExe = if ($Shell -eq 'pwsh') { (Get-Command pwsh.exe).Source } else { Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
$Report = Join-Path $Out 'report.txt'
function Say([string]$Text) { Write-Host $Text; Add-Content -LiteralPath $Report -Value $Text -Encoding utf8 }
function Hide([string]$Text) { if ($null -eq $Text) { return '' }; return $Text.Replace($Key,'[SYNTHETIC KEY]') }

function Invoke-Captured([string]$Label,[string]$File,[string[]]$Arguments,[string]$Stdin) {
  # Captured stdio, as the harness runs the installer: the same redirection and wrapping.
  $info = [Diagnostics.ProcessStartInfo]::new($File)
  foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
  $info.UseShellExecute = $false
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $process = [Diagnostics.Process]::Start($info)
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  if ($Stdin) { $process.StandardInput.Write($Stdin) }
  $process.StandardInput.Close()
  if (-not $process.WaitForExit(900000)) { $process.Kill($true); Say "${Label}: TIMEOUT" }
  $process.WaitForExit()
  Say "===== ${Label}: exit $($process.ExitCode)"
  Say '----- stdout'; Say (Hide $stdout.Result)
  Say '----- stderr'; Say (Hide $stderr.Result)
  return $process.ExitCode
}

function Show-State([string]$Label) {
  Say "===== state after $Label"
  if (Test-Path -LiteralPath $Transaction) {
    $value = Get-Content -Raw -LiteralPath $Transaction | ConvertFrom-Json
    Say "transaction phase: $($value.phase)"
  } else { Say 'transaction: absent' }
  foreach ($verb in @('query','qc')) {
    $text = & (Join-Path $env:SystemRoot 'System32\sc.exe') $verb $Name 2>&1 | Out-String
    Say "sc $verb (exit $LASTEXITCODE):"; Say $text.Trim()
  }
  foreach ($path in @($Data,$Bin,$Root,$Runtime,(Join-Path $Bin $Id),$Exe,$Config,(Join-Path $Root 'binding.json'),(Join-Path $Root 'credential.dpapi'),(Join-Path $Runtime 'risk.jsonl'))) {
    if (Test-Path -LiteralPath $path) { Say ("acl " + $path + " = " + (Get-Acl -LiteralPath $path).Sddl) }
    else { Say "acl $path = absent" }
  }
  try {
    $events = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddHours(-2)} -ErrorAction Stop |
      Where-Object { $_.Message -match 'Zunder' } | Select-Object -First 20
    foreach ($event in $events) { Say ("scm event {0} {1}: {2}" -f $event.Id,$event.TimeCreated.ToString('o'),($event.Message -replace '\s+',' ')) }
  } catch { Say "scm events: none or unreadable ($($_.Exception.GetType().Name))" }
}

Say "Guard Windows SCM diagnostic: tag $Tag, loader shell $Shell, PowerShell $($PSVersionTable.PSVersion), $((Get-CimInstance Win32_OperatingSystem).Caption)"
$Base = "https://github.com/zunderlabs/zunder-guard/releases/download/$Tag"
$Loader = Join-Path $Work 'i.ps1'
$Zip = Join-Path $Work 'guard.zip'
Invoke-WebRequest -Uri "$Base/i.ps1" -OutFile $Loader -UseBasicParsing
Invoke-WebRequest -Uri "$Base/zunder-guard-$Tag-windows-amd64.zip" -OutFile $Zip -UseBasicParsing
$Tools = Join-Path $Work 'tools'
Expand-Archive -LiteralPath $Zip -DestinationPath $Tools -Force
$Tool = Join-Path $Tools 'zunder-guard.exe'

# The released defaults as a rules code, from a throwaway paper home.
$PaperHome = Join-Path $Work 'paper-home'
$null = Invoke-Captured 'paper init (rules source)' $Tool @('--home',$PaperHome,'init','--non-interactive','--network','paper','--account',$Account,'--account-network','testnet') ''
$Rules = ((& $Tool --home $PaperHome config get rules) -join '').Trim()
Say "rules: $Rules"

# Hosted images carry crash-dump policies Guard refuses; the runner is discarded afterwards.
foreach ($hive in @('HKLM:','HKCU:')) {
  foreach ($path in @('SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps','SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting')) {
    $full = "$hive\$path"
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force; Say "removed crash policy $full" }
  }
}

$Frame = "$Key`n"
$code = Invoke-Captured 'stage A: loader -ManagedService testnet (synthetic wallet)' $ShellExe @('-NoProfile','-ExecutionPolicy','Bypass','-File',$Loader,'-Network','testnet','-ManagedService','-NonInteractive','-KeyStdin','-Id',$Id,'-Rules',$Rules,'-Account',$Account,'-ConfirmAccount',$Account,'-EquityCap','100') ($Frame + $Frame)
Show-State 'stage A'

$phase = if (Test-Path -LiteralPath $Transaction) { (Get-Content -Raw -LiteralPath $Transaction | ConvertFrom-Json).phase } else { '' }
if ($phase -ne 'config-preparing' -or (Test-Path -LiteralPath $Config)) {
  Say "stage B skipped: stage A stopped at phase '$phase' (expected config-preparing after init refuses the synthetic wallet)."
  exit 0
}

# Stage B: a synthetic testnet config (the paper config's fields, switched to testnet with the
# synthetic wallet) and its journal, then the retained helper's Resume and Start.
$text = Get-Content -Raw -LiteralPath (Join-Path $PaperHome 'guard.toml')
$text = $text -replace '(?m)^mode = .*$','mode = "testnet"'
$text = $text -replace '(?m)^network = .*$','network = "testnet"'
$text = $text -replace '(?m)^state_dir = .*$','state_dir = "."'
$text = $text -replace '(?m)^(account = .*)$',"`$1`napi_wallet = `"$Wallet`""
$text = $text -replace '(?m)^max_trading_equity_usd = .*$','max_trading_equity_usd = "100"'
[IO.File]::WriteAllText($Config,$text,[Text.UTF8Encoding]::new($false))
$null = Invoke-Captured 'stage B: journal-init testnet (synthetic account)' $Exe @('--home',$Runtime,'--config',$Config,'journal-init','--mode','testnet','--note','hosted SCM diagnostic, synthetic account') ''
$Helper = (Get-Content -Raw -LiteralPath $Transaction | ConvertFrom-Json).release
$Helper = Join-Path $Helper 'install-windows-service.ps1'
$Windows = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$null = Invoke-Captured 'stage B: helper Resume (prepare, binding, provision, check)' $Windows @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Helper,'-Action','Resume','-Network','testnet','-KeyStdin','-Id',$Id,'-ConfirmAccount',$Account) $Frame
Show-State 'stage B Resume'
$null = Invoke-Captured 'stage B: helper Start -Startup Manual' $Windows @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Helper,'-Action','Start','-Network','testnet','-Id',$Id,'-ConfirmAccount',$Account,'-Startup','Manual') ''
Show-State 'stage B Start'
$null = Invoke-Captured 'stage B: helper Status' $Windows @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Helper,'-Action','Status','-Network','testnet','-Id',$Id) ''
exit 0
