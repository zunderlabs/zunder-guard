# Synthetic boundaries only: no service, credential, network, privilege or native binary.
# Parses/loads real function ASTs; exercises actual lifecycle code with temp files.
[CmdletBinding()]
param([string]$SourceRoot = (Split-Path $PSScriptRoot -Parent))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tests=0
function Assert([bool]$Condition,[string]$Name) { if (-not $Condition) { throw "FAIL: $Name" }; $script:tests++ }
function Refuses([scriptblock]$Code,[string]$Name) { $failed=$false; try { & $Code | Out-Null } catch { $failed=$true }; Assert $failed $Name }
foreach ($relative in @('loader/i.ps1','windows/service.ps1')) {
  $tokens=$null; $errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot $relative),[ref]$tokens,[ref]$errors)
  Assert ($errors.Count -eq 0) "parse $relative"
  foreach ($node in $ast.FindAll({ param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] },$true)) {
    . ([scriptblock]::Create($node.Extent.Text))
  }
}
$realPrepare=(Get-Item Function:Complete-ZgPrepare).ScriptBlock
$realUpgrade=(Get-Item Function:Complete-ZgUpgrade).ScriptBlock
$realStart=(Get-Item Function:Complete-ZgStart).ScriptBlock
$realManifest=(Get-Item Function:Get-ZgManifestHash).ScriptBlock
$realImage=(Get-Item Function:Get-ZgImage).ScriptBlock
$realHash=(Get-Item Function:Get-ZgHash).ScriptBlock
# All OS/trust/network/Guard boundaries below are synthetic; production functions
# have no test flags and cannot select these adapters through user arguments/env.
function Assert-ZgPath($Path,[switch]$Machine,[string]$ReadSid) { if (-not (Test-Path -LiteralPath $Path)) { throw 'missing fixture path' } }
function Assert-ZgCache { if ($script:badCache) { throw 'synthetic signature rejection' } }
function Confirm-ZgConsent { if ($ConfirmAccount -cne $ZgTransaction.account) { throw 'synthetic consent mismatch' } }
function New-ZgDirectory($Path) { [IO.Directory]::CreateDirectory($Path) | Out-Null }
function Set-ZgAcl($Path,$Sid,$Writable) { if (-not (Test-Path -LiteralPath $Path)) { throw 'missing fixture ACL target' } }
function Disable-ZgService { $script:trace.Add('disabled'); $script:startupMode='Disabled'; $script:running=$false; Assert-ZgStopped }
function Assert-ZgStopped { if ($startupMode -ne 'Disabled' -or $running) { throw 'mutation before durable disabled/stopped state' } }
function Ensure-ZgService { Disable-ZgService; $script:ZgSid='fixture-service-sid' }
function Get-ZgImage {
  Assert-ZgCache
  $directory=Join-Path $script:work ([Guid]::NewGuid().ToString('N')); [IO.Directory]::CreateDirectory($directory) | Out-Null
  [IO.File]::WriteAllText((Join-Path $directory 'zunder-guard.exe'),$script:newImage)
  foreach ($name in @('LICENSE','NOTICE','THIRD_PARTY_LICENSES.md')) { [IO.File]::WriteAllText((Join-Path $directory $name),'fixture notice') }
  return $directory
}
function Install-ZgImage($Directory) {
  Assert-ZgStopped; $script:trace.Add('image-promoted')
  foreach ($name in @('zunder-guard.exe','LICENSE','NOTICE','THIRD_PARTY_LICENSES.md')) { [IO.File]::Copy((Join-Path $Directory $name),(Join-Path $ZgBinaryDir $name),$true) }
}
function Write-ZgJson($Path,$Value) {
  [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 24))
  if ($Path -eq $ZgTransactionPath) {
    $script:trace.Add('durable-'+$Value.phase); $script:writes++
    if ($script:crashAfter -gt 0 -and $script:writes -eq $script:crashAfter) { throw 'synthetic abrupt power loss AFTER durable write' }
  }
}
function Get-ZgPreparedBinding {
  if (-not [IO.File]::Exists($ZgConfig)) { throw 'missing config' }
  return [pscustomobject]@{ version=1; account=$ZgTransaction.account; api_wallet='0x2222222222222222222222222222222222222222'; mode='mainnet'; executable=$ZgExe; executable_sha256=(Get-ZgHash $ZgExe); home=$ZgHome; config=$ZgConfig; identity=@{service_name=$ZgServiceName;service_sid=$ZgSid} }
}
function Get-ZgBinding {
  $value=[IO.File]::ReadAllText($ZgBinding) | ConvertFrom-Json
  if ($value.executable_sha256 -cne (Get-ZgHash $ZgExe)) { throw 'binding/image mismatch' }
  return $value
}
function Invoke-ZgGuard([string[]]$Words) {
  $script:trace.Add('guard-'+($Words -join ' '))
  if ($Words[0] -eq 'init') {
    if ([IO.File]::Exists($ZgConfig)) { throw 'Repeated init would replace pairings' }
    $script:initCalls++; $script:pairingOutput++
    [IO.File]::WriteAllText($ZgConfig,"synthetic-config`nclient=preserved`nrenewal=preserved")
  } elseif ($Words[0] -eq 'service' -and $Words[1] -eq 'provision') {
    $credential=Join-Path $ZgRoot 'credential.dpapi'
    if ([IO.FileInfo]::new($credential).Length -ne 0) { throw 'Repeated credential provisioning refused' }
    $script:provisionCalls++; [IO.File]::WriteAllText($credential,'synthetic opaque ciphertext')
  } elseif ($Words[0] -eq 'service' -and $Words[1] -eq 'check') {
    if ($script:badCredential -or [IO.FileInfo]::new((Join-Path $ZgRoot 'credential.dpapi')).Length -eq 0) { throw 'synthetic credential admission refused' }
  } elseif ($Words[0] -eq 'service' -and $Words[1] -eq 'licence-set') {
    # Model only; actual licence verification is a separate real Rust/native gate.
    $script:licenceCalls++
  } else { throw 'unexpected Guard invocation in fixture' }
}
function Invoke-ZgSc([string[]]$Words) {
  if ($Words[0] -ne 'config' -or $Words[2] -ne 'start=') { throw 'unexpected SCM mutation' }
  $script:startupMode=$Words[3]; $script:trace.Add('startup-'+$Words[3])
  if ($Words[3] -eq 'delayed-auto' -and $ZgTransaction.phase -ne 'activation-committed') { throw 'auto startup before committed readiness' }
}
function Start-ZgOwnedRuntime { if ($startupMode -ne 'demand') { throw 'start before Demand' }; $script:startCalls++; $script:running=$true; $script:trace.Add('started') }
function Wait-ZgReady($StartedAt) { if ($script:badReadiness) { throw 'synthetic unready runtime' }; return @{account=$ZgTransaction.account;mode='mainnet';risk='active';trading_ready=$true;approval='not_required'} }
function New-Case {
  $script:work=Join-Path ([IO.Path]::GetTempPath()) ('zg-lifecycle-model-'+[Guid]::NewGuid().ToString('N'))
  [IO.Directory]::CreateDirectory($work) | Out-Null
  $script:ZgData=Join-Path $work 'data'; $script:ZgBin=Join-Path $work 'bin'; $script:ZgManagement=Join-Path $work 'management'
  foreach ($path in @($ZgData,$ZgBin,$ZgManagement)) { [IO.Directory]::CreateDirectory($path) | Out-Null }
  $script:Id='fixture'; $script:ZgServiceName='ZunderGuard-fixture'; $script:ZgSid='fixture-service-sid'
  $script:ZgRoot=Join-Path $ZgData $Id; $script:ZgHome=Join-Path $ZgRoot 'runtime'; $script:ZgBinaryDir=Join-Path $ZgBin $Id
  $script:ZgExe=Join-Path $ZgBinaryDir 'zunder-guard.exe'; $script:ZgConfig=Join-Path $ZgHome 'guard.toml'; $script:ZgBinding=Join-Path $ZgRoot 'binding.json'; $script:ZgTransactionPath=Join-Path $ZgManagement 'fixture.json'
  $script:ConfirmAccount='0x1111111111111111111111111111111111111111'; $script:Licence=''; $script:Startup='DelayedAuto'
  $script:newImage='synthetic-version-A'; $script:trace=[Collections.Generic.List[string]]::new()
  $script:crashAfter=0; $script:writes=0; $script:initCalls=0; $script:pairingOutput=0; $script:provisionCalls=0; $script:licenceCalls=0; $script:startCalls=0
  $script:badCache=$false; $script:badCredential=$false; $script:badReadiness=$false; $script:running=$false; $script:startupMode='Disabled'
  $script:ZgTransaction=[pscustomobject]@{ schema=1; transaction='fixturetxn'; operation='install'; id=$Id; account=$ConfirmAccount; api_wallet=''; rules=''; cap='100'; new_hash=(Get-ZgTextHash $newImage); old_hash=''; old_binding_hash=''; config_hash=''; journal_hash=''; snapshot_captured=$false; runtime_attempted=$false; licence_hash=''; phase='install-planned'; startup_choice=''; readiness=$null }
}
function Remove-Case { if ($script:work -and [IO.Directory]::Exists($script:work)) { [IO.Directory]::Delete($script:work,$true) } }
# Every fresh phase can lose the process after persisting, then continue without
# regenerating any committed pairing or credential. Actual function body runs.
foreach ($cut in 1..10) {
  New-Case
  try {
    $script:crashAfter=$cut
    try { Complete-ZgPrepare } catch { if ($_.Exception.Message -notlike '*synthetic abrupt*') { throw } }
    if ([IO.File]::Exists($ZgTransactionPath)) { $script:ZgTransaction=[IO.File]::ReadAllText($ZgTransactionPath) | ConvertFrom-Json }
    $script:crashAfter=0; Complete-ZgPrepare
    Assert ($initCalls -eq 1 -and $pairingOutput -eq 1 -and $provisionCalls -eq 1) "fresh resume cut ${cut}: one init/pair/provision"
    Assert ($startCalls -eq 0 -and $startupMode -eq 'Disabled' -and $ZgTransaction.phase -eq 'admitted-disabled') "fresh resume cut $cut remains disabled"
  } finally { Remove-Case }
}
# Real upgrade state machine, interrupted after every durable phase.
foreach ($cut in 1..6) {
  New-Case
  try {
    Complete-ZgPrepare
    [IO.File]::WriteAllText((Join-Path $ZgHome 'risk-mainnet.jsonl'),'synthetic scoped journal preserve exactly')
    $configBefore=Get-ZgHash $ZgConfig; $journalBefore=Get-ZgJournalHash; $credentialBefore=Get-ZgHash (Join-Path $ZgRoot 'credential.dpapi')
    $ZgTransaction.operation='upgrade'; $ZgTransaction.old_hash=Get-ZgHash $ZgExe; $ZgTransaction.old_binding_hash=Get-ZgHash $ZgBinding
    $script:newImage='synthetic-version-B'; $ZgTransaction.new_hash=Get-ZgTextHash $newImage
    $script:startupMode='DelayedAuto'; $script:running=$true; $script:writes=0; $script:crashAfter=$cut
    try { Complete-ZgUpgrade } catch { if ($_.Exception.Message -notlike '*synthetic abrupt*') { throw } }
    $script:ZgTransaction=[IO.File]::ReadAllText($ZgTransactionPath) | ConvertFrom-Json
    # Reboot observation: disabled startup cannot implicitly create a new runtime.
    Assert ($startupMode -eq 'Disabled') "upgrade cut $cut disabled across interruption"
    $script:crashAfter=0; Complete-ZgUpgrade
    Assert ((Get-ZgHash $ZgConfig) -eq $configBefore -and (Get-ZgJournalHash) -eq $journalBefore -and (Get-ZgHash (Join-Path $ZgRoot 'credential.dpapi')) -eq $credentialBefore) "upgrade cut $cut preserves runtime state"
    Assert ($startCalls -eq 0 -and $initCalls -eq 1 -and $provisionCalls -eq 1) "upgrade cut $cut never restarts or reprovisions"
  } finally { Remove-Case }
}
New-Case
try {
  Complete-ZgPrepare; [IO.File]::WriteAllText((Join-Path $ZgHome 'risk-mainnet.jsonl'),'fixture journal')
  Complete-ZgStart
  Assert ($startCalls -eq 1 -and $startupMode -eq 'delayed-auto' -and $ZgTransaction.phase -eq 'activation-committed') 'explicit activation after readiness'
  Assert ($trace.IndexOf('durable-activation-committed') -lt $trace.IndexOf('startup-delayed-auto')) 'readiness commit precedes automatic startup'
  $script:Startup=''; Refuses { Complete-ZgStart } 'missing explicit startup choice refused'
  $script:Startup='Manual'; $script:badReadiness=$true
  Refuses { try { Complete-ZgStart } catch { Disable-ZgService; throw } } 'unready activation refused'
  Assert ($startupMode -eq 'Disabled' -and -not $running) 'unready activation disabled and stopped'
} finally { Remove-Case }
# Validation logic uses the real manifest parser and status predicate.
New-Case
try {
  $manifest=Join-Path $work 'SHA256SUMS'; $digest='a'*64
  [IO.File]::WriteAllText($manifest,"$digest  install-windows-service.ps1`n")
  Assert ((Get-ZgManifestHash $manifest 'install-windows-service.ps1') -ceq $digest) 'unique valid helper checksum'
  foreach ($body in @("$digest  install-windows-service.ps1`n$digest  install-windows-service.ps1`n","$digest  INSTALL-WINDOWS-SERVICE.PS1`n","bad  install-windows-service.ps1`n","$digest  ../install-windows-service.ps1`n")) {
    [IO.File]::WriteAllText($manifest,$body); Refuses { Get-ZgManifestHash $manifest 'install-windows-service.ps1' } 'duplicate/malformed/case/traversal checksums refused'
  }
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $status=[pscustomobject]@{schema=1;version='1.0.0';mode='mainnet';network='mainnet';account=$ConfirmAccount;killed=$null;risk=@{state='active';journal_ready=$true};equity_cap='100';last_sync_ms=$now;last_error=$null;started_at_ms=$now;licence=@{state='active'};fee=@{mode='fee_free'};journal_broken=$false}
  $null=Assert-ZgStatus $status $ConfirmAccount '100' $true ($now-1000); Assert $true 'current ready status accepted'
  foreach ($value in @($false,'latched')) { $status.killed=$value; Refuses { Assert-ZgStatus $status $ConfirmAccount '100' $true ($now-1000) } 'non-null killed field refused' }
  $status.PSObject.Properties.Remove('killed'); Refuses { Assert-ZgStatus $status $ConfirmAccount '100' $true ($now-1000) } 'missing killed field refused'
  # These flag guards run before any machine initialization or download boundary.
  foreach ($flags in @(@($true,$false,$false,''),@($false,$true,$false,''),@($false,$false,$true,''),@($false,$false,$false,'C:\per-user'))) {
    Refuses { Install-ZgMainnet '' '' '' '' '' 'fixture' 'v1.0.0' '' $flags[0] $flags[1] $flags[2] $flags[3] } 'mainnet incompatible flags refused before privilege'
  }
} finally { Remove-Case }

# Real signed-release validation, mocked only at the external verifier boundary.
New-Case
try {
  $cache=Join-Path $work 'release'; [IO.Directory]::CreateDirectory($cache) | Out-Null
  foreach ($name in @('cosign.exe','SHA256SUMS.sigstore.json','install-windows-service.ps1','zunder-guard-v1.0.0-windows-amd64.zip')) { [IO.File]::WriteAllText((Join-Path $cache $name),'synthetic asset') }
  $script:actualHash=$realHash; $script:badVerifier=$false; $script:verifierExit=0; $script:verifications=0
  function Get-ZgHash([string]$Path) {
    if ([IO.Path]::GetFileName($Path) -eq 'cosign.exe') { if ($script:badVerifier) { return '0'*64 }; return '9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be' }
    return & $script:actualHash $Path
  }
  function Invoke-ZgReleaseVerifier($Verifier,$Bundle,$Sums,$Identity) {
    if ($Identity -cne 'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/v1.0.0') { throw 'unexpected release identity' }
    $script:verifications++; return $script:verifierExit
  }
  $lines=@('install-windows-service.ps1','zunder-guard-v1.0.0-windows-amd64.zip') | ForEach-Object { (Get-ZgHash (Join-Path $cache $_))+'  '+$_ }
  [IO.File]::WriteAllLines((Join-Path $cache 'SHA256SUMS'),$lines)
  Confirm-ZgRelease $cache 'v1.0.0'; Assert ($verifications -eq 1) 'valid signature boundary and both signed assets accepted'
  $script:badVerifier=$true; Refuses { Confirm-ZgRelease $cache 'v1.0.0' } 'tampered verifier refused before execution'; Assert ($verifications -eq 1) 'tampered verifier never executed'
  $script:badVerifier=$false; $script:verifierExit=1; Refuses { Confirm-ZgRelease $cache 'v1.0.0' } 'failed signature refused'
  $script:verifierExit=0
  [IO.File]::AppendAllText((Join-Path $cache 'install-windows-service.ps1'),'tamper')
  Refuses { Confirm-ZgRelease $cache 'v1.0.0' } 'tampered signed helper refused'
  Refuses { Confirm-ZgRelease $cache 'v1.0.0-rc1' } 'nonstable release identity refused'
  Set-Item Function:Get-ZgHash $realHash
  # Mutants must be caught by independent state assertions, not by source matching.
  $mutant=[scriptblock]::Create($realPrepare.ToString().Replace("Invoke-ZgGuard $"+"words", "Invoke-ZgGuard $"+"words; Invoke-ZgGuard $"+"words"))
  Refuses { & $mutant } 'repeated init mutation caught by fixture pairing invariant'
} finally { Set-Item Function:Get-ZgHash $realHash; Remove-Case }
# Archive member refusal executes the actual extraction predicate before any binary.
# Windows PowerShell 5.1 does not preload ZipFile for this synthetic archive fixture.
[Reflection.Assembly]::Load('System.IO.Compression.FileSystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089') | Microsoft.PowerShell.Core\Out-Null
New-Case
try {
  $script:ZgTransaction | Add-Member release $work
  $script:ZgTransaction | Add-Member tag 'v1.0.0'
  foreach ($entries in @(@('../zunder-guard.exe'),@('zunder-guard.exe','ZUNDER-GUARD.EXE'),@('zunder-guard.exe'))) {
    $zip=Join-Path $work 'zunder-guard-v1.0.0-windows-amd64.zip'
    if ([IO.File]::Exists($zip)) { [IO.File]::Delete($zip) }
    $archive=[IO.Compression.ZipFile]::Open($zip,[IO.Compression.ZipArchiveMode]::Create)
    try { foreach ($name in $entries) { $entry=$archive.CreateEntry($name); $writer=[IO.StreamWriter]::new($entry.Open()); try { $writer.Write('synthetic nonexecutable fixture') } finally { $writer.Dispose() } } } finally { $archive.Dispose() }
    $message=''; try { & $realImage | Out-Null } catch { $message=$_.Exception.Message }
    Assert ($message -in @('Unsafe, repeated or unexpected archive member.','Required executable or notice missing.')) 'traversal/collision/missing notices rejected by archive validation before execution'
  }
} finally { Remove-Case }


# Public journey: missing public fields prompt, confirmation is never inferred,
# and a completed/pending installation cannot be silently replaced or restarted.
New-Case
$oldVerifier=$env:ZUNDER_GUARD_COSIGN
try {
  $env:ZUNDER_GUARD_COSIGN=$null
  function Initialize-ZgMachineContext { $script:ZgPowerShell='fixture-never-executed' }
  function Assert-ZgInteractiveConsole {}
  function Read-ZgPublicPrompt($Message) { $script:prompts.Add($Message); if ($script:answers.Count -eq 0) { throw 'fixture EOF' }; return $script:answers.Dequeue() }
  function Get-ZgAsset($Source,$Name,$Destination) { [IO.File]::WriteAllText($Destination,'synthetic verified asset') }
  function Confirm-ZgRelease($Directory,$Tag) { if ($script:badCache) { throw 'synthetic signature rejection' } }
  function Invoke-ZgLifecycleHelper([string[]]$Words) { $script:helperCalls++; $script:helperWords=$Words }
  $script:helperCalls=0; $script:prompts=[Collections.Generic.List[string]]::new(); $script:answers=[Collections.Generic.Queue[string]]::new()
  foreach ($answer in @($ConfirmAccount,$ConfirmAccount,'100')) { $answers.Enqueue($answer) }
  Install-ZgMainnet '' '' '' '' '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false ''
  Assert ($prompts.Count -eq 3 -and $helperCalls -eq 1) 'fresh loader prompts account repeated consent and cap'
  Assert ($helperWords[$helperWords.IndexOf('-ExecutionPolicy')+1] -eq 'Bypass') 'verified helper invocation uses per-process policy only'
  Assert ($helperWords[$helperWords.IndexOf('-Action')+1] -eq 'Prepare' -and $helperWords[$helperWords.IndexOf('-ConfirmAccount')+1] -ceq $ConfirmAccount) 'fresh helper gets explicit confirmation unchanged'
  $cache=$helperWords[$helperWords.IndexOf('-ReleaseDir')+1]
  $script:ZgTransactionPath=Join-Path (Join-Path $ZgData 'management') 'fixture.json'
  $script:helperCalls=0; $script:running=$true
  $prior=[pscustomobject]@{schema=1;id='fixture';account=$ConfirmAccount;phase='activation-committed';tag='v1.0.0';release=$cache}
  [IO.File]::WriteAllText($ZgTransactionPath,($prior|ConvertTo-Json))
  Install-ZgMainnet '' $ConfirmAccount $ConfirmAccount '100' '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false ''
  Assert ($helperCalls -eq 0 -and $running) 'completed loader only stages explicit upgrade and leaves service untouched'
  $prior.phase='credential-provisioning'; $prior.tag='v0.9.0'; [IO.File]::WriteAllText($ZgTransactionPath,($prior|ConvertTo-Json))
  Refuses { Install-ZgMainnet '' $ConfirmAccount $ConfirmAccount '100' '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false '' } 'pending different release refused'
  Assert ($helperCalls -eq 0 -and $running) 'pending mismatch never invokes helper or mutates service'
  $prior.tag='v1.0.0'; [IO.File]::WriteAllText($ZgTransactionPath,($prior|ConvertTo-Json))
  Install-ZgMainnet '' $ConfirmAccount $ConfirmAccount '100' '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false ''
  Assert ($helperCalls -eq 1 -and $helperWords[$helperWords.IndexOf('-Action')+1] -eq 'Resume') 'matching pending release resumes exact helper'
  $script:helperCalls=0
  Refuses { Install-ZgMainnet '' $ConfirmAccount '' '100' '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false '' } 'EOF never synthesizes repeated consent'
  Refuses { Install-ZgMainnet '' $ConfirmAccount ('0x'+'2'*40) '100' '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false '' } 'different account confirmation refused'
  foreach ($cap in @('0','2501','NaN','1e3')) { Refuses { Install-ZgMainnet '' $ConfirmAccount $ConfirmAccount $cap '' 'fixture' 'v1.0.0' 'https://invalid.example' $false $false $false '' } 'invalid cap refused' }
  Assert ($helperCalls -eq 0) 'failed public consent/cap never reaches helper'
} finally { $env:ZUNDER_GUARD_COSIGN=$oldVerifier; Remove-Case }



# WIN-C2: real status predicate distinguishes service admission from fee readiness.
New-Case
try {
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $status=[pscustomobject]@{schema=1;version='1.0.0';mode='mainnet';network='mainnet';account=$ConfirmAccount;killed=$null;risk=@{state='active';journal_ready=$true};equity_cap='100';last_sync_ms=$now;last_error=$null;started_at_ms=$now;licence=@{state='none'};fee=$null;journal_broken=$false}
  foreach ($approval in @('unchecked','approved','not_approved','refused_by_venue','refused_by_venue_builder')) {
    $status.fee=[pscustomobject]@{mode='builder';approval=[pscustomobject]@{state=$approval};entries_blocked=($approval -ne 'approved');charged=($approval -eq 'approved');paper=$false}
    $ready=Assert-ZgStatus $status $ConfirmAccount '100' $false ($now-1000)
    Assert ($ready.approval -ceq $approval -and $ready.trading_ready -eq ($approval -eq 'approved')) ('actual approval variant retained: '+$approval)
    $output=Write-ZgActivationOutcome $ready 6>&1 | Out-String
    if ($approval -eq 'approved') { Assert ($output -match 'trading-ready') 'approved builder reports trading ready' }
    else { Assert ($output -match 'https://zunderlabs.com/approve' -and $output -match 'main wallet' -and $output -notmatch 'trading-ready') 'blocked builder directs explicit Mainnet wallet approval without readiness claim' }
  }
  foreach ($bad in @([pscustomobject]@{mode='builder'},[pscustomobject]@{mode='builder';approval=[pscustomobject]@{state='unsupported'}},[pscustomobject]@{mode='unknown'})) {
    $status.fee=$bad; Refuses { Assert-ZgStatus $status $ConfirmAccount '100' $false ($now-1000) } 'missing or unknown fee/approval rejected'
  }
  $status.fee=[pscustomobject]@{mode='builder';approval=[pscustomobject]@{state='approved'};entries_blocked=$true;charged=$true;paper=$false}
  $ready=Assert-ZgStatus $status $ConfirmAccount '100' $false ($now-1000)
  Assert (-not $ready.trading_ready) 'approved but blocked builder never trading ready'
  $status.fee=[pscustomobject]@{mode='fee_free'}
  Refuses { Assert-ZgStatus $status $ConfirmAccount '100' $false ($now-1000) } 'fee-free status without active licence rejected'
  $status.licence.state='active'
  $ready=Assert-ZgStatus $status $ConfirmAccount '100' $true ($now-1000)
  Assert ($ready.trading_ready -and $ready.approval -eq 'not_required') 'valid active fee-free licence trading ready'
} finally { Remove-Case }
# WIN-L1: a structurally valid but altered retained binding cannot be promoted.
New-Case
try {
  Complete-ZgPrepare
  $ZgTransaction.operation='upgrade'; $ZgTransaction.old_hash=Get-ZgHash $ZgExe; $ZgTransaction.old_binding_hash=Get-ZgHash $ZgBinding
  $script:newImage='synthetic-version-B'; $ZgTransaction.new_hash=Get-ZgTextHash $newImage
  $backup=Join-Path $ZgManagement ($Id+'-'+$ZgTransaction.transaction+'-previous.json')
  $altered=[IO.File]::ReadAllText($ZgBinding) | ConvertFrom-Json; $altered.api_wallet='0x4444444444444444444444444444444444444444'
  [IO.File]::WriteAllText($backup,($altered | ConvertTo-Json -Depth 12)); $trace.Clear()
  $failure=''; try { Complete-ZgUpgrade } catch { $failure=$_.Exception.Message }
  Assert ($failure -eq 'Old binding backup changed.') 'modified valid-JSON binding backup refused'
  Assert (-not $trace.Contains('image-promoted') -and (Get-ZgHash $ZgExe) -ceq $ZgTransaction.old_hash) 'binding backup refusal happens before new image promotion'
} finally { Remove-Case }

# WIN-C1: run the real dispatch/catch, not only Complete-* functions. Validation
# refusals and read-only Status must not disable an existing or unmanaged service.
New-Case
try {
  $script:ReleaseDir=Join-Path $work 'release'; [IO.Directory]::CreateDirectory($ReleaseDir) | Out-Null
  $script:Tag='v1.0.0'; $script:Account=$ConfirmAccount; $script:EquityCap='100'; $script:Rules=''; $script:Note=''; $script:Recovery=''
  $script:ZgManagement=Join-Path $ZgData 'management'; [IO.Directory]::CreateDirectory($ZgManagement) | Out-Null
  $script:ZgTransactionPath=Join-Path $ZgManagement 'fixture.json'
  $helperHash=Get-ZgHash $PSCommandPath
  $script:entryHelperDigest=$helperHash
  # AST-extracted functions lack a script filename; stand in only for their
  # own admitted helper hash, keeping all dispatch/cleanup decisions real.
  function Get-ZgHash([string]$Path) { if (-not $Path) { return $script:entryHelperDigest }; return & $realHash $Path }
  function Entry-Refuses([scriptblock]$Code,[string]$Expected,[string]$Name) { $message=''; try { & $Code | Out-Null } catch { $message=$_.Exception.Message }; Assert ($message -like $Expected) ($Name+': '+$message) }
  [IO.File]::WriteAllText((Join-Path $ReleaseDir 'SHA256SUMS'),$helperHash+'  install-windows-service.ps1')
  $prior=[pscustomobject]@{schema=1;id=$Id;service=$ZgServiceName;root=$ZgRoot;exe=$ZgExe;binding=$ZgBinding;account=$ConfirmAccount;tag=$Tag;phase='activation-committed';operation='install';helper_hash=$helperHash;release=$ReleaseDir}
  [IO.File]::WriteAllText($ZgTransactionPath,($prior|ConvertTo-Json))
  $script:disableCalls=0; $script:running=$true; $script:startupMode='DelayedAuto'
  function Get-ZgService { $script:ZgSid='fixture-service-sid'; return [pscustomobject]@{StartMode=$startupMode;State=$(if ($running) {'Running'} else {'Stopped'})} }
  function Disable-ZgService { $script:disableCalls++; $script:running=$false; $script:startupMode='Disabled' }
  $script:Action='Prepare'
  Entry-Refuses { Invoke-ZgLifecycle } 'Instance already exists.*' 'repeated direct Prepare rejected'
  Assert ($disableCalls -eq 0 -and $running -and $startupMode -eq 'DelayedAuto') 'rejected Prepare retains existing owned running service'
  $script:Action='Status'; $script:badCache=$true
  Entry-Refuses { Invoke-ZgLifecycle } 'synthetic signature rejection' 'Status signature/cache failure rejected'
  Assert ($disableCalls -eq 0 -and $running) 'read-only Status failure cannot stop service'
  $script:badCache=$false
  [IO.File]::Delete($ZgTransactionPath); $script:Action='Prepare'
  Entry-Refuses { Invoke-ZgLifecycle } 'Instance already exists.*' 'unmanaged matching SCM registration not adopted'
  Assert ($disableCalls -eq 0 -and $running) 'unmanaged matching service never disabled by rejected Prepare'
  $script:Action='Status'
  Entry-Refuses { Invoke-ZgLifecycle } 'No owned transaction.*' 'unmanaged Status refuses absent transaction'
  Assert ($disableCalls -eq 0 -and $running) 'unmanaged Status cannot disable matching registration'
  $prior.phase='config-preparing'; [IO.File]::WriteAllText($ZgTransactionPath,($prior|ConvertTo-Json))
  $script:Action='Resume'; $script:ConfirmAccount='0x3333333333333333333333333333333333333333'
  Entry-Refuses { Invoke-ZgLifecycle } 'Transaction account differs from explicit confirmation.' 'wrong account Resume refused before cleanup admission'
  Assert ($disableCalls -eq 0 -and $running) 'invalid consent cannot disable owned service'
  $script:ConfirmAccount=$Account
  $script:Action='JournalInit'; $script:Note=''
  Entry-Refuses { Invoke-ZgLifecycle } 'Explicit human review note required.' 'missing journal review note refuses before stop'
  Assert ($disableCalls -eq 0 -and $running) 'missing journal note cannot stop owned service'
  [IO.Directory]::CreateDirectory($ZgHome) | Out-Null
  [IO.File]::WriteAllText((Join-Path $ZgHome 'risk-mainnet.jsonl'),'fixture journal')
  $script:Note='fixture human review'
  Entry-Refuses { Invoke-ZgLifecycle } 'Existing journal is never initialized again*' 'existing journal refuses before stop'
  Assert ($disableCalls -eq 0 -and $running) 'existing journal refusal cannot stop owned service'
  $script:Action='Recover'; $script:Recovery=''
  Entry-Refuses { Invoke-ZgLifecycle } 'Image rollback requires explicit pre-start upgrade recovery*' 'invalid recovery choice refuses before stop'
  Assert ($disableCalls -eq 0 -and $running) 'invalid recovery choice cannot stop owned service'
  $script:Action='Resume'
  function Complete-ZgPrepare { throw 'synthetic failure AFTER owned mutating phase admission' }
  $entryFailure=''; try { Invoke-ZgLifecycle } catch { $entryFailure=$_.Exception.Message }; Assert ($entryFailure -eq 'synthetic failure AFTER owned mutating phase admission') ('admitted mutation failure propagates: '+$entryFailure)
  Assert ($disableCalls -ge 2 -and -not $running -and $startupMode -eq 'Disabled') 'admitted mutation failure retains disabled cleanup'
} finally { Remove-Case }

Write-Host "Windows mainnet synthetic lifecycle: $tests assertions passed. Native ACL/signature/SCM/reboot proof remains separate."
