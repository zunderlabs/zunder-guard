# Disposable hosted Windows runner only. Exercises production broker/DPAPI/ACL/Job
# code with a non-shipped fixture binary that cannot start Guard or contact a venue.
[CmdletBinding(DefaultParameterSetName='Lifecycle')]
param(
  [Parameter(Mandatory,ParameterSetName='Lifecycle')][string]$Fixture,
  [Parameter(Mandatory,ParameterSetName='PolicyOnly')][switch]$DiagnosticsOnly,
  [Parameter(Mandatory)][string]$PolicyDiagnostic,
  [Parameter(ParameterSetName='Lifecycle')][switch]$ObservePolicyRefusal
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted native CI only.' }
$Principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated runner required.' }
# Read-only metadata for exactly the four Registry64 keys admission checks.
# Never inspect values/subkeys or print exception text. HKCU here is the elevated
# runner's hive; this is not a claim about the virtual service account's hive.
$PolicyPaths = @(
  'SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps',
  'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
)
$PolicyRows = @(
  foreach ($Hive in @([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryHive]::CurrentUser)) {
    foreach ($PolicyPath in $PolicyPaths) {
      $BaseKey = $null
      $PolicyKey = $null
      $State = 'unreadable'
      try {
        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, [Microsoft.Win32.RegistryView]::Registry64)
        $PolicyKey = $BaseKey.OpenSubKey($PolicyPath, $false)
        # OpenSubKey can return null for errors too; this does not prove absence.
        $State = if ($null -eq $PolicyKey) { 'absent-or-unreadable' } else { 'present' }
      } catch {
        $State = 'unreadable'
      } finally {
        if ($null -ne $PolicyKey) { $PolicyKey.Dispose() }
        if ($null -ne $BaseKey) { $BaseKey.Dispose() }
      }
      [ordered]@{ hive = $Hive.ToString(); path = $PolicyPath; view = 'Registry64'; status = $State }
    }
  }
)
$PolicyJson = [ordered]@{
  version = 1
  scope = 'read-only key existence; elevated runner identity; not readiness evidence'
  keys = $PolicyRows
} | ConvertTo-Json -Depth 4
if ($PolicyRows.Count -ne 4 -or $PolicyJson.Length -gt 4096) { throw 'Invalid policy diagnostic shape.' }
[IO.File]::WriteAllText($PolicyDiagnostic, $PolicyJson, [Text.UTF8Encoding]::new($false))
# Parameter-set selection guarantees PolicyOnly cannot fall through, even with
# an explicitly false switch value. Metadata is not a readiness verdict.
if ($PSCmdlet.ParameterSetName -eq 'PolicyOnly') { return }
# Continue unchanged: production admission must still refuse any present policy.
$Id = 'ci-' + [Guid]::NewGuid().ToString('N')
$Name = "ZunderGuard-$Id"
$DataBase = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ZunderGuard'
$BinBase = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ZunderGuard'
$Root = Join-Path $DataBase $Id
$Runtime = Join-Path $Root 'runtime'
$Bin = Join-Path $BinBase $Id
$Exe = Join-Path $Bin 'zunder-guard.exe'
$Binding = Join-Path $Root 'binding.json'
$Log = Join-Path $Runtime 'lifecycle.log'
$Sc = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\sc.exe'
$Wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
$Sid = $null
$CreatedBases = @()
$PreviousWer = $null
$HadWer = $false
$WerChanged = $false
$ScSource = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../windows/service.ps1'))
$ScTokens = $null; $ScErrors = $null
$ScAst = [System.Management.Automation.Language.Parser]::ParseFile($ScSource,[ref]$ScTokens,[ref]$ScErrors)
if ($ScErrors.Count) { throw 'Production SCM helper parse failure.' }
foreach ($FunctionName in @('ConvertTo-ZgNativeArgument','Invoke-ZgSc')) {
  $Nodes = @($ScAst.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $FunctionName },$true))
  if ($Nodes.Count -ne 1) { throw 'Production SCM function missing or duplicated.' }
  Invoke-Expression $Nodes[0].Extent.Text
}
$script:ZgSc = $Sc
function Invoke-Sc([string[]]$Words) { Invoke-ZgSc $Words }
$Admission = [ordered]@{version=1;invocation_id=[Guid]::NewGuid().ToString('N');started_utc=[DateTimeOffset]::UtcNow.ToString('o');finished_utc=$null;result='pending';positive_lifecycle_verified=$false;cleanup_complete=$false;releaseReady=$false;powershell=$PSVersionTable.PSVersion.ToString();source_helper_sha256=(Get-FileHash -LiteralPath $ScSource -Algorithm SHA256).Hash.ToLowerInvariant();fixture_sha256=(Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash.ToLowerInvariant();harness_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()}
$Admission | ConvertTo-Json | Set-Content -LiteralPath ($PolicyDiagnostic+'.admission.json') -Encoding UTF8
function Assert-SyntheticPolicyRefusal([string]$Executable) {
  # Only the public fixture runs here; no configuration, credential or venue request.
  $info = [Diagnostics.ProcessStartInfo]::new()
  $info.FileName = $Executable
  $info.Arguments = 'prepare-fixture'
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $info
  $started = $false
  $clock = [Diagnostics.Stopwatch]::StartNew()
  try {
    $started = $process.Start()
    if (-not $started) { throw 'Policy-refusal fixture could not start.' }
    $streams = @(
      @{reader=$process.StandardOutput;buffer=[char[]]::new(513);text=[Text.StringBuilder]::new()},
      @{reader=$process.StandardError;buffer=[char[]]::new(513);text=[Text.StringBuilder]::new()}
    )
    foreach ($stream in $streams) { $stream.task=$stream.reader.ReadAsync($stream.buffer,0,513) }
    if (-not $process.WaitForExit(10000)) { throw 'Policy-refusal fixture timed out.' }
    foreach ($stream in $streams) {
      do {
        $remaining = 12000 - [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $stream.task.Wait($remaining)) { throw 'Policy-refusal output timed out.' }
        $count = $stream.task.Result
        if ($stream.text.Length + $count -gt 512) { throw 'Oversized policy-refusal fixture output.' }
        if ($count -gt 0) {
          $null = $stream.text.Append($stream.buffer,0,$count)
          $stream.task = $stream.reader.ReadAsync($stream.buffer,0,513-$stream.text.Length)
        }
      } while ($count -gt 0)
    }
    if ($process.ExitCode -ne 1 -or $streams[0].text.Length -ne 0 -or $streams[1].text.ToString().Trim() -cne 'Error: service refused: managed WER or LocalDumps policy prevents service secret admission') {
      throw 'Fixture did not refuse the observed crash policy at secret admission.'
    }
  } finally {
    try {
      if ($started -and -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'Policy-refusal fixture cleanup failed.' }
      }
    } finally { $process.Dispose() }
  }
}
function Set-FixtureAcl([string]$Path, [bool]$Writable = $false, [bool]$Public = $false) {
  $Item = Get-Item -LiteralPath $Path -Force
  if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse fixture refused.' }
  $Acl = if ($Item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $Acl.SetAccessRuleProtection($true,$false)
  $Acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $Inheritance = if ($Item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($Owner in @('S-1-5-18','S-1-5-32-544')) { $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Owner),'FullControl',$Inheritance,'None','Allow')) }
  $Reader = if ($Public) { 'S-1-5-11' } else { $script:Sid }
  if ($Reader) {
    $Rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }
    $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Reader),$Rights,$Inheritance,'None','Allow'))
  }
  Set-Acl -LiteralPath $Path -AclObject $Acl
}
function Wait-Started([int]$Count) {
  $Deadline = [DateTime]::UtcNow.AddSeconds(45)
  do {
    $Lines = @(if (Test-Path -LiteralPath $Log) { Get-Content -LiteralPath $Log | Where-Object { $_ -match '^started \d+$' } })
    if ($Lines.Count -ge $Count) { return [int]($Lines[-1] -split ' ')[1] }
    Start-Sleep -Milliseconds 100
  } while ([DateTime]::UtcNow -lt $Deadline)
  throw 'Synthetic runtime did not start; SCM or credential admission failed.'
}
function Stop-Fixture {
  $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($Service -and $Service.Status -ne 'Stopped') { Stop-Service -Name $Name; $Service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35)) }
}
function Assert-NoProcess([int]$ProcessId) {
  $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if ($Process) { $Process | Wait-Process -Timeout 10 }
  if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) { throw 'Synthetic child survived broker shutdown.' }
}
try {
  foreach ($Base in @($DataBase,$BinBase)) {
    if (Test-Path -LiteralPath $Base) { throw 'Native fixture needs a clean disposable runner application namespace.' }
    New-Item -ItemType Directory -Path $Base | Out-Null; $CreatedBases += $Base; Set-FixtureAcl $Base $false $true
  }
  foreach ($Path in @($Root,$Runtime,$Bin)) { New-Item -ItemType Directory -Path $Path | Out-Null; Set-FixtureAcl $Path }
  Copy-Item -LiteralPath $Fixture -Destination $Exe
  $ImagePath = '"' + $Exe + '" service run --binding "' + $Binding + '"'
  Invoke-Sc @('create',$Name,'binPath=',$ImagePath,'start=','demand','obj=',"NT SERVICE\$Name")
  $Registered = Get-CimInstance Win32_Service -Filter "Name='$Name'"
  if ($Registered.PathName -cne $ImagePath -or $Registered.StartName -cne "NT SERVICE\$Name") { throw 'SCM registration changed quoted executable/binding or virtual identity.' }
  $Sid = ([Security.Principal.NTAccount]::new("NT SERVICE\$Name")).Translate([Security.Principal.SecurityIdentifier]).Value
  foreach ($Path in @($Root,$Bin,$Exe)) { Set-FixtureAcl $Path }
  Set-FixtureAcl $Runtime $true
  New-Item -Path $Wer -Force | Out-Null
  $WerKey = Get-Item -LiteralPath $Wer
  try {
    if ($WerKey.GetValueNames() -contains 'zunder-guard.exe') {
      if ($WerKey.GetValueKind('zunder-guard.exe') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'Existing WER exclusion type refused before mutation.' }
      $PreviousWer = $WerKey.GetValue('zunder-guard.exe'); $HadWer = $true
    }
  } finally { $WerKey.Dispose() }
  $WerChanged = $true
  New-ItemProperty -LiteralPath $Wer -Name 'zunder-guard.exe' -Value 1 -PropertyType DWord -Force | Out-Null
  if ($ObservePolicyRefusal -and @($PolicyRows | Where-Object { $_.status -eq 'present' }).Count -gt 0) {
    Assert-SyntheticPolicyRefusal $Exe
    $Admission.result='expected-policy-refusal'
    Write-Host 'Observed crash policy correctly refused before fixture credential admission; positive SCM lifecycle remains pending on this host.'
    return
  }
  $Json = & $Exe prepare-fixture --id $Id --home $Runtime --service-name $Name --service-sid $Sid
  if ($LASTEXITCODE) { throw 'Synthetic fixture preparation failed.' }
  [IO.File]::WriteAllText($Binding,($Json -join "`n"),[Text.UTF8Encoding]::new($false)); Set-FixtureAcl $Binding
  Set-FixtureAcl (Join-Path $Runtime 'guard.toml') $true
  Set-FixtureAcl (Join-Path $Runtime 'risk-mainnet.jsonl') $true
  $Credential = Join-Path $Root 'credential.dpapi'; [IO.File]::WriteAllBytes($Credential,[byte[]]@()); Set-FixtureAcl $Credential
  & $Exe service provision --binding $Binding; if ($LASTEXITCODE) { throw 'Synthetic machine credential provision failed.' }
  Invoke-Sc @('failure',$Name,'reset=','86400','actions=','restart/1000/restart/1000/restart/1000')
  Invoke-Sc @('failureflag',$Name,'0')
  Invoke-Sc @('start',$Name); $First = Wait-Started 1
  Stop-Fixture; Assert-NoProcess $First
  if (-not ((Get-Content -LiteralPath $Log) -contains "stopped $First")) { throw 'Normal SCM stop did not reach stdin EOF cleanup.' }
  Start-Sleep -Seconds 2
  if ((Get-Service -Name $Name).Status -ne 'Stopped') { throw 'Intentional stop unexpectedly restarted.' }
  Invoke-Sc @('start',$Name); $Second = Wait-Started 2
  $Broker = Get-CimInstance Win32_Service -Filter "Name='$Name'"
  if ($Broker.StartName -ne "NT SERVICE\$Name" -or $Broker.ProcessId -eq 0) { throw 'SCM virtual-account broker identity mismatch.' }
  Stop-Process -Id $Broker.ProcessId -Force
  Assert-NoProcess $Second
  $Third = Wait-Started 3
  Stop-Fixture; Assert-NoProcess $Third
  [IO.File]::WriteAllText((Join-Path $Runtime 'fixture-transient-count'),'4'); Set-FixtureAcl (Join-Path $Runtime 'fixture-transient-count') $true
  [IO.File]::WriteAllText((Join-Path $Runtime 'fixture-renew'),'synthetic only'); Set-FixtureAcl (Join-Path $Runtime 'fixture-renew') $true
  Invoke-Sc @('start',$Name); $Fourth = Wait-Started 4
  if ((Get-Content -LiteralPath (Join-Path $Runtime 'fixture-transient-count') -Raw).Trim() -ne '0') { throw 'SCM did not continue transient recovery past the third attempt.' }
  & $Exe service check --binding $Binding; if ($LASTEXITCODE) { throw 'Administrator lost config access after service-owned renewal.' }
  if ((Get-Content -LiteralPath (Join-Path $Runtime 'guard.toml') -Raw) -notmatch 'synthetic-renewed-fixture') { throw 'Service-owned renewal fixture did not update config.' }
  Stop-Fixture; Assert-NoProcess $Fourth
  # An accepted Stop must win even when the child independently exits 75.
  $StopRace = Join-Path $Runtime 'fixture-stop-transient'
  $ReleaseExit = Join-Path $Runtime 'fixture-exit-now'
  [IO.File]::WriteAllText($StopRace,'synthetic only'); Set-FixtureAcl $StopRace $true
  Invoke-Sc @('start',$Name); $Fifth = Wait-Started 5
  Invoke-Sc @('stop',$Name) # returns after the handler acknowledges stop intent
  [IO.File]::WriteAllText($ReleaseExit,'exit 75 now'); Set-FixtureAcl $ReleaseExit $true
  (Get-Service -Name $Name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35))
  Assert-NoProcess $Fifth
  if (-not ((Get-Content -LiteralPath $Log) -contains "transient-after-stop $Fifth")) { throw 'Synthetic child did not take the requested concurrent transient-exit path.' }
  Start-Sleep -Seconds 3 # exceeds the fixture's one-second recovery action
  if ((Get-Service -Name $Name).Status -ne 'Stopped') { throw 'Accepted Stop was overridden by transient recovery.' }
  $Starts = @(Get-Content -LiteralPath $Log | Where-Object { $_ -match '^started \d+$' })
  if ($Starts.Count -ne 5) { throw 'An extra broker restarted after accepted Stop.' }
  Remove-Item -LiteralPath $StopRace,$ReleaseExit
  # Crash the synthetic runtime while its public dummy key is resident.
  # Admission already refuses HKLM/HKCU LocalDumps and managed WER policies.
  $DumpRoots = @((Join-Path $env:ProgramData 'Microsoft\Windows\WER'),(Join-Path $env:LOCALAPPDATA 'CrashDumps'),(Join-Path $env:SystemRoot 'ServiceProfiles'),(Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\CrashDumps'))
  function Dump-Paths {
    @($DumpRoots | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Get-ChildItem -LiteralPath $_ -File -Recurse -Force -ErrorAction Stop } | Where-Object { $_.Extension -in @('.dmp','.mdmp','.hdmp') } | ForEach-Object FullName)
  }
  $BeforeDumps = @(Dump-Paths)
  [IO.File]::WriteAllText((Join-Path $Runtime 'fixture-crash'),'synthetic only'); Set-FixtureAcl (Join-Path $Runtime 'fixture-crash') $true
  Invoke-Sc @('start',$Name)
  (Get-Service -Name $Name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35))
  Start-Sleep -Seconds 5
  $NewDumps = @(Dump-Paths | Where-Object { $_ -notin $BeforeDumps })
  if ($NewDumps.Count) { throw 'Synthetic credential runtime crash created a dump artifact.' }
  & $Exe service remove-credential --binding $Binding; if ($LASTEXITCODE) { throw 'Stopped credential removal failed.' }
  if (Test-Path -LiteralPath $Credential) { throw 'Encrypted fixture credential remains.' }
  $Admission.result='positive-synthetic-lifecycle'; $Admission.positive_lifecycle_verified=$true
  Write-Host 'Native SCM virtual identity, machine decryption, stdin stop, broker death containment, four transient retries, accepted Stop versus transient exit, renewal/admin ACL, bounded WER dump scan after synthetic runtime crash and credential cleanup passed.'
} finally {
  Stop-Fixture
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { Invoke-Sc @('delete',$Name) }
  foreach ($Path in @($Root,$Bin)) { if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force } }
  foreach ($Path in $CreatedBases) { if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force } }
  if ($WerChanged) {
    if ($HadWer) {
      New-ItemProperty -LiteralPath $Wer -Name 'zunder-guard.exe' -Value $PreviousWer -PropertyType DWord -Force | Out-Null
      $Restored = Get-Item -LiteralPath $Wer
      if ($Restored.GetValueKind('zunder-guard.exe') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or $Restored.GetValue('zunder-guard.exe') -ne $PreviousWer) { throw 'WER exclusion restoration differs.' }
    } else {
      Remove-ItemProperty -LiteralPath $Wer -Name 'zunder-guard.exe' -ErrorAction Stop
      if ((Get-Item -LiteralPath $Wer).GetValueNames() -contains 'zunder-guard.exe') { throw 'WER exclusion remains after cleanup.' }
    }
  }
  $Admission.cleanup_complete=$true; $Admission.finished_utc=[DateTimeOffset]::UtcNow.ToString('o')
  $Admission | ConvertTo-Json | Set-Content -LiteralPath ($PolicyDiagnostic+'.admission.json') -Encoding UTF8

}
