# Hosted phase-zero wrapper. Fixed OS compiler; no raw compiler/native output is published.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$core = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll'
$system = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll'
$work = $null
$workOwned = $false
$failure = 'PREREQUISITE'
$native = $null
$nativeCode = $null
$compilerHash = $null
$coreHash = $null
$systemHash = $null
$helperHash = $null
$gateHash = $null
$sourceHash = $null
$gateSourceHash = $null
$fixtureHash = $null
$fixtureCount = 0
$executed = $false
$buildCleanup = 'UNKNOWN'
function Check-Path([string]$Path) {
  if ($Path -notmatch '^[CD]:\\[a-zA-Z0-9_.\\ -]{1,220}$') { throw 'Closed path refused.' }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse input refused.' }
  for ($dir = $item.Directory; $null -ne $dir; $dir = $dir.Parent) {
    if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse parent refused.' }
  }
  if ($item -isnot [IO.FileInfo] -or $item.Length -le 0 -or $item.Length -gt 16777216) { throw 'Bounded regular input required.' }
}
function Digest([string]$Path) { Check-Path $Path; return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Run-Fixed([string]$ExePath, [string]$Arguments, [int]$BoundMs) {
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName = $ExePath
  $info.Arguments = $Arguments
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.WorkingDirectory = $work
  $info.EnvironmentVariables.Clear()
  $info.EnvironmentVariables['SystemRoot'] = 'C:\Windows'
  $info.EnvironmentVariables['WINDIR'] = 'C:\Windows'
  $info.EnvironmentVariables['PATH'] = 'C:\Windows\System32'
  $info.EnvironmentVariables['TEMP'] = $work
  $info.EnvironmentVariables['TMP'] = $work
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $info
  try {
    if (-not $process.Start()) { throw 'Fixed process could not start.' }
    if ($ExePath -ceq $helper) { $script:executed = $true }
    $output = $process.StandardOutput.ReadToEndAsync()
    $errorOutput = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($BoundMs)) {
      # This direct process handle is owned. No PID lookup or foreign kill is used.
      $process.Kill()
      if (-not $process.WaitForExit(10000)) { throw 'Owned process termination unknown.' }
      throw 'Bounded process timed out.'
    }
    $text = $output.GetAwaiter().GetResult()
    $null = $errorOutput.GetAwaiter().GetResult()
    if ($text.Length -gt 16384) { throw 'Bounded report refused.' }
    return @{ code = $process.ExitCode; text = $text }
  } finally { $process.Dispose() }
}
try {
  if ($env:RUNNER_TEMP -notin @('D:\a\_temp', 'C:\a\_temp')) { throw 'Hosted temporary root refused.' }
  $source = Join-Path $PSScriptRoot 'PhaseZero.cs'
  $gateSource = Join-Path $PSScriptRoot 'ReportGate.cs'
  $compilerHash = Digest $csc; $coreHash = Digest $core; $systemHash = Digest $system
  $sourceHash = Digest $source; $gateSourceHash = Digest $gateSource
  $fixtureFile = Join-Path $PSScriptRoot 'report-gate-fixtures.json'
  $fixtureHash = Digest $fixtureFile
  $tempRoot = Get-Item -LiteralPath $env:RUNNER_TEMP -Force
  if ($tempRoot -isnot [IO.DirectoryInfo]) { throw 'Hosted temporary directory refused.' }
  for ($dir = $tempRoot; $null -ne $dir; $dir = $dir.Parent) {
    if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Hosted temporary ancestor refused.' }
  }
  $work = Join-Path $env:RUNNER_TEMP 'zunder-windows-native-phase-zero'
  if (Test-Path -LiteralPath $work) { throw 'Pre-existing build directory refused.' }
  $null = [IO.Directory]::CreateDirectory($work)
  $workOwned = $true
  $helper = Join-Path $work 'PhaseZero.exe'
  $gate = Join-Path $work 'ReportGate.dll'
  $common = '/nologo /noconfig /nostdlib+ /platform:x64 /langversion:5 /unsafe- /checked+ /optimize+ /r:"' + $core + '" /r:"' + $system + '" '
  $failure = 'COMPILER'
  $compiled = Run-Fixed $csc ($common + '/target:exe /out:"' + $helper + '" "' + $source + '"') 120000
  if ($compiled.code -ne 0) { throw 'Fixed native compilation failed.' }
  $compiled = Run-Fixed $csc ($common + '/target:library /out:"' + $gate + '" "' + $gateSource + '"') 120000
  if ($compiled.code -ne 0) { throw 'Fixed report-gate compilation failed.' }
  $helperHash = Digest $helper; $gateHash = Digest $gate
  # Byte-load only the reviewed pure report gate; this does not execute any native getter.
  $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($gate))
  $type = $assembly.GetType('ReportGate', $true)
  $failure = 'REPORT_GATE'
  $fixtures = [IO.File]::ReadAllText($fixtureFile) | ConvertFrom-Json
  if ($fixtures.schema -ne 1 -or $fixtures.kind -cne 'INERT_REPORT_GATE_FIXTURES' -or $fixtures.native_execution -ne $false -or @($fixtures.cases).Count -gt 64) { throw 'Inert gate fixtures refused.' }
  foreach ($case in $fixtures.cases) {
    $value = $type.GetMethod('Validate').Invoke($null, @([string]$case.raw))
    if (($null -ne $value) -ne [bool]$case.accept) { throw 'Pure report-gate fixture failed.' }
    $fixtureCount++
  }
  $failure = 'EXECUTOR'
  $result = Run-Fixed $helper '--probe' 180000
  if ($result.code -in @(0,1,2)) { $nativeCode = $result.code }
  $failure = 'REPORT'
  $validated = $type.GetMethod('Validate').Invoke($null, @($result.text))
  if ($null -eq $validated) { throw 'Native report refused.' }
  $parsed = $validated | ConvertFrom-Json
  if ($parsed.outcome -eq 'OBSERVED') {
    $images = @($parsed.files | Where-Object role -eq 'executable')
    if ($nativeCode -ne 0 -or $images.Count -ne 1 -or $images[0].sha256 -cne $helperHash) { throw 'Actual helper image join refused.' }
  } elseif ($nativeCode -eq 0) { throw 'Exit/report disagreement refused.' }
  $native = $parsed
  $failure = 'NONE'
} catch {
  # Fixed enum only. Raw exceptions, paths, payloads and compiler/stderr never leave this wrapper.
} finally {
  if ($workOwned) {
    try {
      foreach ($pair in @(@('PhaseZero.exe',$helperHash), @('ReportGate.dll',$gateHash))) {
        $owned = Join-Path $work $pair[0]
        if (Test-Path -LiteralPath $owned) {
          if ($null -eq $pair[1] -or (Digest $owned) -cne $pair[1]) { throw 'Changed build output held.' }
          [IO.File]::Delete($owned)
        }
      }
      [IO.Directory]::Delete($work, $false)
      $buildCleanup = 'PATH_ABSENCE_OBSERVED_IDENTITY_UNJOINED'
    } catch { $buildCleanup = 'UNKNOWN' }
  }
}
$report = [ordered]@{
  schema = 1
  kind = 'WINDOWS_NO_KEY_NATIVE_PHASE_ZERO_HOSTED'
  failure = $failure
  actual_probe_invoked = $executed
  native_exit_code = $nativeCode
  source_admitted = $false
  runtime_admitted = $false
  release_ready = $false
  production_windows_service_acceptance = $false
  same_host_reboot_proven = $false
  all_owned_processes_gone = $false
  build_cleanup = $buildCleanup
  compiler_sha256 = $compilerHash
  mscorlib_sha256 = $coreHash
  system_sha256 = $systemHash
  helper_sha256 = $helperHash
  report_gate_sha256 = $gateHash
  source_sha256 = $sourceHash
  report_gate_source_sha256 = $gateSourceHash
  report_gate_fixtures_sha256 = $fixtureHash
  report_gate_fixture_count = $fixtureCount
  native = $native
}
$encoded = ConvertTo-Json -InputObject $report -Depth 10 -Compress
if ($encoded.Length -gt 32768) { throw 'Closed hosted report too large.' }
if ($env:RUNNER_TEMP -notin @('D:\a\_temp', 'C:\a\_temp')) { throw 'Closed report destination refused.' }
$destination = Join-Path $env:RUNNER_TEMP 'windows-native-phase-zero-report.json'
$finalRoot = Get-Item -LiteralPath $env:RUNNER_TEMP -Force
for ($dir = $finalRoot; $null -ne $dir; $dir = $dir.Parent) {
  if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Closed report parent refused.' }
}
$reportFile = New-Object IO.FileStream($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
  $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($encoded + "`n")
  $reportFile.Write($bytes, 0, $bytes.Length)
  $reportFile.Flush($true)
} finally { $reportFile.Dispose() }
if ($failure -ne 'NONE' -or $null -eq $native -or $native.outcome -ne 'OBSERVED') { exit 1 }
