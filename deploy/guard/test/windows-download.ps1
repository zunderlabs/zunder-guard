# The loaders' real download loops, Get-ZgAsset (machine service) and Get-Asset (per-user),
# against a loopback HTTP fixture (download-fixture-server.py) and one public HTTPS file.
# Runs under Windows PowerShell 5.1 and PowerShell 7. No service, credential, key or install.
#
# The functions are parsed from loader/i.ps1 unchanged. For the loopback cases only, this
# test's own copy is rewritten in three ways, each matched exactly once: it accepts http://
# (the fixture has no certificate), it calls an unqualified Start-Sleep (recorded here, not
# slept), and for the stall cases a shorter read timeout keeps the run short. The unmodified
# functions are checked to refuse http:// and to fetch the HTTPS file with every production
# value. Creation goes through the real New-ZgSecureFile (CreateNew, protected ACL) in an
# owned temporary directory; only its machine-path admission is narrowed to that directory.
[CmdletBinding()]
param([string]$SourceRoot = (Split-Path $PSScriptRoot -Parent), [string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # as Install-ZunderGuard sets it
$script:tests = 0
function Assert([bool]$Condition, [string]$Name) {
  if (-not $Condition) { throw "FAIL: $Name" }
  $script:tests++
  Write-Host "ok: $Name"
}

$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot 'loader/i.ps1'), [ref]$tokens, [ref]$errors)
Assert ($errors.Count -eq 0) 'parse loader/i.ps1'
$definitions = @{}
foreach ($node in $ast.FindAll({ param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($node.Name -in @('Get-ZgAsset', 'Get-Asset', 'New-ZgSecureFile', 'New-ZgAcl')) { $definitions[$node.Name] = $node.Extent.Text }
}
Assert ($definitions.Count -eq 4) 'the four functions are found in loader/i.ps1'
function Edit-Definition([string]$Text, [string]$Old, [string]$New) {
  $count = [regex]::Matches($Text, [regex]::Escape($Old)).Count
  if ($count -ne 1) { throw "fixture rewrite expects one '$Old', found $count" }
  return $Text.Replace($Old, $New)
}
$machine = $definitions['Get-ZgAsset']
$machineLoopback = Edit-Definition $machine '$Source.StartsWith(''https://'')' '$Source.StartsWith(''http://'')'
$machineLoopback = Edit-Definition $machineLoopback 'Microsoft.PowerShell.Utility\Start-Sleep' 'Start-Sleep'
$machineShortRead = Edit-Definition $machineLoopback '$request.ReadWriteTimeout = 60000' '$request.ReadWriteTimeout = 5000'
$user = $definitions['Get-Asset']
$userLoopback = Edit-Definition $user '$From -like ''https://*''' '$From -like ''http://*'''
$userShortRead = Edit-Definition $userLoopback '$Bounds.OperationTimeoutSeconds = 60' '$Bounds.OperationTimeoutSeconds = 5'
. ([scriptblock]::Create($definitions['New-ZgAcl']))
. ([scriptblock]::Create($definitions['New-ZgSecureFile']))

# As the loaders set it before downloading (Windows PowerShell 5.1 may default to older TLS).
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('zg-download-' + [Guid]::NewGuid().ToString('N'))
$work = Join-Path $fixture 'work'
[IO.Directory]::CreateDirectory($work) | Out-Null
$Tmp = $work # Get-Asset writes into its caller's $Tmp
function Assert-ZgPath($Path, [switch]$Machine, [string]$ReadSid) {
  if ($Path -cne $work -and [IO.Path]::GetDirectoryName($Path) -cne $work) { throw 'fixture parent differs' }
}
function Start-Sleep([int]$Seconds) { $script:sleeps.Add($Seconds) }
$script:sleeps = [Collections.Generic.List[int]]::new()

function Invoke-Case([scriptblock]$Code) {
  $script:sleeps = [Collections.Generic.List[int]]::new()
  $message = $null
  $watch = [Diagnostics.Stopwatch]::StartNew()
  try { & $Code | Out-Null } catch { $message = $_.Exception.Message }
  $watch.Stop()
  return [pscustomobject]@{ Message = $message; Seconds = $watch.Elapsed.TotalSeconds; Sleeps = ($script:sleeps -join ',') }
}
function Get-Body([string]$Name, [int]$Size) {
  $seed = [Text.Encoding]::ASCII.GetBytes($Name)
  $bytes = [byte[]]::new($Size)
  for ($i = 0; $i -lt $Size; $i++) { $bytes[$i] = $seed[$i % $seed.Length] }
  return [Convert]::ToBase64String($bytes)
}
function Get-Saved([string]$Path) { return [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) }

$portFile = Join-Path $fixture 'port'
$log = Join-Path $fixture 'requests'
function Get-Requests([string]$Path) {
  if (-not [IO.File]::Exists($log)) { return 0 }
  return @([IO.File]::ReadAllLines($log) | Where-Object { $_ -ceq $Path }).Count
}
$serverScript = Join-Path $PSScriptRoot 'download-fixture-server.py'
$server = Start-Process -FilePath $Python -ArgumentList @('-I', ('"' + $serverScript + '"'), ('"' + $portFile + '"'), ('"' + $log + '"')) -PassThru -NoNewWindow
try {
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  while (-not [IO.File]::Exists($portFile)) {
    if ($server.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'the loopback fixture did not start' }
    [Threading.Thread]::Sleep(200)
  }
  $base = 'http://127.0.0.1:' + [IO.File]::ReadAllText($portFile).Trim()
  # A port nothing listens on: bound once, then released.
  $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  $probe.Start(); $closedPort = $probe.LocalEndpoint.Port; $probe.Stop()
  $closed = "http://127.0.0.1:$closedPort"

  # --- Production functions: http:// refused; the pinned verifier's checksums over HTTPS.
  . ([scriptblock]::Create($machine))
  $destination = Join-Path $work 'refused-http.bin'
  $result = Invoke-Case { Get-ZgAsset "$base/ok" 'refused-http.bin' $destination }
  Assert ($result.Message -ceq 'Release source must be HTTPS or an offline release directory.') 'machine: production refuses http://'
  Assert ((Get-Requests '/ok/refused-http.bin') -eq 0 -and -not [IO.File]::Exists($destination)) 'machine: refused http:// sends nothing and writes nothing'
  . ([scriptblock]::Create($user))
  $result = Invoke-Case { Get-Asset 'refused-http.bin' "$base/ok" }
  Assert ($result.Message -ceq "ZUNDER_GUARD_BASE_URL must be an https:// URL or a folder, got $base/ok") 'per-user: production refuses http://'
  Assert ((Get-Requests '/ok/refused-http.bin') -eq 0) 'per-user: refused http:// sends nothing'

  $pinned = '(?m)^9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be\s+cosign-windows-amd64\.exe\r?$'
  $cosign = 'https://github.com/sigstore/cosign/releases/download/v3.1.3'
  $destination = Join-Path $work 'cosign_checksums.txt'
  $result = Invoke-Case { Get-ZgAsset $cosign 'cosign_checksums.txt' $destination }
  Assert ($null -eq $result.Message) "machine: HTTPS fetch through GitHub's redirect succeeds ($($result.Message))"
  Assert ([IO.File]::ReadAllText($destination) -match $pinned) "machine: HTTPS body holds the pinned verifier's checksum"
  [IO.File]::Delete($destination)
  $result = Invoke-Case { Get-Asset 'cosign_checksums.txt' $cosign }
  Assert ($null -eq $result.Message) "per-user: HTTPS fetch succeeds ($($result.Message))"
  Assert ([IO.File]::ReadAllText($destination) -match $pinned) "per-user: HTTPS body holds the pinned verifier's checksum"
  [IO.File]::Delete($destination)

  # --- Get-ZgAsset, loopback copy with production timeouts.
  . ([scriptblock]::Create($machineLoopback))
  $destination = Join-Path $work 'slow.bin'
  $result = Invoke-Case { Get-ZgAsset "$base/throttle" 'slow.bin' $destination }
  Assert ($null -eq $result.Message -and $result.Seconds -gt 22) "machine: a 26 s transfer that keeps sending completes past the 20 s header timeout ($([int]$result.Seconds) s; $($result.Message))"
  Assert ((Get-Saved $destination) -ceq (Get-Body 'slow.bin' 26624) -and (Get-Requests '/throttle/slow.bin') -eq 1 -and $result.Sleeps -eq '') 'machine: slow body complete in one try'

  foreach ($mode in @('cut', 'reset')) {
    $name = "$mode.bin"; $destination = Join-Path $work $name
    $result = Invoke-Case { Get-ZgAsset "$base/$mode" $name $destination }
    Assert ($null -eq $result.Message) "machine: a body $mode mid-transfer is retried ($($result.Message))"
    Assert ((Get-Requests "/$mode/$name") -eq 2 -and $result.Sleeps -eq '2') "machine: $mode costs exactly one more try after 2 s"
    Assert ((Get-Saved $destination) -ceq (Get-Body $name 4096)) "machine: $mode retry writes the whole body to a fresh file"
  }

  $destination = Join-Path $work 'refused.bin'
  $result = Invoke-Case { Get-ZgAsset $closed 'refused.bin' $destination }
  Assert ($null -ne $result.Message -and $result.Sleeps -eq '2,4,8') "machine: a refused connection is tried 4 times, 2/4/8 s apart ($($result.Sleeps))"
  Assert ($result.Message -notmatch 'announced length' -and -not [IO.File]::Exists($destination)) 'machine: the last connection error is kept and no file is left'

  $destination = Join-Path $work 'missing.bin'
  $result = Invoke-Case { Get-ZgAsset "$base/missing" 'missing.bin' $destination }
  Assert ((Get-Requests '/missing/missing.bin') -eq 4 -and $result.Sleeps -eq '2,4,8') "machine: four 404 responses are four real requests (each error response closed; $(Get-Requests '/missing/missing.bin'))"
  Assert ($result.Message -match '404' -and -not [IO.File]::Exists($destination)) "machine: the final error is the 404 itself ($($result.Message))"

  $destination = Join-Path $work 'existing.bin'
  [IO.File]::WriteAllText($destination, 'preexisting entry')
  $result = Invoke-Case { Get-ZgAsset "$base/ok" 'existing.bin' $destination }
  Assert ($result.Message -ceq 'Existing machine file entry refused.' -and $result.Sleeps -eq '') "machine: an existing destination fails at once ($($result.Message))"
  Assert ((Get-Requests '/ok/existing.bin') -eq 1 -and [IO.File]::ReadAllText($destination) -ceq 'preexisting entry') 'machine: no retry, and the existing entry is neither replaced nor deleted'

  # --- Get-ZgAsset, loopback copy whose read timeout is 5 s instead of 60 s.
  . ([scriptblock]::Create($machineShortRead))
  $destination = Join-Path $work 'stall.bin'
  $result = Invoke-Case { Get-ZgAsset "$base/stall" 'stall.bin' $destination }
  Assert ((Get-Requests '/stall/stall.bin') -eq 4 -and $result.Sleeps -eq '2,4,8') "machine: headers then silence is cut by the read timeout, 4 tries ($(Get-Requests '/stall/stall.bin'))"
  Assert ($result.Seconds -lt 40 -and -not [IO.File]::Exists($destination)) "machine: each stalled try ends near the read timeout, no file left ($([int]$result.Seconds) s)"

  # --- Get-Asset (per-user), loopback copy with production bounds.
  . ([scriptblock]::Create($userLoopback))
  $result = Invoke-Case { Get-Asset 'slow-user.bin' "$base/throttle" }
  Assert ($null -eq $result.Message -and $result.Seconds -gt 22) "per-user: a 26 s transfer that keeps sending completes ($([int]$result.Seconds) s; $($result.Message))"
  Assert ((Get-Saved (Join-Path $work 'slow-user.bin')) -ceq (Get-Body 'slow-user.bin' 26624) -and $result.Sleeps -eq '') 'per-user: slow body complete in one try'

  # Windows PowerShell 5.1's Invoke-WebRequest is not checked for a cleanly closed short body:
  # verification refuses such a file. A reset connection is an error on every version.
  $modes = if ($PSVersionTable.PSVersion.Major -ge 6) { @('cut', 'reset') } else { @('reset') }
  foreach ($mode in $modes) {
    $name = "$mode-user.bin"
    $result = Invoke-Case { Get-Asset $name "$base/$mode" }
    Assert ($null -eq $result.Message -and (Get-Requests "/$mode/$name") -eq 2 -and $result.Sleeps -eq '2') "per-user: a body $mode mid-transfer costs one more try ($($result.Message))"
    Assert ((Get-Saved (Join-Path $work $name)) -ceq (Get-Body $name 4096)) "per-user: $mode retry writes the whole body to a fresh file"
  }

  $result = Invoke-Case { Get-Asset 'refused-user.bin' $closed }
  $expected = '^download failed: ' + [regex]::Escape("$closed/refused-user.bin") + ' \(.+\); refusing, nothing was installed$'
  Assert ($result.Message -match $expected -and $result.Sleeps -eq '2,4,8') "per-user: a refused connection is tried 4 times with the unchanged final message ($($result.Message))"
  Assert (-not [IO.File]::Exists((Join-Path $work 'refused-user.bin'))) 'per-user: no file left'

  $result = Invoke-Case { Get-Asset 'missing-user.bin' "$base/missing" }
  Assert ((Get-Requests '/missing/missing-user.bin') -eq 4 -and $result.Sleeps -eq '2,4,8') "per-user: four 404 responses are four real requests ($(Get-Requests '/missing/missing-user.bin'))"
  Assert ($result.Message -match '^download failed: .+; refusing, nothing was installed$' -and -not [IO.File]::Exists((Join-Path $work 'missing-user.bin'))) 'per-user: unchanged final message, no file left'

  if ((Get-Command -Name Invoke-WebRequest -CommandType Cmdlet).Parameters.ContainsKey('OperationTimeoutSeconds')) {
    . ([scriptblock]::Create($userShortRead))
    $result = Invoke-Case { Get-Asset 'stall-user.bin' "$base/stall" }
    Assert ((Get-Requests '/stall/stall-user.bin') -eq 4 -and $result.Sleeps -eq '2,4,8' -and $result.Seconds -lt 40) "per-user: a stalled read is cut on PowerShell 7.4+ ($([int]$result.Seconds) s)"
    Assert (-not [IO.File]::Exists((Join-Path $work 'stall-user.bin'))) 'per-user: no file left after stalls'
  } else {
    Write-Host "skip: per-user stall (PowerShell $($PSVersionTable.PSVersion) has no -OperationTimeoutSeconds; .NET's own read timeout applies)"
  }
} finally {
  if (-not $server.HasExited) { $server.Kill() }
  $server.WaitForExit()
  [IO.Directory]::Delete($fixture, $true)
}
Write-Host "Windows download loops: $script:tests assertions passed on PowerShell $($PSVersionTable.PSVersion)."
