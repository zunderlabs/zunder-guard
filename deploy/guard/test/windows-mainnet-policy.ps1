# Native hosted-CI policy probe only; no services, credentials or persistent policy writes.
[CmdletBinding()]
param([string]$SourceRoot=(Split-Path $PSScriptRoot -Parent))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Disposable hosted Windows Actions runner required.' }
$machineShell=[IO.Path]::Combine([Environment]::GetFolderPath('Windows'),'System32','WindowsPowerShell','v1.0','powershell.exe')
$loader=(Join-Path $SourceRoot 'loader/i.ps1').Replace("'","''")
$probe=@'
$ErrorActionPreference='Stop'
if ((Get-ExecutionPolicy) -ne 'Restricted') { throw 'Restricted parent policy was not established; no policy proof.' }
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('@FILE@',[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Candidate parse failed.' }
foreach ($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) { . ([scriptblock]::Create($node.Extent.Text)) }
# Actual immutable Windows path/ACL checks and OS binary-module imports, read-only.
Initialize-ZgMachineContext
if (Microsoft.PowerShell.Core\Get-Module NetTCPIP) { throw 'Outer bootstrap imported script-based NetTCPIP under Restricted.' }
Microsoft.PowerShell.Utility\Write-Host 'Restricted outer bootstrap passed with OS binary modules only.'
'@.Replace('@FILE@',$loader)
$before=@{}
foreach ($scope in @('CurrentUser','LocalMachine','MachinePolicy','UserPolicy')) { $before[$scope]=[string](Get-ExecutionPolicy -Scope $scope) }
& $machineShell -NoLogo -NoProfile -ExecutionPolicy Restricted -Command $probe
if ($LASTEXITCODE -ne 0) { throw 'Restricted outer bootstrap probe failed.' }
$directory=Join-Path ([IO.Path]::GetTempPath()) ('zg-policy-fixture-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($directory) | Out-Null
try {
  # This inert fixture tests native process-policy semantics only. The separate
  # trust suite tests that production reaches its helper only after admission.
  $fixture=Join-Path $directory 'inert-helper.ps1'
  [IO.File]::WriteAllText($fixture,"Write-Output 'INERT_HELPER_EXECUTED'")
  $output=& $machineShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $fixture
  if ($LASTEXITCODE -ne 0 -or $output -cne 'INERT_HELPER_EXECUTED') { throw 'Per-process helper policy blocked; Group Policy must remain authoritative.' }
} finally { [IO.Directory]::Delete($directory,$true) }
foreach ($scope in $before.Keys) { if ([string](Get-ExecutionPolicy -Scope $scope) -cne $before[$scope]) { throw 'Persistent or organization execution policy changed.' } }
Write-Host 'Native Restricted bootstrap and scoped inert helper passed; persistent/Group Policy unchanged. Production signed-helper installation remains a separate gate.'
