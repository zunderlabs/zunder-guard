# Signed, versioned Windows sending-service lifecycle helper. Rust owns key prompts.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Prepare','Resume','JournalInit','Start','Stop','Status','Upgrade','Recover','Uninstall')][string]$Action,
  [ValidatePattern('^[A-Za-z0-9-]{1,64}$')][string]$Id = 'guard',
  [string]$ReleaseDir, [string]$Tag,
  [string]$Rules, [string]$Account, [string]$ConfirmAccount, [string]$EquityCap,
  [string]$Licence, [string]$Note,
  [ValidateSet('mainnet','testnet')][string]$Network = 'mainnet',
  [switch]$KeyStdin,
  [ValidateSet('','Manual','DelayedAuto')][string]$Startup = '',
  [ValidateSet('','RollbackImage')][string]$Recovery = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Shared verbatim trust primitives embedded into the loader and signed lifecycle helper.
function Initialize-ZgMachineContext([switch]$RuntimeModules) {
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) { throw 'Mainnet requires native Windows x64 PowerShell.' }
  $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open a trusted elevated PowerShell window explicitly; the loader will not elevate a downloaded script.' }
  foreach ($name in @([Environment]::GetEnvironmentVariables().Keys)) { if ([string]$name -like 'ZUNDER_*') { [Environment]::SetEnvironmentVariable([string]$name,$null,'Process') } }
  $script:ZgWindows = [Environment]::GetFolderPath('Windows')
  $script:ZgPowerShell = [IO.Path]::Combine($ZgWindows,'System32','WindowsPowerShell','v1.0','powershell.exe')
  $script:ZgSc = [IO.Path]::Combine($ZgWindows,'System32','sc.exe')
  $env:PATH = [IO.Path]::Combine($ZgWindows,'System32') + ';' + $ZgWindows
  $env:PSModulePath = [IO.Path]::Combine($ZgWindows,'System32','WindowsPowerShell','v1.0','Modules')
  $script:PSModuleAutoLoadingPreference = 'None'
  Assert-ZgPath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -Machine
  Assert-ZgPath $ZgPowerShell -Machine
  Assert-ZgPath $ZgSc -Machine
  Assert-ZgPath $PSHOME -Machine
  # Outer bootstrap must work under default Restricted policy. Import only
  # OS binary modules here; CDXML/script networking module belongs to the
  # already verified helper's explicit per-process execution policy.
  $modules = @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility','CimCmdlets')
  if ($RuntimeModules) { $modules += 'NetTCPIP' }
  foreach ($name in $modules) {
    $moduleRoot = if ($name.StartsWith('Microsoft.PowerShell.')) { [IO.Path]::Combine($PSHOME,'Modules') } else { $env:PSModulePath }
    $manifest = [IO.Path]::Combine($moduleRoot,$name,($name+'.psd1'))
    Assert-ZgPath $manifest -Machine
    Microsoft.PowerShell.Core\Import-Module $manifest -Force -ErrorAction Stop
  }
  foreach ($cpu in @(CimCmdlets\Get-CimInstance Win32_Processor)) { if ($cpu.Architecture -ne 9) { throw 'Windows mainnet requires native x64, not ARM emulation.' } }
  $script:ZgData = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'),'ZunderGuard')
  $script:ZgBin = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'),'ZunderGuard')
  Assert-ZgPath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -Machine
  Assert-ZgPath $ZgPowerShell -Machine
  Assert-ZgPath $ZgSc -Machine
}
function Assert-ZgPath([string]$Path,[switch]$Machine,[string]$ReadSid) {
  $full = [IO.Path]::GetFullPath($Path)
  if ($full -cne $Path -or $full.StartsWith('\\') -or $full.Substring(2).Contains(':')) { throw 'Noncanonical machine path refused.' }
  $known = @([Environment]::GetFolderPath('CommonApplicationData'),[Environment]::GetFolderPath('ProgramFiles'),[IO.Path]::GetPathRoot($full))
  $current = $full
  while ($current) {
    $item = if ([IO.Directory]::Exists($current)) { [IO.DirectoryInfo]::new($current) } else { [IO.FileInfo]::new($current) }
    if (-not $item.Exists -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Missing or reparse machine path refused.' }
    $acl = if ($PSVersionTable.PSVersion.Major -ge 6) { [IO.FileSystemAclExtensions]::GetAccessControl($item) } else { $item.GetAccessControl() }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { throw 'Untrusted machine path owner.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
      if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { continue }
      $allowed = 0x1200a9 # read/execute/synchronize; no delete, ACL or owner writes
      if ($current -in $known) { $allowed = $allowed -bor 6 } # standard root create-child only; each created anchor rechecked
      if (([int]$rule.FileSystemRights -band (-bnot $allowed)) -ne 0) { throw 'Unprivileged machine path mutation rights refused.' }
    }
    if ($current -eq [IO.Path]::GetPathRoot($current)) { break }
    $current = [IO.Path]::GetDirectoryName($current)
  }
}
function New-ZgAcl([bool]$Directory,[string]$ServiceSid,[bool]$Writable=$false) {
  $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl',$inherit,'None','Allow')) }
  if ($ServiceSid) {
    $rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($ServiceSid),$rights,$inherit,'None','Allow'))
  }
  return $acl
}
function New-ZgDirectory([string]$Path) {
  Assert-ZgPath ([IO.Path]::GetDirectoryName($Path)) -Machine
  if (-not [IO.Directory]::Exists($Path)) {
    $acl = New-ZgAcl $true ''
    if ($PSVersionTable.PSVersion.Major -ge 6) { [IO.FileSystemAclExtensions]::CreateDirectory($acl,$Path) | Microsoft.PowerShell.Core\Out-Null }
    else { [IO.Directory]::CreateDirectory($Path,$acl) | Microsoft.PowerShell.Core\Out-Null }
  }
  Assert-ZgPath $Path
}
function Set-ZgAcl([string]$Path,[string]$ServiceSid,[bool]$Writable=$false) {
  $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ACL target refused.' }
  Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject (New-ZgAcl $item.PSIsContainer $ServiceSid $Writable)
}
function Get-ZgHash([string]$Path) { return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-ZgJson([string]$Path,$Value) {
  Assert-ZgPath ([IO.Path]::GetDirectoryName($Path))
  if ([IO.File]::Exists($Path)) { Assert-ZgPath $Path }
  $next = $Path + '.next-' + [Guid]::NewGuid().ToString('N')
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 24))
  $file = [IO.FileStream]::new($next,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
  Set-ZgAcl $next ''
  if ([IO.File]::Exists($Path)) { [IO.File]::Replace($next,$Path,$null) } else { [IO.File]::Move($next,$Path) }
}
function Get-ZgManifestHash([string]$Sums,[string]$Name) {
  $found = @()
  foreach ($line in [IO.File]::ReadAllLines($Sums)) {
    if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') { throw 'Malformed signed checksum line refused.' }
    if ($Matches[2] -ieq $Name) {
      if ($Matches[2] -cne $Name) { throw 'Case-colliding signed asset refused.' }
      $found += $Matches[1]
    }
  }
  if ($found.Count -ne 1) { throw 'Consumed asset must appear exactly once in signed checksums.' }
  return $found[0]
}
function Invoke-ZgReleaseVerifier([string]$Verifier,[string]$Bundle,[string]$Sums,[string]$Identity) {
  $oldPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue' # PS5.1 wraps successful native stderr
    & $Verifier verify-blob --bundle $Bundle --certificate-identity $Identity --certificate-oidc-issuer https://token.actions.githubusercontent.com $Sums 2>&1 | Microsoft.PowerShell.Core\Out-Host
    return $LASTEXITCODE
  } finally { $ErrorActionPreference = $oldPreference }
}
function Confirm-ZgRelease([string]$Directory,[string]$Tag) {
  if ($Tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Exact stable release tag required.' }
  Assert-ZgPath $Directory
  $verifier = [IO.Path]::Combine($Directory,'cosign.exe')
  Assert-ZgPath $verifier
  if ((Get-ZgHash $verifier) -ne '9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be') { throw 'Pinned verifier checksum mismatch.' }
  $sums = [IO.Path]::Combine($Directory,'SHA256SUMS')
  $bundle = [IO.Path]::Combine($Directory,'SHA256SUMS.sigstore.json')
  Assert-ZgPath $sums; Assert-ZgPath $bundle
  $code = Invoke-ZgReleaseVerifier $verifier $bundle $sums "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/$Tag"
  if ($code -ne 0) { throw 'Release signature verification failed.' }
  foreach ($name in @("zunder-guard-$Tag-windows-amd64.zip",'install-windows-service.ps1')) {
    $asset = [IO.Path]::Combine($Directory,$name); Assert-ZgPath $asset
    if ((Get-ZgHash $asset) -ne (Get-ZgManifestHash $sums $name)) { throw 'Signed release asset checksum mismatch.' }
  }
}
function Get-ZgAsset([string]$Source,[string]$Name,[string]$Destination) {
  if ($Source.StartsWith('https://')) {
    $client = [Net.WebClient]::new()
    try { $client.DownloadFile($Source.TrimEnd('/')+'/'+$Name,$Destination) } finally { $client.Dispose() }
  } elseif ([IO.Directory]::Exists($Source)) { [IO.File]::Copy([IO.Path]::Combine($Source,$Name),$Destination,$false) }
  else { throw 'Release source must be HTTPS or an offline release directory.' }
}

function Get-ZgHelperInvocation([string]$Helper) {
  # Paths came from admitted machine roots; quote defensively for printed commands.
  return "& '"+$ZgPowerShell.Replace("'","''")+"' -NoProfile -ExecutionPolicy Bypass -File '"+$Helper.Replace("'","''")+"'"
}
function Assert-ZgHelperPolicy {
  foreach ($scope in @('MachinePolicy','UserPolicy')) {
    $policy = [string](Microsoft.PowerShell.Security\Get-ExecutionPolicy -Scope $scope)
    if ($policy -in @('Restricted','AllSigned')) { throw "Organization $scope execution policy is $policy and prevents this Sigstore-verified helper. No policy was changed; contact the policy administrator." }
  }
}

function Get-ZgRecordNetwork($Record) {
  # A missing field is the immutable legacy Mainnet transaction schema.
  $mode = if ($Record.PSObject.Properties.Name -contains 'mode') { $Record.mode } else { 'mainnet' }
  if ($mode -cnotin @('mainnet','testnet')) { throw 'Unsupported owned sending network.' }
  return $mode
}
function Get-ZgConfirmationFlag {
  if ($Network -eq 'testnet') { return '--confirm-account' }
  return '--confirm-mainnet'
}
function Get-ZgJournalPath {
  $name = if ($Network -eq 'testnet') { 'risk.jsonl' } else { 'risk-mainnet.jsonl' }
  return [IO.Path]::Combine($ZgHome,$name)
}
function Assert-ZgPrivateTestnetInput {
  if ($Network -cne 'testnet' -or -not $KeyStdin -or -not [Console]::IsInputRedirected) { throw 'Protected Testnet key setup requires explicit private redirected stdin.' }
}
function Test-ZgSamePath([string]$Left,[string]$Right) {
  if ($Left.StartsWith('\\?\')) { $Left=$Left.Substring(4) }
  if ($Right.StartsWith('\\?\')) { $Right=$Right.Substring(4) }
  return [string]::Equals([IO.Path]::GetFullPath($Left),[IO.Path]::GetFullPath($Right),[StringComparison]::OrdinalIgnoreCase)
}
function ConvertTo-ZgNativeArgument([string]$Value) {
  # Windows argv quoting: double backslashes before quotes and at the quoted end.
  if ($Value.IndexOf([char]0) -ge 0) { throw 'NUL in SCM argument refused; transaction remains pending.' }
  $quoted = [regex]::Replace($Value,'(\\*)"','$1$1\"')
  $quoted = [regex]::Replace($quoted,'(\\+)$','$1$1')
  return '"'+$quoted+'"'
}
function Invoke-ZgSc([string[]]$Words) {
  $arguments = (@(foreach ($word in $Words) { ConvertTo-ZgNativeArgument $word }) -join ' ')
  $info = [Diagnostics.ProcessStartInfo]::new()
  $info.FileName = $ZgSc
  $info.Arguments = $arguments
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  # Inherit output directly: no buffered drains or EOF waits beyond the deadline.
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $info
  $started = $false
  try {
    $started = $process.Start()
    if (-not $started) { throw 'SCM client could not start; transaction remains pending.' }
    if (-not $process.WaitForExit(30000)) { throw 'SCM client timed out; transaction remains pending.' }
    if ($process.ExitCode -ne 0) { throw 'SCM operation failed; transaction remains pending.' }
  } finally {
    try {
      if ($started -and -not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'SCM client did not exit after termination.' }
      }
    } catch {
      throw 'SCM client cleanup failed; transaction remains pending.'
    } finally { $process.Dispose() }
  }
}
function Get-ZgService {
  $service = CimCmdlets\Get-CimInstance Win32_Service -Filter "Name='$ZgServiceName'"
  if ($service) {
    $expected = '"'+$ZgExe+'" service run --binding "'+$ZgBinding+'"'
    if ($service.PathName -cne $expected -or $service.StartName -ine "NT SERVICE\$ZgServiceName") { throw 'SCM registration is not this owned installation.' }
    $script:ZgSid = ([Security.Principal.NTAccount]::new("NT SERVICE\$ZgServiceName")).Translate([Security.Principal.SecurityIdentifier]).Value
  }
  return $service
}
function Assert-ZgStopped {
  $service = Get-ZgService
  if ($service -and ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled')) { throw 'Owned service must be stopped with startup Disabled.' }
  foreach ($process in @(CimCmdlets\Get-CimInstance Win32_Process -Filter "Name='zunder-guard.exe'")) {
    if ($process.ExecutablePath -ieq $ZgExe) { throw 'Owned executable still has a live process; no mutation permitted.' }
  }
}
function Disable-ZgService {
  $service = Get-ZgService
  if ($service) {
    Invoke-ZgSc @('config',$ZgServiceName,'start=','disabled')
    if ((Get-ZgService).StartMode -ne 'Disabled') { throw 'SCM did not disable startup.' }
    $handle = Microsoft.PowerShell.Management\Get-Service -Name $ZgServiceName
    if ($handle.Status -ne 'Stopped') {
      Microsoft.PowerShell.Management\Stop-Service -Name $ZgServiceName
      $handle.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35))
    }
  }
  Assert-ZgStopped
}
function Save-ZgPhase([string]$Phase) {
  $script:ZgTransaction.phase = $Phase
  Write-ZgJson $ZgTransactionPath $ZgTransaction
}
function Read-ZgTransaction {
  Assert-ZgPath $ZgTransactionPath
  if ([IO.FileInfo]::new($ZgTransactionPath).Length -gt 65536) { throw 'Oversized transaction refused.' }
  $value = [IO.File]::ReadAllText($ZgTransactionPath) | Microsoft.PowerShell.Utility\ConvertFrom-Json
  $phases = @('install-planned','paths-created','image-admitted','service-created-disabled','config-preparing','config-prepared','binding-prepared','credential-provisioning','credential-present','admitted-disabled','journal-requested','journal-present','upgrade-planned','startup-disabled','quiesced','promoting-image','promoting-binding','activation-requested','activation-committed','stopped','uninstalled','rolled-back')
  if ($value.schema -ne 1 -or $value.id -cne $Id -or $value.service -cne $ZgServiceName -or $value.root -cne $ZgRoot -or $value.exe -cne $ZgExe -or $value.binding -cne $ZgBinding -or $value.phase -notin $phases -or $value.account -notmatch '^0x[0-9a-f]{40}$' -or $value.tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Transaction identity or phase is ambiguous; refuse recovery.' }
  if ((Get-ZgRecordNetwork $value) -cne $Network) { throw 'Transaction belongs to another sending network; adoption refused.' }
  if ($ConfirmAccount -and $ConfirmAccount.ToLowerInvariant() -cne $value.account) { throw 'Transaction account differs from explicit confirmation.' }
  return $value
}
function Confirm-ZgConsent {
  if ($ConfirmAccount -notmatch '^0x[0-9a-fA-F]{40}$' -or $ConfirmAccount.ToLowerInvariant() -cne $ZgTransaction.account) { throw 'Exact explicit ConfirmAccount is required.' }
}
function Invoke-ZgGuard([string[]]$Words) {
  & $ZgExe --home $ZgHome --config $ZgConfig @Words
  if ($LASTEXITCODE -ne 0) { throw 'Guard refused this lifecycle step; no following step was performed.' }
}
function Get-ZgPublic([string[]]$Words) {
  $text = & $ZgExe --home $ZgHome --config $ZgConfig @Words
  if ($LASTEXITCODE -ne 0) { throw 'Guard public metadata validation failed.' }
  return ($text -join "`n")
}
function Get-ZgPreparedBinding {
  $text = Get-ZgPublic @('service','prepare','--credential-id',$Id,(Get-ZgConfirmationFlag),$ConfirmAccount,'--service-name',$ZgServiceName,'--service-sid',$ZgSid)
  $metadata = $text | Microsoft.PowerShell.Utility\ConvertFrom-Json
  if ($metadata.account -cne $ZgTransaction.account -or $metadata.mode -cne $Network -or ( -not (Test-ZgSamePath $metadata.executable $ZgExe)) -or ( -not (Test-ZgSamePath $metadata.home $ZgHome)) -or ( -not (Test-ZgSamePath $metadata.config $ZgConfig)) -or $metadata.identity.service_name -cne $ZgServiceName -or $metadata.identity.service_sid -cne $ZgSid) { throw 'Prepared service metadata differs from transaction.' }
  return $metadata
}
function Get-ZgBinding {
  Assert-ZgPath $ZgBinding
  $metadata = [IO.File]::ReadAllText($ZgBinding) | Microsoft.PowerShell.Utility\ConvertFrom-Json
  if ($metadata.account -cne $ZgTransaction.account -or $metadata.mode -cne $Network -or ( -not (Test-ZgSamePath $metadata.executable $ZgExe)) -or ( -not (Test-ZgSamePath $metadata.home $ZgHome)) -or ( -not (Test-ZgSamePath $metadata.config $ZgConfig)) -or $metadata.identity.service_name -cne $ZgServiceName -or $metadata.identity.service_sid -cne $ZgSid) { throw 'Binding differs from owned transaction.' }
  if ((Get-ZgHash $ZgExe) -cne $metadata.executable_sha256) { throw 'Executable differs from admitted binding.' }
  return $metadata
}
function Assert-ZgCache {
  Confirm-ZgRelease $ZgTransaction.release $ZgTransaction.tag
  $helper = [IO.Path]::Combine($ZgTransaction.release,'install-windows-service.ps1')
  if ((Get-ZgHash $helper) -cne $ZgTransaction.helper_hash) { throw 'Retained lifecycle helper changed.' }
}
function Get-ZgImage {
  Assert-ZgCache
  $directory = [IO.Path]::Combine($ZgManagement,('extract-'+[Guid]::NewGuid().ToString('N'))); New-ZgDirectory $directory
  try {
    [Reflection.Assembly]::Load('System.IO.Compression.FileSystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089') | Microsoft.PowerShell.Core\Out-Null
    $archive = [IO.Compression.ZipFile]::OpenRead([IO.Path]::Combine($ZgTransaction.release,"zunder-guard-$($ZgTransaction.tag)-windows-amd64.zip"))
    try {
      $required = @('zunder-guard.exe','LICENSE','NOTICE','THIRD_PARTY_LICENSES.md')
      $seen = @{}
      foreach ($entry in $archive.Entries) {
        $name = $entry.FullName
        if ($name -cnotin ($required+@('README.md')) -or $seen.ContainsKey($name.ToLowerInvariant()) -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 -or ($entry.ExternalAttributes -band 0x400) -ne 0) { throw 'Unsafe, repeated or unexpected archive member.' }
        if ($entry.Length -gt 512MB) { throw 'Archive member exceeds installer size bound.' }
        $seen[$name.ToLowerInvariant()] = $true
        $output = [IO.FileStream]::new([IO.Path]::Combine($directory,$name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $input = $entry.Open()
        try { $input.CopyTo($output); $output.Flush($true) } finally { $input.Dispose(); $output.Dispose() }
      }
      foreach ($name in $required) { if (-not $seen.ContainsKey($name.ToLowerInvariant())) { throw 'Required executable or notice missing.' } }
    } finally { $archive.Dispose() }
    $image = [IO.Path]::Combine($directory,'zunder-guard.exe')
    $version = (& $image --version) -join ''
    if ($LASTEXITCODE -ne 0 -or $version -cne ('zunder-guard '+$ZgTransaction.tag.TrimStart('v'))) { throw 'Verified binary does not report the release version.' }
    return $directory
  } catch { [IO.Directory]::Delete($directory,$true); throw }
}
function Install-ZgImage([string]$Directory) {
  Assert-ZgStopped
  foreach ($name in @('zunder-guard.exe','LICENSE','NOTICE','THIRD_PARTY_LICENSES.md','README.md')) {
    $source = [IO.Path]::Combine($Directory,$name)
    if (-not [IO.File]::Exists($source)) { continue }
    $destination = [IO.Path]::Combine($ZgBinaryDir,$name)
    if ([IO.File]::Exists($destination)) { Assert-ZgPath $destination }
    $next = $destination+'.next-'+[Guid]::NewGuid().ToString('N')
    [IO.File]::Copy($source,$next,$false); Set-ZgAcl $next $ZgSid
    $stream = [IO.FileStream]::new($next,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    if ([IO.File]::Exists($destination)) { [IO.File]::Replace($next,$destination,$null) } else { [IO.File]::Move($next,$destination) }
  }
}
function Ensure-ZgService {
  $service = Get-ZgService
  if (-not $service) {
    $imagePath = '"'+$ZgExe+'" service run --binding "'+$ZgBinding+'"'
    Invoke-ZgSc @('create',$ZgServiceName,'binPath=',$imagePath,'start=','disabled','obj=',"NT SERVICE\$ZgServiceName",'DisplayName=',"Zunder Guard ($Id)")
    $null = Get-ZgService
  }
  Disable-ZgService
  foreach ($path in @($ZgRoot,$ZgBinaryDir,$ZgExe)) { Set-ZgAcl $path $ZgSid }
  Set-ZgAcl $ZgHome $ZgSid $true
  # Same per-executable WER exclusion as native service admission; never global policy.
  $wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
  Microsoft.PowerShell.Management\New-Item -Path $wer -Force | Microsoft.PowerShell.Core\Out-Null
  Microsoft.PowerShell.Management\New-ItemProperty -Path $wer -Name 'zunder-guard.exe' -Value 1 -PropertyType DWord -Force | Microsoft.PowerShell.Core\Out-Null
  Invoke-ZgSc @('failure',$ZgServiceName,'reset=','86400','actions=','restart/10000')
  Invoke-ZgSc @('failureflag',$ZgServiceName,'0')
}
function Complete-ZgPrepare {
  Confirm-ZgConsent; Assert-ZgCache
  Disable-ZgService
  foreach ($path in @($ZgData,$ZgBin,$ZgRoot,$ZgBinaryDir,$ZgHome)) {
    if (-not [IO.Directory]::Exists($path)) { New-ZgDirectory $path }
  }
  Save-ZgPhase 'paths-created'
  Assert-ZgPath $ZgRoot; Assert-ZgPath $ZgBinaryDir
  if ([IO.File]::Exists($ZgExe) -and (Get-ZgHash $ZgExe) -cne $ZgTransaction.new_hash) { throw 'Partial installation image differs from transaction.' }
  # Reconcile binary AND notices after interruption; never touch runtime state.
  $image = Get-ZgImage
  try { Install-ZgImage $image } finally { [IO.Directory]::Delete($image,$true) }
  Assert-ZgPath $ZgExe
  if (-not $ZgTransaction.new_hash) { $ZgTransaction.new_hash = Get-ZgHash $ZgExe }
  Save-ZgPhase 'image-admitted'
  Ensure-ZgService; Save-ZgPhase 'service-created-disabled'
  if (-not [IO.File]::Exists($ZgConfig)) {
    if ([IO.File]::Exists($ZgConfig+'.new')) { throw 'Uncommitted config staging exists. Retained helper Status/Resume requires manual inspection; no init or deletion repeated.' }
    Save-ZgPhase 'config-preparing'
    $words = @('init','--non-interactive','--service-setup',$Id,'--network',$Network,'--account',$ZgTransaction.account,'--equity-cap',$ZgTransaction.cap)
    if ($Network -eq 'mainnet') { $words += @('--confirm-mainnet',$ConfirmAccount) }
    else { Assert-ZgPrivateTestnetInput; $words += '--key-stdin' }
    if ($ZgTransaction.rules) { $words += @('--rules',$ZgTransaction.rules) }
    Invoke-ZgGuard $words
  }
  # A committed config on Resume is admitted, never initialized or paired again.
  $prepared = Get-ZgPreparedBinding
  if ($ZgTransaction.api_wallet -and $prepared.api_wallet -cne $ZgTransaction.api_wallet) { throw 'Recovered API wallet differs from transaction.' }
  $ZgTransaction.api_wallet = $prepared.api_wallet
  Set-ZgAcl $ZgConfig $ZgSid $true
  if ($Network -eq 'testnet') {
    $journal = Get-ZgJournalPath
    if (-not [IO.File]::Exists($journal)) { throw 'Initialized Testnet risk journal is missing; no reset permitted.' }
    Set-ZgAcl $journal $ZgSid $true
  }
  Save-ZgPhase 'config-prepared'
  if (-not [IO.File]::Exists($ZgBinding)) { Write-ZgJson $ZgBinding $prepared; Set-ZgAcl $ZgBinding $ZgSid }
  $null = Get-ZgBinding
  Save-ZgPhase 'binding-prepared'
  $credential = [IO.Path]::Combine($ZgRoot,'credential.dpapi')
  if (-not [IO.File]::Exists($credential)) {
    $file = [IO.FileStream]::new($credential,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $file.Dispose(); Set-ZgAcl $credential $ZgSid
  }
  Assert-ZgPath $credential
  if ([IO.FileInfo]::new($credential).Length -eq 0) {
    Save-ZgPhase 'credential-provisioning'
    $words = @('service','provision','--binding',$ZgBinding,(Get-ZgConfirmationFlag),$ConfirmAccount)
    if ($Network -eq 'testnet') { Assert-ZgPrivateTestnetInput; $words += '--key-stdin' }
    Invoke-ZgGuard $words
  }
  # Presence only, never a claim of successful virtual-account decryption.
  Invoke-ZgGuard @('service','check','--binding',$ZgBinding)
  Save-ZgPhase 'credential-present'
  if ($Licence) {
    if ($ZgTransaction.licence_hash -and $ZgTransaction.licence_hash -cne (Get-ZgTextHash $Licence)) { throw 'Different licence supplied on resume; use explicit service licence-set.' }
    $ZgTransaction.licence_hash = Get-ZgTextHash $Licence
    Write-ZgJson $ZgTransactionPath $ZgTransaction
    Invoke-ZgGuard @('service','licence-set','--binding',$ZgBinding,'--key',$Licence)
  }
  Assert-ZgStopped; Save-ZgPhase 'admitted-disabled'
}
function Get-ZgTextHash([string]$Text) {
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
}
function Get-ZgJournalHash {
  $path = (Get-ZgJournalPath)
  if (-not [IO.File]::Exists($path)) { return '' }
  return Get-ZgHash $path
}
function Complete-ZgUpgrade {
  Confirm-ZgConsent; Assert-ZgCache
  Disable-ZgService; Save-ZgPhase 'startup-disabled'
  $backup = [IO.Path]::Combine($ZgManagement,($Id+'-'+$ZgTransaction.transaction+'-previous.exe'))
  $oldBinding = [IO.Path]::Combine($ZgManagement,($Id+'-'+$ZgTransaction.transaction+'-previous.json'))
  if (-not $ZgTransaction.snapshot_captured) {
    $ZgTransaction.journal_hash = Get-ZgJournalHash; $ZgTransaction.config_hash = Get-ZgHash $ZgConfig; $ZgTransaction.snapshot_captured=$true
  }
  Save-ZgPhase 'quiesced'
  if (-not [IO.File]::Exists($backup)) {
    if ((Get-ZgHash $ZgExe) -cne $ZgTransaction.old_hash) { throw 'Missing old image backup and unexpected active digest.' }
    [IO.File]::Copy($ZgExe,$backup,$false); Set-ZgAcl $backup ''
  }
  if ((Get-ZgHash $backup) -cne $ZgTransaction.old_hash) { throw 'Old image backup changed.' }
  if (-not [IO.File]::Exists($oldBinding)) {
    if ((Get-ZgHash $ZgBinding) -cne $ZgTransaction.old_binding_hash) { throw 'Missing old binding backup and unexpected active binding.' }
    [IO.File]::Copy($ZgBinding,$oldBinding,$false); Set-ZgAcl $oldBinding ''
  }
  if ((Get-ZgHash $oldBinding) -cne $ZgTransaction.old_binding_hash) { throw 'Old binding backup changed.' }
  $image = Get-ZgImage
  try {
    $imageHash = Get-ZgHash ([IO.Path]::Combine($image,'zunder-guard.exe'))
    if ($ZgTransaction.new_hash -and $ZgTransaction.new_hash -cne $imageHash) { throw 'New admitted release digest changed.' }
    $ZgTransaction.new_hash = $imageHash; Save-ZgPhase 'promoting-image'
    $activeHash = Get-ZgHash $ZgExe
    if ($activeHash -cne $ZgTransaction.old_hash -and $activeHash -cne $imageHash) { throw 'Unknown interrupted image state.' }
    Install-ZgImage $image # finish notices as well if a prior process died after binary promotion
    Save-ZgPhase 'promoting-binding'
    $metadata = [IO.File]::ReadAllText($oldBinding) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $metadata.executable_sha256 = $imageHash
    Write-ZgJson $ZgBinding $metadata; Set-ZgAcl $ZgBinding $ZgSid
    Invoke-ZgGuard @('service','check','--binding',$ZgBinding)
    if ((Get-ZgHash $ZgConfig) -cne $ZgTransaction.config_hash -or (Get-ZgJournalHash) -cne $ZgTransaction.journal_hash) { throw 'Configuration or journal changed during disabled upgrade; no rollback of state attempted.' }
    Assert-ZgStopped; Save-ZgPhase 'admitted-disabled'
  } finally { [IO.Directory]::Delete($image,$true) }
}
function Read-ZgHttp([string]$Uri) {
  $request = [Net.HttpWebRequest]::Create($Uri)
  $request.Proxy = $null; $request.AllowAutoRedirect = $false; $request.Timeout = 5000; $request.ReadWriteTimeout = 5000
  $response = $request.GetResponse()
  try {
    if ([int]$response.StatusCode -ne 200) { throw 'Loopback readiness request did not succeed.' }
    $reader = [IO.StreamReader]::new($response.GetResponseStream())
    try {
      $buffer = [char[]]::new(65537); $count = $reader.ReadBlock($buffer,0,$buffer.Length)
      if ($count -gt 65536) { throw 'Oversized readiness response.' }
      return [string]::new($buffer,0,$count)
    } finally { $reader.Dispose() }
  } finally { $response.Dispose() }
}
function Get-ZgFeeReadiness($Fee,[string]$LicenceState) {
  if ($Network -eq 'testnet') {
    if ($Fee.mode -ne 'off') { throw 'Testnet requires fee mode off.' }
    return @{ mode='off'; approval='not_required'; trading_ready=$true }
  }
  if ($Fee.mode -eq 'fee_free') {
    if ($LicenceState -ne 'active') { throw 'Fee-free status requires an active licence.' }
    return @{ mode='fee_free'; approval='not_required'; trading_ready=$true }
  }
  if ($Fee.mode -ne 'builder') { throw 'Unsupported fee mode; trading readiness cannot be established.' }
  if ($Fee.approval.state -notin @('unchecked','approved','not_approved','refused_by_venue','refused_by_venue_builder')) { throw 'Missing or unsupported builder approval state.' }
  foreach ($value in @($Fee.entries_blocked,$Fee.charged,$Fee.paper)) { if ($value -isnot [bool]) { throw 'Builder fee readiness fields must be present booleans.' } }
  if ($Fee.paper) { throw 'Mainnet runtime cannot report paper fee state.' }
  return @{ mode='builder'; approval=$Fee.approval.state; entries_blocked=$Fee.entries_blocked; trading_ready=($Fee.approval.state -eq 'approved' -and -not $Fee.entries_blocked -and $Fee.charged) }
}
function Write-ZgActivationOutcome($Readiness) {
  if ($Readiness.trading_ready) { Microsoft.PowerShell.Utility\Write-Host "Owned $Network runtime is trading-ready for the admitted account, risk state and fee policy." }
  else {
    Microsoft.PowerShell.Utility\Write-Host "Service is running; trading remains blocked (builder approval: $($Readiness.approval))."
    Microsoft.PowerShell.Utility\Write-Host 'Review Mainnet approval with your main wallet at https://zunderlabs.com/approve. Guard never approves on your behalf. If the venue refuses the builder itself, contact Zunder support.'
  }
}
function Assert-ZgStatus($Status,[string]$Account,[string]$Cap,[bool]$Licensed,[long]$StartedAt) {
  foreach ($field in @('schema','version','mode','network','account','killed','risk','equity_cap','last_sync_ms','last_error','started_at_ms','licence','fee','journal_broken')) {
    if ($Status.PSObject.Properties.Name -notcontains $field) { throw 'Runtime readiness field missing.' }
  }
  if ($Status.schema -isnot [long] -and $Status.schema -isnot [int]) { throw 'Runtime schema must be an integer.' }
  if ($Status.risk.journal_ready -isnot [bool] -or $Status.journal_broken -isnot [bool]) { throw 'Runtime risk readiness requires boolean fields.' }
  if ($Status.started_at_ms -isnot [long] -and $Status.started_at_ms -isnot [int]) { throw 'Runtime start timestamp must be an integer.' }
  if ($Status.last_sync_ms -isnot [long] -and $Status.last_sync_ms -isnot [int]) { throw 'Runtime synchronization timestamp must be an integer.' }
  if ($null -ne $Status.killed -or $Status.mode -cne $Network -or $Status.network -cne $Network -or $Status.account -cne $Account -or $Status.risk.state -ne 'active' -or $Status.risk.journal_ready -ne $true -or $null -ne $Status.last_error -or $Status.journal_broken -ne $false) { throw 'Runtime mainnet/account/risk admission not ready.' }
  if ([string]$Status.equity_cap -cne $Cap -and [decimal]::Parse([string]$Status.equity_cap,[Globalization.CultureInfo]::InvariantCulture) -ne [decimal]::Parse($Cap,[Globalization.CultureInfo]::InvariantCulture)) { throw 'Runtime equity cap differs.' }
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  if ($Status.started_at_ms -lt $StartedAt -or $Status.last_sync_ms -lt $Status.started_at_ms -or $Status.last_sync_ms -gt ($now+5000) -or ($now-$Status.last_sync_ms) -gt 90000) { throw 'Runtime has no fresh synchronization for this start.' }
  if ($Licensed -and ($Status.licence.state -ne 'active' -or ($Network -eq 'mainnet' -and $Status.fee.mode -ne 'fee_free'))) { throw 'Validated licence is not active/fee-free in this runtime.' }
  $fee = Get-ZgFeeReadiness $Status.fee $Status.licence.state
  return @{ account=$Status.account; mode=$Status.mode; network=$Status.network; risk=$Status.risk.state; licence=$Status.licence.state; fee=$fee.mode; approval=$fee.approval; trading_ready=$fee.trading_ready; started_at_ms=$Status.started_at_ms; last_sync_ms=$Status.last_sync_ms }
}
function Wait-ZgReady([long]$StartedAt) {
  $listen = Get-ZgPublic @('config','get','listen')
  $uri = [Uri]::new('http://'+$listen)
  $ip = [Net.IPAddress]::Parse($uri.Host.Trim('[',']'))
  if (-not [Net.IPAddress]::IsLoopback($ip)) { throw 'Mainnet service readiness must use explicit loopback IP.' }
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  do {
    try {
      $service = Get-ZgService
      if ($service.State -ne 'Running' -or $service.ProcessId -eq 0) { throw 'SCM broker not running.' }
      $broker = CimCmdlets\Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
      if (-not $broker -or $broker.ExecutablePath -ine $ZgExe) { throw 'Broker identity mismatch.' }
      $connections = @(NetTCPIP\Get-NetTCPConnection -LocalPort $uri.Port -State Listen -ErrorAction Stop | Microsoft.PowerShell.Core\Where-Object { $_.LocalAddress -eq $ip.ToString() })
      $owners = @($connections.OwningProcess | Microsoft.PowerShell.Utility\Select-Object -Unique)
      if ($owners.Count -ne 1) { throw 'No unique owned loopback listener.' }
      $runtime = CimCmdlets\Get-CimInstance Win32_Process -Filter "ProcessId=$($owners[0])"
      if (-not $runtime -or $runtime.ExecutablePath -ine $ZgExe -or $runtime.ParentProcessId -ne $broker.ProcessId -or $runtime.CreationDate -lt $broker.CreationDate) { throw 'Listener is not the admitted broker child.' }
      $owner = CimCmdlets\Invoke-CimMethod -InputObject $runtime -MethodName GetOwnerSid
      if ($owner.ReturnValue -ne 0 -or $owner.Sid -cne $ZgSid) { throw 'Listener virtual account differs.' }
      $null = Read-ZgHttp ($uri.AbsoluteUri.TrimEnd('/')+'/healthz')
      $status = (Read-ZgHttp ($uri.AbsoluteUri.TrimEnd('/')+'/guard/status')) | Microsoft.PowerShell.Utility\ConvertFrom-Json
      if ($status.version -cne $ZgTransaction.tag.TrimStart('v') -or $status.schema -ne 1) { throw 'Runtime version/status schema differs from admitted release.' }
      $summary = Assert-ZgStatus $status $ZgTransaction.account $ZgTransaction.cap ([bool]$ZgTransaction.licence_hash) $StartedAt
      $again = CimCmdlets\Get-CimInstance Win32_Process -Filter "ProcessId=$($runtime.ProcessId)"
      if (-not $again -or $again.CreationDate -ne $runtime.CreationDate -or (Get-ZgService).ProcessId -ne $broker.ProcessId) { throw 'Runtime changed during readiness proof.' }
      return $summary
    } catch { Microsoft.PowerShell.Utility\Start-Sleep -Seconds 1 }
  } while ([DateTime]::UtcNow -lt $deadline)
  throw 'Owned runtime did not meet mainnet/account/risk/licence readiness; service is being disabled.'
}
function New-ZgTransaction([string]$Operation) {
  $value = [pscustomobject][ordered]@{
    schema=1; transaction=[Guid]::NewGuid().ToString('N'); operation=$Operation; id=$Id; service=$ZgServiceName;
    root=$ZgRoot; exe=$ZgExe; binding=$ZgBinding; account=$Account.ToLowerInvariant(); api_wallet='';
    tag=$Tag; release=$ReleaseDir; helper_hash=(Get-ZgHash ([IO.Path]::Combine($ReleaseDir,'install-windows-service.ps1')));
    rules=$Rules; cap=$EquityCap; licence_hash=''; phase=($Operation+'-planned'); new_hash=''; old_hash=''; old_binding_hash='';
    original_startup=''; original_running=$false; config_hash=''; journal_hash=''; snapshot_captured=$false; runtime_attempted=$false;
    startup_choice=''; readiness=$null; old_release=''; old_tag=''; old_helper_hash=''
  }
  if ($Network -eq 'testnet') { $value | Microsoft.PowerShell.Utility\Add-Member -NotePropertyName mode -NotePropertyValue 'testnet' }
  return $value
}
function Start-ZgOwnedRuntime { Microsoft.PowerShell.Management\Start-Service -Name $ZgServiceName }
function Complete-ZgStart {
  Confirm-ZgConsent
  if ($Startup -notin @('Manual','DelayedAuto')) { throw 'Explicit Startup Manual or DelayedAuto is required; no default activation.' }
  Disable-ZgService; $null=Get-ZgBinding
  Invoke-ZgGuard @('service','check','--binding',$ZgBinding)
  if (-not [IO.File]::Exists((Get-ZgJournalPath))) { throw 'Explicit scoped journal initialization is required.' }
  $ZgTransaction.runtime_attempted=$true; $ZgTransaction.startup_choice=$Startup; Save-ZgPhase 'activation-requested'
  Invoke-ZgSc @('config',$ZgServiceName,'start=','demand')
  $startedAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()-1000
  Start-ZgOwnedRuntime
  $ZgTransaction.readiness=Wait-ZgReady $startedAt
  Save-ZgPhase 'activation-committed'
  if ($Startup -eq 'DelayedAuto') { Invoke-ZgSc @('config',$ZgServiceName,'start=','delayed-auto') }
  Write-ZgActivationOutcome $ZgTransaction.readiness
}
function Invoke-ZgLifecycle {
  Initialize-ZgMachineContext -RuntimeModules
  if ($Id -notmatch '^[A-Za-z0-9-]{1,64}$') { throw 'Invalid instance ID.' }
  if ($Network -eq 'testnet' -and -not $Id.StartsWith('testnet-',[StringComparison]::Ordinal)) { throw 'Testnet requires a separate testnet- instance identity.' }
  if ($KeyStdin -and ($Network -ne 'testnet' -or $Action -notin @('Prepare','Resume'))) { throw 'Private unattended key input is Testnet Prepare/Resume only.' }
  $script:ZgServiceName = 'ZunderGuard-'+$Id
  $script:ZgManagement = [IO.Path]::Combine($ZgData,'management')
  $script:ZgTransactionPath = [IO.Path]::Combine($ZgManagement,($Id+'.json'))
  $script:ZgRoot = [IO.Path]::Combine($ZgData,$Id)
  $script:ZgHome = [IO.Path]::Combine($ZgRoot,'runtime')
  $script:ZgConfig = [IO.Path]::Combine($ZgHome,'guard.toml')
  $script:ZgBinaryDir = [IO.Path]::Combine($ZgBin,$Id)
  $script:ZgExe = [IO.Path]::Combine($ZgBinaryDir,'zunder-guard.exe')
  $script:ZgBinding = [IO.Path]::Combine($ZgRoot,'binding.json')
  $script:ZgSid = ''
  New-ZgDirectory $ZgData; New-ZgDirectory $ZgManagement
  # Exclusive OS file handle is the lock, not a PID file: crashes release it automatically.
  $lockPath = [IO.Path]::Combine($ZgManagement,($Id+'.lock'))
  if ([IO.File]::Exists($lockPath)) { Assert-ZgPath $lockPath }
  $lock = [IO.FileStream]::new($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  # Validation and Status are read-only. Cleanup is armed at the first admitted
  # owned service mutation, never merely because a name/path matches SCM.
  $cleanupOwnedMutation = $false
  try {
    $exists = [IO.File]::Exists($ZgTransactionPath)
    if ($exists) { $script:ZgTransaction = Read-ZgTransaction }
    elseif ($Action -ne 'Prepare') { throw 'No owned transaction. Refusing to adopt existing state.' }
    if ($Action -in @('Prepare','Upgrade')) {
      Confirm-ZgRelease $ReleaseDir $Tag
      if ((Get-ZgHash $PSCommandPath) -cne (Get-ZgManifestHash ([IO.Path]::Combine($ReleaseDir,'SHA256SUMS')) 'install-windows-service.ps1')) { throw 'Running lifecycle helper is not the signed release helper.' }
    } else {
      Assert-ZgCache
      if ((Get-ZgHash $PSCommandPath) -cne $ZgTransaction.helper_hash) { throw 'Use the exact retained helper named by this transaction.' }
    }
    switch ($Action) {
      'Prepare' {
        if ($exists -or (Get-ZgService) -or [IO.Directory]::Exists($ZgRoot) -or [IO.Directory]::Exists($ZgBinaryDir)) { throw 'Instance already exists. Use retained helper Resume/Upgrade; never Force or reinitialize.' }
        if ($Account -notmatch '^0x[0-9a-fA-F]{40}$' -or $ConfirmAccount -ine $Account -or $EquityCap -notmatch '^[0-9]+(?:\.[0-9]+)?$') { throw 'Explicit account/confirmation and decimal cap required.' }
        $script:ZgTransaction = New-ZgTransaction 'install'
        $image=Get-ZgImage
        try { $ZgTransaction.new_hash=Get-ZgHash ([IO.Path]::Combine($image,'zunder-guard.exe')) } finally { [IO.Directory]::Delete($image,$true) }
        Write-ZgJson $ZgTransactionPath $ZgTransaction
        $cleanupOwnedMutation = $true
        Complete-ZgPrepare
      }
      'Resume' {
        Confirm-ZgConsent
        if ($Tag -and ($Tag -cne $ZgTransaction.tag -or $ReleaseDir -cne $ZgTransaction.release)) { throw 'Resume must use the exact transaction release cache.' }
        $phase = $ZgTransaction.phase
        if ($phase -in @('activation-committed','stopped','uninstalled','rolled-back')) { throw 'Completed lifecycle: use explicit Upgrade or Start; loader never reinitializes.' }
        if ($ZgTransaction.operation -notin @('install','upgrade')) { throw 'Unknown transaction operation.' }
        $null=Get-ZgService # validate ownership before arming cleanup
        $cleanupOwnedMutation = $true
        Disable-ZgService
        if ($phase -eq 'activation-requested') { throw 'Interrupted activation left disabled. Review Status and explicitly Start again.' }
        if ($phase -eq 'journal-requested') {
          if ($Network -ne 'mainnet') { throw 'Testnet cannot adopt a Mainnet journal transaction.' }
          if (-not [IO.File]::Exists((Get-ZgJournalPath))) { throw 'Journal not committed; explicitly invoke JournalInit with a review note.' }
          $old = $env:ZUNDER_MAINNET_CONFIRM
          try { $env:ZUNDER_MAINNET_CONFIRM=$ConfirmAccount; Invoke-ZgGuard @('journal-show','--mode','mainnet') } finally { $env:ZUNDER_MAINNET_CONFIRM=$old }
          Save-ZgPhase 'journal-present'
        } elseif ($phase -in @('admitted-disabled','journal-present')) { Microsoft.PowerShell.Utility\Write-Host 'Preparation already complete; choose JournalInit/Start separately.' }
        elseif ($ZgTransaction.operation -eq 'install') { Complete-ZgPrepare }
        elseif ($ZgTransaction.operation -eq 'upgrade') { Complete-ZgUpgrade }
        else { throw 'Unknown transaction operation.' }
      }
      'JournalInit' {
        if ($Network -ne 'mainnet') { throw 'Testnet journal is created only during fresh init; no reinitialization or automatic resume.' }
        Confirm-ZgConsent
        if ([string]::IsNullOrWhiteSpace($Note)) { throw 'Explicit human review note required.' }
        if ([IO.File]::Exists((Get-ZgJournalPath))) { throw 'Existing journal is never initialized again or resumed automatically.' }
        $null=Get-ZgService; $null=Get-ZgBinding
        $cleanupOwnedMutation = $true
        Disable-ZgService; Save-ZgPhase 'journal-requested'
        $old=$env:ZUNDER_MAINNET_CONFIRM
        try { $env:ZUNDER_MAINNET_CONFIRM=$ConfirmAccount; Invoke-ZgGuard @('journal-init','--mode','mainnet','--note',$Note) } finally { $env:ZUNDER_MAINNET_CONFIRM=$old }
        Set-ZgAcl ((Get-ZgJournalPath)) $ZgSid $true
        Save-ZgPhase 'journal-present'
      }
      'Start' {
        Confirm-ZgConsent
        if ($Startup -notin @('Manual','DelayedAuto')) { throw 'Explicit Startup Manual or DelayedAuto is required; no default activation.' }
        $null=Get-ZgService; $null=Get-ZgBinding
        if (-not [IO.File]::Exists((Get-ZgJournalPath))) { throw 'Explicit scoped journal initialization is required.' }
        $cleanupOwnedMutation = $true
        Complete-ZgStart
      }
      'Stop' { Confirm-ZgConsent; $null=Get-ZgService; $cleanupOwnedMutation = $true; Disable-ZgService; Save-ZgPhase 'stopped' }
      'Status' {
        $service=Get-ZgService
        [pscustomobject]@{ phase=$ZgTransaction.phase; account=$ZgTransaction.account; tag=$ZgTransaction.tag; startup=$(if ($service) { $service.StartMode } else { 'unregistered' }); state=$(if ($service) { $service.State } else { 'unregistered' }); retained_helper=[IO.Path]::Combine($ZgTransaction.release,'install-windows-service.ps1') } | Microsoft.PowerShell.Utility\Format-List | Microsoft.PowerShell.Core\Out-Host
        if ([IO.File]::Exists($ZgBinding)) { Invoke-ZgGuard @('service','check','--binding',$ZgBinding) }
      }
      'Upgrade' {
        if (-not $exists) { throw 'Upgrade needs an owned installed instance.' }
        Confirm-ZgConsent; $oldTransaction=$ZgTransaction; Assert-ZgCache
        $service=Get-ZgService; $metadata=Get-ZgBinding
        if ($oldTransaction.phase -notin @('activation-committed','admitted-disabled','journal-present','stopped','rolled-back')) { throw 'A transaction is pending; use its exact retained helper Resume.' }
        $Account=$oldTransaction.account; $EquityCap=$oldTransaction.cap; $Rules=$oldTransaction.rules
        $script:ZgTransaction=New-ZgTransaction 'upgrade'
        $ZgTransaction.api_wallet=$oldTransaction.api_wallet; $ZgTransaction.licence_hash=$oldTransaction.licence_hash
        $ZgTransaction.old_hash=$metadata.executable_sha256; $ZgTransaction.old_binding_hash=Get-ZgHash $ZgBinding
        $ZgTransaction.original_startup=$service.StartMode; $ZgTransaction.original_running=($service.State -eq 'Running')
        $ZgTransaction.old_release=$oldTransaction.release; $ZgTransaction.old_tag=$oldTransaction.tag; $ZgTransaction.old_helper_hash=$oldTransaction.helper_hash
        Write-ZgJson ([IO.Path]::Combine($ZgManagement,($Id+'-'+$oldTransaction.transaction+'.history.json'))) $oldTransaction
        $image=Get-ZgImage
        try { $ZgTransaction.new_hash=Get-ZgHash ([IO.Path]::Combine($image,'zunder-guard.exe')) } finally { [IO.Directory]::Delete($image,$true) }
        Write-ZgJson $ZgTransactionPath $ZgTransaction
        $cleanupOwnedMutation = $true
        Complete-ZgUpgrade
      }
      'Recover' {
        Confirm-ZgConsent
        if ($Recovery -ne 'RollbackImage' -or $ZgTransaction.operation -ne 'upgrade' -or $ZgTransaction.runtime_attempted -or (Get-ZgJournalHash) -cne $ZgTransaction.journal_hash) { throw 'Image rollback requires explicit pre-start upgrade recovery and unchanged journal.' }
        Confirm-ZgRelease $ZgTransaction.old_release $ZgTransaction.old_tag
        $backup=[IO.Path]::Combine($ZgManagement,($Id+'-'+$ZgTransaction.transaction+'-previous.exe'))
        $oldBinding=[IO.Path]::Combine($ZgManagement,($Id+'-'+$ZgTransaction.transaction+'-previous.json'))
        if ((Get-ZgHash $backup) -cne $ZgTransaction.old_hash -or (Get-ZgHash $oldBinding) -cne $ZgTransaction.old_binding_hash) { throw 'Recovery backup does not match durable admission.' }
        $null=Get-ZgService
        $cleanupOwnedMutation = $true
        Disable-ZgService
        if ((Get-ZgJournalHash) -cne $ZgTransaction.journal_hash) { throw 'Journal changed while quiescing; rollback refused.' }
        $next=$ZgExe+'.recover-'+[Guid]::NewGuid().ToString('N'); [IO.File]::Copy($backup,$next,$false); Set-ZgAcl $next $ZgSid; [IO.File]::Replace($next,$ZgExe,$null)
        Write-ZgJson $ZgBinding ([IO.File]::ReadAllText($oldBinding) | Microsoft.PowerShell.Utility\ConvertFrom-Json); Set-ZgAcl $ZgBinding $ZgSid
        Invoke-ZgGuard @('service','check','--binding',$ZgBinding)
        $ZgTransaction.tag=$ZgTransaction.old_tag; $ZgTransaction.release=$ZgTransaction.old_release; $ZgTransaction.helper_hash=$ZgTransaction.old_helper_hash; $ZgTransaction.new_hash=$ZgTransaction.old_hash
        Save-ZgPhase 'rolled-back'
      }
      'Uninstall' { Confirm-ZgConsent; $null=Get-ZgService; $cleanupOwnedMutation = $true; Disable-ZgService; if (Get-ZgService) { Invoke-ZgSc @('delete',$ZgServiceName) }; Save-ZgPhase 'uninstalled'; Microsoft.PowerShell.Utility\Write-Host 'Registration removed; credential, licence, configuration, journals and recovery files retained.' }
    }
    if ($Action -in @('Prepare','Resume','Upgrade','JournalInit','Recover')) {
      $helper=[IO.Path]::Combine($ZgTransaction.release,'install-windows-service.ps1')
      Microsoft.PowerShell.Utility\Write-Host "Retained helper: $helper"
      if ($Network -eq 'testnet') {
        Microsoft.PowerShell.Utility\Write-Host "Service remains disabled. Testnet journal is preserved. Start with: $(Get-ZgHelperInvocation $helper) -Action Start -Network testnet -Id $Id -ConfirmAccount $($ZgTransaction.account) -Startup Manual or DelayedAuto."
      } else {
        Microsoft.PowerShell.Utility\Write-Host "Service remains disabled. Next explicit choices: $(Get-ZgHelperInvocation $helper) -Action JournalInit -Network $Network -Id $Id -ConfirmAccount $($ZgTransaction.account) -Note '<review note>'; then $(Get-ZgHelperInvocation $helper) -Action Start -Network $Network -Id $Id -ConfirmAccount $($ZgTransaction.account) -Startup Manual or DelayedAuto."
      }
    }
  } catch {
    if ($cleanupOwnedMutation) {
      try { Disable-ZgService } catch { Microsoft.PowerShell.Utility\Write-Warning 'Could not confirm owned service disabled/stopped; inspect SCM before continuing.' }
    }
    if ($cleanupOwnedMutation) {
      $recoveryHelper = [IO.Path]::Combine($ZgTransaction.release,'install-windows-service.ps1')
      Microsoft.PowerShell.Utility\Write-Warning "Recovery: $(Get-ZgHelperInvocation $recoveryHelper) -Action Status -Network $Network -Id $Id; then the same helper -Action Resume -Network $Network -Id $Id -ConfirmAccount <your account>. State is retained."
    } else { Microsoft.PowerShell.Utility\Write-Warning 'Action refused before owned service mutation; no stop or start was requested.' }
    throw
  } finally { $lock.Dispose() }
}

Invoke-ZgLifecycle
