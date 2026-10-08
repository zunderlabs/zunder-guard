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
