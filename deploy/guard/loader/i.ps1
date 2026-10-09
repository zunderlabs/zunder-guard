# zunderlabs.com/i.ps1: Zunder Guard for Windows (deploy/guard/README.md, "Windows").
#
#   irm https://zunderlabs.com/i.ps1 | iex                                          # guided setup
#   & ([scriptblock]::Create((irm https://zunderlabs.com/i.ps1))) -Rules zr1_... -Account 0x...
#   ... -Licence zgl1_...     a licence key for the account (checked by the binary before saving)
#
# Read it first:  irm https://zunderlabs.com/i.ps1 -OutFile i.ps1; notepad i.ps1
#                 powershell -ExecutionPolicy Bypass -File .\i.ps1 -Rules zr1_...
#
# What it does, refusing at the first thing that does not check out: downloads the release's
# SHA256SUMS, its Sigstore bundle and the Windows archive; verifies the bundle with cosign against
# the release workflow of zunderlabs/zunder-guard at exactly this tag (fetching a pinned cosign,
# checked by its SHA-256, if none is installed); checks the archive against the signed checksums;
# installs zunder-guard.exe for this user (no administrator rights); then runs
# `zunder-guard init`, which shows the rules and asks for the account, the mode (paper or
# testnet) and, for testnet, the API wallet key with hidden input. The key goes into the Windows
# Credential Manager (DPAPI, this user), never into a file. Explicit -Network mainnet uses
# a separately verified elevated machine-service path; setup leaves it disabled. Windows PowerShell 5.1 and PowerShell 7; never closes the window it runs in.
param(
  [string]$Rules = $env:ZUNDER_GUARD_RULES,
  [string]$Account = $env:ZUNDER_GUARD_ACCOUNT,
  # A licence key (zgl1_...) for the account; not a secret.
  [string]$Licence = $env:ZUNDER_GUARD_LICENCE,
  # Paper by default; protected Testnet additionally requires ManagedService and private KeyStdin.
  [string]$Network = '',
  [switch]$NonInteractive,
  # Explicit protected Testnet SCM path; key frames stay on private standard input.
  [switch]$ManagedService,
  [switch]$KeyStdin,
  # Download, verify and install; no setup.
  [switch]$InstallOnly,
  # Replace an existing configuration (the journals are kept).
  [switch]$Force,
  [string]$InstallDir = '',
  [string]$Id = 'guard',
  [string]$ConfirmAccount = '',
  [string]$EquityCap = ''
)

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

function Get-ZgLoaderRecordNetwork($Record) {
  $mode = if ($null -ne $Record.PSObject.Properties['mode']) { $Record.mode } else { 'mainnet' }
  if ($mode -cnotin @('mainnet','testnet')) { throw 'Unsupported owned sending network.' }
  return $mode
}
function Assert-ZgInteractiveConsole {
  if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected -or $Host.Name -ne 'ConsoleHost') { throw 'Mainnet needs an elevated interactive console; EOF or cancellation never confirms setup.' }
}
function Read-ZgPublicPrompt([string]$Message) { return Microsoft.PowerShell.Utility\Read-Host $Message }
function Invoke-ZgLifecycleHelper([string[]]$Words) {
  Assert-ZgHelperPolicy
  & $ZgPowerShell @Words
  if ($LASTEXITCODE -ne 0) { throw 'Verified service helper did not complete. Organization execution policy remains authoritative; no policy was changed. Inspect the preceding error and use the retained helper Status/Resume only for an owned pending setup.' }
}
function Install-ZgMainnet($Rules,$Account,$ConfirmAccount,$EquityCap,$Licence,$Id,$Tag,$Source,$NonInteractive,$InstallOnly,$Force,$InstallDir,$Network='mainnet',$KeyStdin=$false) {
  if ($Network -cnotin @('mainnet','testnet')) { throw 'Unsupported protected service network.' }
  if ($Network -eq 'mainnet') {
    if ($NonInteractive -or $KeyStdin -or $InstallOnly -or $Force -or $InstallDir) { throw 'Mainnet refuses NonInteractive, KeyStdin, InstallOnly, Force and alternate InstallDir.' }
  } else {
    if (-not $NonInteractive -or -not $KeyStdin -or $InstallOnly -or $Force -or $InstallDir -or -not [Console]::IsInputRedirected) { throw 'Protected Testnet requires NonInteractive, private KeyStdin and the machine installation.' }
    if (-not $Account -or -not $ConfirmAccount -or -not $EquityCap -or -not $Rules) { throw 'Protected Testnet requires explicit account, repeated account, equity cap and rules.' }
    if (-not $Id.StartsWith('testnet-',[StringComparison]::Ordinal)) { throw 'Testnet requires a separate testnet- instance identity.' }
  }
  $providedVerifier = $env:ZUNDER_GUARD_COSIGN
  Initialize-ZgMachineContext
  if ($Network -eq 'mainnet') { Assert-ZgInteractiveConsole }
  if ($Id -notmatch '^[A-Za-z0-9-]{1,64}$') { throw 'Invalid service instance Id.' }
  if (-not $Account) { $Account = Read-ZgPublicPrompt 'Hyperliquid main account address' }
  if ($Account -notmatch '^0x[0-9a-fA-F]{40}$') { throw 'Main account must have 40 hex digits.' }
  if (-not $ConfirmAccount) { $ConfirmAccount = Read-ZgPublicPrompt 'Type the same account again to confirm MAINNET' }
  if ($ConfirmAccount -notmatch '^0x[0-9a-fA-F]{40}$' -or $ConfirmAccount -ine $Account) { throw 'Explicit repeated account confirmation did not match.' }
  if (-not $EquityCap) { $EquityCap = Read-ZgPublicPrompt 'Maximum trading equity in USDC (greater than 0, at most 2500)' }
  if ($EquityCap -notmatch '^[0-9]+(?:\.[0-9]+)?$') { throw 'Equity cap must be a decimal string.' }
  $cap = [decimal]::Parse($EquityCap,[Globalization.CultureInfo]::InvariantCulture)
  if ($cap -le 0 -or $cap -gt 2500) { throw 'Equity cap is outside the existing mainnet ceiling.' }
  if ($Rules -and $Rules -notmatch '^zr1_[A-Za-z0-9_-]+$') { throw 'Invalid rules code.' }
  if ($Licence -and $Licence -notmatch '^zgl1_[A-Za-z0-9_.-]+$') { throw 'Invalid public licence key.' }
  New-ZgDirectory $ZgData
  $management = [IO.Path]::Combine($ZgData,'management'); New-ZgDirectory $management
  $releases = [IO.Path]::Combine($management,'releases'); New-ZgDirectory $releases
  $stage = [IO.Path]::Combine($management,('download-'+[Guid]::NewGuid().ToString('N'))); New-ZgDirectory $stage
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    foreach ($name in @('SHA256SUMS','SHA256SUMS.sigstore.json',"zunder-guard-$Tag-windows-amd64.zip",'install-windows-service.ps1')) { Get-ZgAsset $Source $name ([IO.Path]::Combine($stage,$name)) }
    # Never resolve a verifier through PATH. Offline override is copied, pinned and then executed only in protected staging.
    $verifier = [IO.Path]::Combine($stage,'cosign.exe')
    if ($providedVerifier) { [IO.File]::Copy($providedVerifier,$verifier,$false) }
    else { Get-ZgAsset 'https://github.com/sigstore/cosign/releases/download/v3.1.3' 'cosign-windows-amd64.exe' $verifier }
    Confirm-ZgRelease $stage $Tag
    $cache = [IO.Path]::Combine($releases,($Tag+'-'+(Get-ZgHash ([IO.Path]::Combine($stage,'SHA256SUMS')))))
    if ([IO.Directory]::Exists($cache)) { Confirm-ZgRelease $cache $Tag }
    else { [IO.Directory]::Move($stage,$cache); $stage = $null }
    $helper = [IO.Path]::Combine($cache,'install-windows-service.ps1')
    $invocation = Get-ZgHelperInvocation $helper
    $transaction = [IO.Path]::Combine($management,($Id+'.json'))
    $action = 'Prepare'
    if ([IO.File]::Exists($transaction)) {
      Assert-ZgPath $transaction
      if ([IO.FileInfo]::new($transaction).Length -gt 65536) { throw 'Oversized owned transaction refused.' }
      $prior = [IO.File]::ReadAllText($transaction) | Microsoft.PowerShell.Utility\ConvertFrom-Json
      if ($prior.schema -ne 1 -or $prior.id -cne $Id -or $prior.account -cne $Account.ToLowerInvariant() -or (Get-ZgLoaderRecordNetwork $prior) -cne $Network) { throw 'Existing transaction identity differs; nothing was changed.' }
      Microsoft.PowerShell.Utility\Write-Host "Verified lifecycle helper: $helper"
      if ($prior.phase -in @('activation-committed','stopped','admitted-disabled','journal-present','rolled-back')) {
        Microsoft.PowerShell.Utility\Write-Host "Existing instance retained. Explicit upgrade: $invocation -Action Upgrade -Network '$Network' -Id '$Id' -ReleaseDir '$cache' -Tag '$Tag' -ConfirmAccount '$ConfirmAccount'"
        Microsoft.PowerShell.Utility\Write-Host 'No service was stopped or started. For activation without upgrade use the retained installation helper Start command.'
        return
      }
      if ($prior.phase -eq 'uninstalled') { throw 'Uninstalled instance data is retained; automatic adoption/reinitialization is refused.' }
      if ($prior.tag -cne $Tag -or $prior.release -cne $cache) { throw 'Pending transaction belongs to another release. Use its retained helper Status/Resume; no service was changed.' }
      $action = 'Resume'
    }
    $words = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$helper,'-Action',$action,'-Id',$Id,'-ReleaseDir',$cache,'-Tag',$Tag,'-Account',$Account,'-ConfirmAccount',$ConfirmAccount,'-EquityCap',$EquityCap)
    if ($Network -eq 'testnet') { $words += @('-Network','testnet','-KeyStdin') }
    if ($Rules) { $words += @('-Rules',$Rules) }
    if ($Licence) { $words += @('-Licence',$Licence) }
    Invoke-ZgLifecycleHelper $words
    Microsoft.PowerShell.Utility\Write-Host "Verified lifecycle helper: $helper"
    if ($Network -eq 'testnet') { Microsoft.PowerShell.Utility\Write-Host 'Nothing started. Use the printed Testnet Start command; its fresh journal is already initialized.' }
    else { Microsoft.PowerShell.Utility\Write-Host 'Nothing started. Review the printed JournalInit and Start commands separately.' }
  } finally { if ($stage -and [IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage,$true) } }
}

function Install-ZunderGuard {
  param($Rules, $Account, $Licence, $Network, $NonInteractive, $InstallOnly, $Force, $InstallDir, $Id, $ConfirmAccount, $EquityCap, $ManagedService, $KeyStdin)
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $V = '@VERSION@'
  $Repo = 'zunderlabs/zunder-guard'
  $Issuer = 'https://token.actions.githubusercontent.com'
  $Identity = "https://github.com/$Repo/.github/workflows/release.yml@refs/tags/$V"
  $Base = "https://github.com/$Repo/releases/download/$V"
  if ($env:ZUNDER_GUARD_BASE_URL) { $Base = $env:ZUNDER_GUARD_BASE_URL }
  # cosign used when none is installed: github.com/sigstore/cosign, SHA-256 from that release's
  # cosign_checksums.txt (deploy/guard/test/resolve-pins.sh). The same version as loader/i.sh.
  $CosignVersion = 'v3.1.3'
  $CosignSha256 = '9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be'

  if ($KeyStdin -and ($Network -ne 'testnet' -or -not $ManagedService)) { throw 'Private KeyStdin requires explicit protected Testnet service setup.' }
  if ($ManagedService -and $Network -notin @('mainnet','testnet')) { throw 'Managed service requires a sending network.' }
  if ($Network -eq 'mainnet' -or ($Network -eq 'testnet' -and $ManagedService)) {
    Install-ZgMainnet $Rules $Account $ConfirmAccount $EquityCap $Licence $Id $V $Base $NonInteractive $InstallOnly $Force $InstallDir $Network $KeyStdin
    return
  }

  if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    throw 'i.ps1 is for Windows; on Linux and macOS: curl -fsSL https://zunderlabs.com/i | sh'
  }
  if (-not [Environment]::Is64BitOperatingSystem) { throw 'zunder-guard needs 64-bit Windows' }
  # x64 build; Windows 11 on ARM runs it through its x64 emulation.
  $Archive = "zunder-guard-$V-windows-amd64.zip"
  if (-not $Network) { $Network = '' }
  if ($Network -and $Network -notin @('paper', 'testnet')) {
    if ($Network -eq 'mainnet') { throw 'mainnet is not offered on Windows in Guard 1.0; use Linux (the SSH installer)' }
    throw "-Network is paper or testnet, got $Network"
  }
  if ($Rules -and $Rules -notmatch '^zr1_[A-Za-z0-9_-]+$') { throw 'a rules string is zr1_ followed by base64url' }
  if ($Account -and $Account -notmatch '^0x[0-9a-fA-F]{40}$') { throw 'an account address is 0x and 40 hex digits' }
  if ($Licence -and $Licence -notmatch '^zgl1_[A-Za-z0-9_.-]+$') { throw 'a licence key is zgl1_ followed by base64url' }
  if ($NonInteractive -and -not $InstallOnly) {
    if (-not $Rules) { throw '-NonInteractive needs -Rules' }
    if (-not $Account) { throw '-NonInteractive needs -Account' }
    if ($Network -and $Network -ne 'paper') { throw '-NonInteractive sets up paper mode; run it without -NonInteractive for testnet (the key is typed, hidden)' }
    $Network = 'paper'
  }
  if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\zunder-guard' }
  # Windows PowerShell 5.1 may still default to older TLS.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $Tmp = Join-Path ([IO.Path]::GetTempPath()) ("zunder-guard-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $Tmp | Out-Null
  try {
    function Get-Asset([string]$Name, [string]$From) {
      $To = Join-Path $Tmp $Name
      if ($From -like 'https://*') {
        try { Invoke-WebRequest -UseBasicParsing -Uri "$From/$Name" -OutFile $To }
        catch { throw "download failed: $From/$Name ($($_.Exception.Message)); refusing, nothing was installed" }
      } elseif (Test-Path -LiteralPath $From -PathType Container) {
        # A local copy of a release (tests, offline installs): verified exactly the same way.
        Copy-Item -LiteralPath (Join-Path $From $Name) -Destination $To
      } else {
        throw "ZUNDER_GUARD_BASE_URL must be an https:// URL or a folder, got $From"
      }
      return $To
    }
    function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

    Write-Host "Zunder Guard $V for Windows: downloading and verifying the release"
    $Sums = Get-Asset 'SHA256SUMS' $Base
    $Bundle = Get-Asset 'SHA256SUMS.sigstore.json' $Base
    $Zip = Get-Asset $Archive $Base

    $Cosign = $env:ZUNDER_GUARD_COSIGN
    if (-not $Cosign) {
      $Found = Get-Command cosign -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($Found) { $Cosign = $Found.Source }
    }
    if (-not $Cosign) {
      Write-Host "cosign is not installed: fetching cosign $CosignVersion and checking its pinned SHA-256"
      $Cosign = Get-Asset 'cosign-windows-amd64.exe' "https://github.com/sigstore/cosign/releases/download/$CosignVersion"
      if ((Get-Sha256 $Cosign) -ne $CosignSha256) { throw 'the cosign download does not match its pinned SHA-256; refusing' }
    }
    # cosign reports on stderr; Windows PowerShell 5.1 would turn that into a terminating error.
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $Log = & $Cosign verify-blob --bundle $Bundle --certificate-identity $Identity --certificate-oidc-issuer $Issuer $Sums 2>&1
    $Code = $LASTEXITCODE
    $ErrorActionPreference = $Previous
    if ($Code -ne 0) {
      $Log | ForEach-Object { Write-Host $_ }
      throw "signature check FAILED: SHA256SUMS was not signed by $Repo's release workflow for $V; refusing"
    }
    Write-Host "  signature: SHA256SUMS signed by $Repo, release workflow, tag $V (Sigstore)"
    $Expected = $null
    foreach ($Line in Get-Content -LiteralPath $Sums) {
      $Fields = $Line -split '\s+', 2
      if ($Fields.Count -eq 2 -and ($Fields[1] -eq $Archive -or $Fields[1] -eq "*$Archive")) { $Expected = $Fields[0].ToLowerInvariant() }
    }
    if (-not $Expected) { throw "$Archive is not in the signed checksums; refusing" }
    if ((Get-Sha256 $Zip) -ne $Expected) { throw "checksum mismatch for $Archive; refusing" }
    Write-Host "  checksum:  $Archive matches"

    $Unpacked = Join-Path $Tmp 'x'
    Expand-Archive -LiteralPath $Zip -DestinationPath $Unpacked
    $New = Join-Path $Unpacked 'zunder-guard.exe'
    if (-not (Test-Path -LiteralPath $New -PathType Leaf)) { throw 'the archive holds no zunder-guard.exe' }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $Exe = Join-Path $InstallDir 'zunder-guard.exe'
    try { Copy-Item -LiteralPath $New -Destination $Exe -Force }
    catch { throw "could not replace $Exe (is Guard running? stop it first): $($_.Exception.Message)" }
    foreach ($Notice in 'LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md', 'README.md') {
      $From = Join-Path $Unpacked $Notice
      if (Test-Path -LiteralPath $From) { Copy-Item -LiteralPath $From -Destination (Join-Path $InstallDir $Notice) -Force }
    }
    $Version = (& $Exe --version) -join ''
    if ($Version -ne "zunder-guard $($V.TrimStart('v'))") { throw "installed binary reports '$Version', expected $V" }
    Write-Host "Installed $Version to $Exe"
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($UserPath -split ';') -contains $InstallDir)) {
      $Joined = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
      [Environment]::SetEnvironmentVariable('Path', $Joined, 'User')
      Write-Host "  added $InstallDir to your PATH (new terminals)"
    }
    if (-not (($env:Path -split ';') -contains $InstallDir)) { $env:Path = "$env:Path;$InstallDir" }

    if ($InstallOnly) {
      Write-Host 'Installed only. Set Guard up with: zunder-guard init --interactive --rules zr1_...'
      return
    }
    $InitArgs = @('init')
    if ($NonInteractive) {
      $InitArgs += @('--non-interactive', '--network', 'paper', '--rules', $Rules, '--account', $Account)
    } else {
      $InitArgs += '--interactive'
      if ($Rules) { $InitArgs += @('--rules', $Rules) }
      if ($Account) { $InitArgs += @('--account', $Account) }
      if ($Network) { $InitArgs += @('--network', $Network) }
    }
    if ($Licence) { $InitArgs += @('--licence', $Licence) }
    if ($Force) { $InitArgs += '--force' }
    & $Exe @InitArgs
    if ($LASTEXITCODE -ne 0) { throw "zunder-guard init stopped (exit $LASTEXITCODE); nothing was started" }
    $Mode = (& $Exe config get network) -join ''
    Write-Host ''
    Write-Host 'Start Guard (it runs in this window; Ctrl-C stops it):'
    Write-Host "  zunder-guard run --network $Mode"
    Write-Host 'It listens on 127.0.0.1:8547 only. Start at every logon instead: see https://zunderlabs.com/docs/deploy/windows'
  } finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Install-ZunderGuard -Rules $Rules -Account $Account -Licence $Licence -Network $Network -NonInteractive:$NonInteractive `
  -InstallOnly:$InstallOnly -Force:$Force -InstallDir $InstallDir -Id $Id -ConfirmAccount $ConfirmAccount -EquityCap $EquityCap -ManagedService:$ManagedService -KeyStdin:$KeyStdin
