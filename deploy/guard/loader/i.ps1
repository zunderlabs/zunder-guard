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
# Credential Manager (DPAPI, this user), never into a file. Mainnet is not offered on Windows in
# 1.0. Windows PowerShell 5.1 and PowerShell 7; never closes the window it runs in.
param(
  [string]$Rules = $env:ZUNDER_GUARD_RULES,
  [string]$Account = $env:ZUNDER_GUARD_ACCOUNT,
  # A licence key (zgl1_...) for the account; not a secret.
  [string]$Licence = $env:ZUNDER_GUARD_LICENCE,
  # paper (default) or testnet; with -NonInteractive only paper (a testnet key is typed).
  [string]$Network = '',
  [switch]$NonInteractive,
  # Download, verify and install; no setup.
  [switch]$InstallOnly,
  # Replace an existing configuration (the journals are kept).
  [switch]$Force,
  [string]$InstallDir = ''
)

function Install-ZunderGuard {
  param($Rules, $Account, $Licence, $Network, $NonInteractive, $InstallOnly, $Force, $InstallDir)
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
  -InstallOnly:$InstallOnly -Force:$Force -InstallDir $InstallDir
