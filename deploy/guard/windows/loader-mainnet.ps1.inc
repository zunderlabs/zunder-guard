function Get-ZgLoaderRecordNetwork($Record) {
  $mode = if ($Record.PSObject.Properties.Name -contains 'mode') { $Record.mode } else { 'mainnet' }
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
