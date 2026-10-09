# Actual signed protected Testnet SCM stages. Invoke only through source-pinned native transport.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('preflight','prepare','exercise','before-reboot','resume','quiesce','cleanup','report')][string]$Stage,
      [Parameter(Mandatory)][string]$Request,[Parameter(Mandatory)][string]$State,
      [Parameter(Mandatory)][string]$Output)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Need([bool]$Value,[string]$Message) { if(-not $Value){throw $Message} }
function Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Utc { return [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') }
function Trusted-Path([string]$Path,[bool]$Private,[bool]$Directory) {
  Need ([IO.Path]::IsPathRooted($Path) -and [IO.Path]::GetFullPath($Path) -ceq $Path -and -not $Path.StartsWith('\\') -and -not $Path.Substring(2).Contains(':')) 'Canonical local native path required'
  $Current=$Path;$First=$true
  while($Current){
    $Item=Get-Item -LiteralPath $Current
    Need (-not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Linked native ancestor refused'
    if($First){Need ($Item.PSIsContainer -eq $Directory) 'Wrong native file kind'}else{Need ($Item.PSIsContainer) 'Wrong native ancestor kind'}
    $Acl=Get-Acl -LiteralPath $Current;$Owner=$Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Need ($Owner -in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) 'Untrusted native owner'
    foreach($Rule in $Acl.Access){if($Rule.AccessControlType -eq 'Allow'){
      $Sid=$Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      if($Sid -in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)){continue}
      if($First -and $Private){throw 'Unconfined private native path'}
      $Allowed=0x1200a9
      if($Current -ceq [IO.Path]::GetPathRoot($Current)){$Allowed=$Allowed -bor 6}
      Need (([int]$Rule.FileSystemRights -band (-bnot $Allowed)) -eq 0) 'Unprivileged native path mutation rights'
    }}
    if($Current -ceq [IO.Path]::GetPathRoot($Current)){break}
    $Current=[IO.Path]::GetDirectoryName($Current);$First=$false
  }
  if(-not $Directory){[ZunderNative]::SingleLink($Path)}
}
function Private-Path([string]$Path,[bool]$Directory) { Trusted-Path $Path $true $Directory }
function Save {
  $Temporary=Join-Path $State ([Guid]::NewGuid().ToString('N')+'.pending')
  [IO.File]::WriteAllText($Temporary,($script:Checkpoint|ConvertTo-Json -Depth 32))
  Move-Item -LiteralPath $Temporary -Destination (Join-Path $State 'state.json') -Force
}
function Check([string]$Name,[string]$Text,$Extra=@{}) {
  $Value=@{result='passed';observed_at=(Utc);observation=$Text;logs=@('native-events.jsonl')}
  foreach($Key in $Extra.Keys){$Value[$Key]=$Extra[$Key]}
  $script:Checkpoint.checks[$Name]=$Value;Save
}
function Event([string]$Name,$Value=@{}) {
  $script:Events.Add(@{at=(Utc);event=$Name;data=$Value})
  if($null -ne $script:Checkpoint){$script:Checkpoint.events=@($script:Events)}
}
function Native([string]$Exe,[string[]]$Words,[byte[]]$InputBytes=$null,[int]$Timeout=300) {
  $null=[ZunderNative]::Execute($Exe,$Words,$InputBytes,$Timeout)
}
function Public-Check([string]$Name,[string[]]$Words=@()) {
  $Destination=Join-Path $State ([Guid]::NewGuid().ToString('N')+'.public.json')
  Native $script:Python (@('-B',(Join-Path $PSScriptRoot 'windows_checks.py'),$Name,'--request',$Request,'--output',$Destination)+$Words) $null 1200
  Private-Path $Destination $false
  try{return Get-Content -LiteralPath $Destination -Raw|ConvertFrom-Json -AsHashtable}finally{Remove-Item -LiteralPath $Destination}
}
function Flat {
  $Observation=Public-Check 'flat';Need ($Observation.complete -eq $true) 'Actual complete flat scan missing'
  Event 'actual-full-dex-flat' @{inventory_sha256=$Observation.inventory_sha256;dex_count=$Observation.dexes.Count;started_at=$Observation.started_at;finished_at=$Observation.finished_at}
}
function Fee-Free {
  if($null -eq $script:Plan.licence){return $false}
  Need ($script:Plan.licence -cmatch '^zgl1_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$') 'Exact licence encoding missing'
  $Payload=$Matches[1];$Padded=$Payload.Replace('-','+').Replace('_','/');while($Padded.Length%4){$Padded+='='}
  $Bytes=[Convert]::FromBase64String($Padded)
  Need ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') -ceq $Payload) 'Noncanonical licence payload'
  $LicencePayload=[Text.Encoding]::UTF8.GetString($Bytes)|ConvertFrom-Json
  Need ($LicencePayload.features -is [Array] -and @($LicencePayload.features|Where-Object{$_ -cne 'fee_free'}).Count -eq 0) 'Unknown configured licence feature'
  return $LicencePayload.features -ccontains 'fee_free'
}
function Stopped {
  $Service=Owned-Service;Need ($Service.State -ceq 'Stopped' -and $Service.ProcessId -eq 0) 'Owned SCM service did not stop'
  $Listeners=@(Get-NetTCPConnection -LocalPort 8547 -State Listen -ErrorAction SilentlyContinue)
  Need ($Listeners.Count -eq 0) 'Native loopback listener remains'
  Need (@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -ieq $script:Exe}).Count -eq 0) 'Native broker/runtime child survives stop'
}
function Configured {
  $Metadata=Get-Content -LiteralPath $script:Binding -Raw|ConvertFrom-Json
  $Service=Owned-Service;$Sid=([Security.Principal.NTAccount]::new($Service.StartName)).Translate([Security.Principal.SecurityIdentifier]).Value
  Need ($Metadata.mode -ceq 'testnet' -and $Metadata.account -ceq $script:Plan.account -and $Metadata.api_wallet -ceq $script:Plan.api_wallet -and $Metadata.executable -ieq $script:Exe -and $Metadata.home -ieq $script:NativeHome -and $Metadata.identity.service_name -ceq 'ZunderGuard-testnet-native' -and $Metadata.identity.service_sid -ceq $Sid -and $Metadata.executable_sha256 -ceq (Sha $script:Exe)) 'Protected binding identity differs'
  $null=Public-Check 'config' @('--binary',$script:Exe,'--work',$script:NativeHome)
  Native $script:Exe @('service','check','--binding',$script:Binding)
}
function Confinement {
  $Credential=Join-Path $script:Root 'credential.dpapi';Need ((Get-Item -LiteralPath $Credential).Length -gt 0 -and (Get-Item -LiteralPath $Credential).Length -le 65536) 'Bounded protected DPAPI credential missing'
  $Sid=([Security.Principal.NTAccount]::new((Owned-Service).StartName)).Translate([Security.Principal.SecurityIdentifier]).Value
  foreach($Path in @($script:Root,$script:Binding,$script:Exe,$Credential)){
    $Item=Get-Item -LiteralPath $Path;Need (-not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Linked protected resource'
    $Acl=Get-Acl -LiteralPath $Path;Need ($Acl.AreAccessRulesProtected) 'Protected service ACL inherits ambient rights'
    foreach($Rule in $Acl.Access){if($Rule.AccessControlType -eq 'Allow'){
      $Identity=$Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      Need ($Identity -in @('S-1-5-18','S-1-5-32-544',$Sid)) 'Unprivileged credential access'
      if($Identity -ceq $Sid){Need (([int]$Rule.FileSystemRights -band 0x000d0116) -eq 0) 'Service credential path admits mutation'}
    }}
  }
  Need (-not (Test-Path -LiteralPath (Join-Path $script:NativeHome 'api.key'))) 'Unprotected key fallback exists'
  Native $script:Exe @('service','check','--binding',$script:Binding)
  Check 'credential_confinement' 'Actual virtual-service DPAPI binding/ACL admitted; no plaintext fallback'
}
function No-Writes {
  $Observation=Public-Check 'journal' @('--path',(Join-Path $script:NativeHome 'decisions.jsonl'))
  Need ($Observation.no_venue_orders -eq $true) 'Native decision/send activity exists'
  $script:Checkpoint.no_venue_orders=$true;Save
  Event 'actual-zero-native-order-intents' @{decision_records=$Observation.records}
}
function Scan-Native {
  $Reference=Join-Path $State 'key-fingerprints.json';Private-Path $Reference $false
  $Observation=Public-Check 'scan' @('--path',$script:Root,'--reference',$Reference)
  Event 'actual-native-secret-scan' $Observation
  foreach($Folder in @((Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'),(Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue'),(Join-Path $env:windir 'Minidump'))){
    if(Test-Path -LiteralPath $Folder){$Observation=Public-Check 'scan' @('--path',$Folder,'--reference',$Reference);Event 'actual-os-crash-secret-scan' $Observation}
  }
}
function Controller-Guards {
  Need (@(Get-CimInstance Win32_PageFileUsage).Count -eq 0) 'No active paging file required before input'
  $Power=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
  Need ($Power.HibernateEnabled -eq 0) 'Hibernation must be disabled before native custody'
  $Crash=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
  Need ($Crash.CrashDumpEnabled -eq 0 -and $null -eq $Crash.PSObject.Properties['DedicatedDumpFile']) 'Controller OS crash dump policy refuses input'
  foreach($Hive in @('HKLM:','HKCU:')){
    foreach($Suffix in @('SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps','SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting')){
      Need (-not (Test-Path -LiteralPath ($Hive+'\'+$Suffix))) 'Controller managed crash dump policy refuses input'
    }
  }
  $Excluded=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
  foreach($Name in @('pwsh.exe','python.exe')){Need ($Excluded.$Name -eq 1) 'Explicit controller WER exclusion required before input'}
  Event 'actual-windows-controller-memory-policy' @{no_paging=$true;hibernation=$false;managed_dumps=$false;controller_wer_excluded=$true;heap_locking=$false}
}
function Action([string]$Name,[string[]]$Words) {
  $script:Checkpoint.pending=$Name;Save
  Native $script:PowerShell (@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$script:Helper)+$Words)
  $script:Checkpoint.pending=$null;Save;Event $Name
}
function Readiness {
  $Until=[DateTimeOffset]::UtcNow.AddSeconds(90)
  while([DateTimeOffset]::UtcNow -lt $Until){
    try{
      $Value=Invoke-RestMethod -Uri 'http://127.0.0.1:8547/guard/status' -TimeoutSec 10 -MaximumRedirection 0
      Need ($Value.mode -ceq 'testnet' -and $Value.network -ceq 'testnet' -and $Value.account -ceq $script:Plan.account -and $Value.version -ceq $script:Plan.tag.Substring(1)) 'Actual native runtime identity differs'
      Need ($Value.risk.state -ceq 'active' -and $Value.risk.journal_ready -eq $true -and -not $Value.journal_broken -and $null -eq $Value.killed -and $null -eq $Value.last_error -and $Value.last_sync_ms -ge $Value.started_at_ms -and $Value.last_sync_ms -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()-$Value.last_sync_ms -le 60000) 'Actual Windows sync/risk not ready'
      $Expected=if($null -eq $script:Plan.licence){'none'}else{'active'}
      $Fee=if(Fee-Free){'fee_free'}else{'off'}
      Need ($Value.licence.state -ceq $Expected -and $Value.fee.mode -ceq $Fee) 'Actual Windows fee/licence differs'
      Need ([decimal]$Value.equity_cap -eq [decimal]$script:Plan.equity_cap) 'Actual native cap differs'
      $Service=Owned-Service;$Broker=Get-CimInstance Win32_Process -Filter "ProcessId=$($Service.ProcessId)"
      Need ($Broker.ExecutablePath -ieq $script:Exe) 'Native broker identity differs'
      $Owners=@(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8547 -State Listen|Select-Object -ExpandProperty OwningProcess -Unique)
      Need ($Owners.Count -eq 1) 'Unique native listener missing'
      $Child=Get-CimInstance Win32_Process -Filter "ProcessId=$($Owners[0])"
      $Owner=Invoke-CimMethod -InputObject $Child -MethodName GetOwnerSid
      $Sid=([Security.Principal.NTAccount]::new($Service.StartName)).Translate([Security.Principal.SecurityIdentifier]).Value
      Need ($Child.ExecutablePath -ieq $script:Exe -and $Child.ParentProcessId -eq $Broker.ProcessId -and $Owner.ReturnValue -eq 0 -and $Owner.Sid -ceq $Sid) 'Native listener virtual-service ancestry differs'
      return $Value
    }catch{Start-Sleep -Seconds 1}
  }
  throw 'Native readiness deadline'
}
function Owned-Service {
  $Service=Get-CimInstance Win32_Service -Filter "Name='ZunderGuard-testnet-native'"
  Need ($null -ne $Service -and $Service.StartName -ieq 'NT SERVICE\ZunderGuard-testnet-native' -and $Service.PathName -ceq ('"'+$script:Exe+'" service run --binding "'+$script:Binding+'"')) 'SCM service ownership differs'
  return $Service
}
function Snapshot {
  $Files=@{}
  foreach($Name in @('guard.toml','risk.jsonl','decisions.jsonl','client.key','kill')){
    $Path=Join-Path $script:NativeHome $Name
    if(-not [IO.File]::Exists($Path)){Need ($Name -in @('client.key','kill')) 'Actual config/journal missing';continue}
    Need ((Get-Item -LiteralPath $Path).Length -le 8388608) 'Bounded stopped snapshot required'
    $Bytes=[IO.File]::ReadAllBytes($Path)
    if($Name.EndsWith('.jsonl')){
      $Length=$Bytes.Length;while($Length -gt 0 -and $Bytes[$Length-1] -eq 0){$Length--}
      Need ($Length -gt 0 -or $Name -ceq 'decisions.jsonl') 'Complete journal record required'
      if($Length -eq 0){$Bytes=[byte[]]@()}else{Need ($Bytes[$Length-1] -eq 10) 'Incomplete stopped journal';$Bytes=[byte[]]$Bytes[0..($Length-1)]}
    }
    Need (($Bytes.Length -gt 0 -or $Name -ceq 'decisions.jsonl') -and $Bytes.Length -le 8388608) 'Bounded runtime state required'
    $Files[$Name]=@{sha256=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($Bytes))).Replace('-','').ToLowerInvariant();bytes=$Bytes.Length}
  }
  return $Files
}
function Preserved($Before) {
  $After=Snapshot
  foreach($Name in $Before.Keys){
    $Bytes=[IO.File]::ReadAllBytes((Join-Path $script:NativeHome $Name));$Count=$Before[$Name].bytes
    Need ($Bytes.Length -ge $Count) 'Runtime state truncated'
    $Slice=if($Name.EndsWith('.jsonl')){if($Count -eq 0){[byte[]]@()}else{$Bytes[0..($Count-1)]}}else{$Bytes}
    $Digest=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([byte[]]$Slice))).Replace('-','').ToLowerInvariant()
    Need ($Digest -ceq $Before[$Name].sha256) 'Actual runtime identity/journal prefix changed'
  }
}
function Start-Owned { Action 'start-owned' @('-Action','Start','-Network','testnet','-Id','testnet-native','-ConfirmAccount',$script:Plan.account,'-Startup','DelayedAuto');$null=Readiness }
function Stop-Owned { Action 'stop-owned' @('-Action','Stop','-Network','testnet','-Id','testnet-native','-ConfirmAccount',$script:Plan.account);Stopped }
function Verify-Subject { return Public-Check 'source' @('--binary',$script:Exe) }
function Signed-Upgrade {
  $script:Checkpoint.pending='signed-upgrade';Save
  Native $script:PowerShell @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$script:Helper,'-Action','Upgrade','-Network','testnet','-Id','testnet-native','-ConfirmAccount',$script:Plan.account,'-ReleaseDir',$script:Release,'-Tag',$script:Plan.tag)
  $script:Checkpoint.pending=$null;Save;Stopped
}
function Interrupted-Upgrade {
  Flat;Stop-Owned;$Before=Snapshot;$Credential=Sha (Join-Path $script:Root 'credential.dpapi');$Binary=Sha $script:Exe;$Metadata=Sha $script:Binding
  $script:Checkpoint.pending='actual-interrupted-upgrade';Save
  $Words=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$script:Helper,'-Action','Upgrade','-Network','testnet','-Id','testnet-native','-ConfirmAccount',$script:Plan.account,'-ReleaseDir',$script:Release,'-Tag',$script:Plan.tag)
  $Child=[ZunderNative]::StartOwned($script:PowerShell,$Words);$Interrupted=$false;$Suspended=$false
  try{
    $Until=[DateTimeOffset]::UtcNow.AddSeconds(180)
    while([DateTimeOffset]::UtcNow -lt $Until -and -not $Child.HasExited){
      try{
        $Transaction=Get-Content -LiteralPath $script:Transaction -Raw|ConvertFrom-Json
        $Backup=Join-Path $script:Management ('testnet-native-'+$Transaction.transaction+'-previous.exe')
        $OldBinding=Join-Path $script:Management ('testnet-native-'+$Transaction.transaction+'-previous.json')
        if($Transaction.operation -ceq 'upgrade' -and $Transaction.phase -in @('quiesced','promoting-image','promoting-binding') -and (Test-Path -LiteralPath $Backup) -and (Test-Path -LiteralPath $OldBinding)){
          [ZunderNative]::SuspendOwned($Child.Id);$Suspended=$true
          $Transaction=Get-Content -LiteralPath $script:Transaction -Raw|ConvertFrom-Json
          Need ($Transaction.phase -in @('quiesced','promoting-image','promoting-binding') -and -not $Transaction.runtime_attempted -and (Sha $Backup) -ceq $Binary -and (Sha $OldBinding) -ceq $Metadata) 'Actual interrupted transaction passed safe rollback window'
          $Child.Kill($true);Need ($Child.WaitForExit(5000)) 'Interrupted installer survives';$Interrupted=$true;break
        }
      }catch{if($Suspended){throw}}
      Start-Sleep -Milliseconds 10
    }
    Need ($Interrupted) 'Actual signed upgrade interruption window not observed; no synthetic credit'
  }finally{if(-not $Child.HasExited){$Child.Kill($true);Need ($Child.WaitForExit(5000)) 'Owned interrupted installer cleanup failed'};$Child.Dispose()}
  Stopped;Need ((Owned-Service).StartMode -ceq 'Disabled') 'Interrupted upgrade left boot enabled';Preserved $Before
  Native $script:PowerShell @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$script:Helper,'-Action','Recover','-Recovery','RollbackImage','-Network','testnet','-Id','testnet-native','-ConfirmAccount',$script:Plan.account)
  Stopped;Preserved $Before;Need ((Sha $script:Exe) -ceq $Binary -and (Sha $script:Binding) -ceq $Metadata -and (Sha (Join-Path $script:Root 'credential.dpapi')) -ceq $Credential) 'Signed rollback altered native identity or credential'
  $script:Checkpoint.pending=$null;Save
  Check 'interrupted_replacement_rollback' 'Actual signed helper interrupted before runtime; actual disabled SCM and signed rollback preserved binary/binding/credential/config/journals'
  Start-Owned;Configured;Confinement
}
function Interactive-Events {
  $BootStart=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  try{$Events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$BootStart} -ErrorAction Stop)}catch{Need ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') 'Security audit log unreadable';return @()}
  $Rows=@()
  foreach($Entry in $Events){
    $Xml=[xml]$Entry.ToXml();$Data=@{};foreach($Item in $Xml.Event.EventData.Data){$Data[$Item.Name]=[string]$Item.'#text'}
    if($Data.LogonType -in @('2','10','11')){$Rows+=@(@{at=$Entry.TimeCreated.ToUniversalTime();record_id=$Entry.RecordId;type=$Data.LogonType;name=$Data.TargetUserName;sid=$Data.TargetUserSid})}
  }
  return @($Rows|Sort-Object at)
}
function Audit-Probe([bool]$RequireFirst,[long]$ReadyAt=0) {
  # Machine-operated native interactive auth proves SCM readiness before a real
  # type2 Security4624 boundary, without a person or desktop automation.
  $Name='zg-native-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
  Need (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) 'Probe local identity exists'
  $Created=$false;$Password=$null;$Secure=$null;$Sid=$null
  $Description='Zunder native read-only logon proof '+$script:Plan.run_id+' '+$script:Plan.challenge
  $script:Checkpoint.probe_identity=@{name=$Name;description=$Description;sid=$null;created=$false};$script:Checkpoint.pending='create-owned-machine-auth-probe';Save
  try{
    if($RequireFirst){Need (@(Interactive-Events).Count -eq 0) 'An interactive login preceded observed native boot readiness'}
    $Password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))+'aA1!';$Secure=ConvertTo-SecureString $Password -AsPlainText -Force
    $User=New-LocalUser -Name $Name -Password $Secure -Description $Description -AccountExpires ([DateTime]::UtcNow.AddMinutes(5))
    $Created=$true;$Sid=$User.Sid.Value
    $script:Checkpoint.probe_identity.sid=$Sid;$script:Checkpoint.probe_identity.created=$true;Save
    $Users=([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    Add-LocalGroupMember -Group $Users -Member $Name
    Need ((Get-LocalUser -Name $Name).Sid.Value -ceq $Sid) 'Owned machine-auth identity changed before logon'
    $Observed=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Need ([ZunderNative]::InteractiveLogon($Name,$Password)) 'Actual type2 authentication failed'
    $Until=[DateTimeOffset]::UtcNow.AddSeconds(20);$Row=$null
    do{$Rows=@(Interactive-Events);$Matches=@($Rows|Where-Object{$_.sid -ceq $Sid -and $_.type -ceq '2'});if($Matches.Count -eq 1){$Row=$Matches[0];break};Start-Sleep -Milliseconds 200}while([DateTimeOffset]::UtcNow -lt $Until)
    Need ($null -ne $Row) 'Actual successful Security4624 audit event missing'
    $At=([DateTimeOffset]$Row.at).ToUnixTimeMilliseconds();Need ($At -ge $Observed -and $At -ge $ReadyAt) 'Actual login chronology precedes ready observation'
    if($RequireFirst){Need ($Rows[0].record_id -eq $Row.record_id) 'Probe was not first interactive logon after real boot'}
    Event 'actual-interactive-auth-audit' @{record_id=$Row.record_id;logon_type=2;event_at=$Row.at.ToString('o');first_after_boot=$RequireFirst;ready_observed_at_ms=$ReadyAt}
    return @{record_id=$Row.record_id;login_at=$Row.at.ToString('o');logon_type=2;ready_observed_at_ms=$ReadyAt;first_after_boot=$RequireFirst}
  }finally{
    try{
      $User=Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
      if($null -ne $User){
        Need ($User.Description -ceq $Description -and ($null -eq $Sid -or $User.Sid.Value -ceq $Sid)) 'Owned probe identity changed'
        # Planned random name was proven absent before creation. A matching
        # description also reconciles a cmdlet that created then threw.
        $script:Checkpoint.probe_identity.sid=$User.Sid.Value;$script:Checkpoint.probe_identity.created=$true;Save
        Remove-LocalUser -Name $Name;Need (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) 'Owned probe identity remains'
      }
      $script:Checkpoint.probe_identity.removed=$true;$script:Checkpoint.pending=$null;Save
    }finally{if($null -ne $Secure){$Secure.Dispose()};$Password=$null}
  }
}
function Dispose-Owned([string]$Path) {
  $Items=@(Get-ChildItem -LiteralPath $Path -Force -Recurse);Need ($Items.Count -le 4096) 'Owned disposal inventory bound'
  foreach($Item in (@(Get-Item -LiteralPath $Path)+$Items)){Need (-not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Linked owned disposable tree refused'}
  Remove-Item -LiteralPath $Path -Recurse -Force;Need (-not (Test-Path -LiteralPath $Path)) 'Owned runtime disposal incomplete'
}
$Started=Utc;$Events=[Collections.Generic.List[object]]::new();$Failure=$null
$Checkpoint=$null;$Plan=$null;$Boot=$null;$RequestHash=$null;$OutputReady=$false
try{
  Need ($PSVersionTable.PSVersion.Major -ge 7) 'PS7 native controller required'
  Need ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and [Environment]::Is64BitProcess) 'Native Windows x64 required'
  $Principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  Need ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Explicit elevated native controller required'
  Add-Type -Path (Join-Path $PSScriptRoot 'windows_native.cs')
  [ZunderNative]::OwnControllerJob()
  $Python='C:\Program Files\Python312\python.exe';Trusted-Path $Python $false $false
  Private-Path $Request $false;Private-Path $State $true;Private-Path ([IO.Path]::GetDirectoryName($Output)) $true
  Need (-not (Test-Path -LiteralPath $Output)) 'Fresh phase output required'
  $OutputReady=$true
  Need ((Get-Item -LiteralPath $Request).Length -le 262144) 'Bounded request required'
  $Plan=Get-Content -LiteralPath $Request -Raw|ConvertFrom-Json
  Need ($Plan.schema -eq 1 -and $Plan.route -ceq 'windows-amd64-scm' -and $Plan.network -ceq 'testnet' -and $Plan.account -match '^0x[0-9a-f]{40}$' -and $Plan.api_wallet -match '^0x[0-9a-f]{40}$' -and $Plan.source -match '^[0-9a-f]{40}$' -and $Plan.manifest_sha256 -match '^[0-9a-f]{64}$' -and $Plan.challenge -match '^[0-9a-f]{64}$' -and $Plan.listen -ceq '127.0.0.1:8547' -and $Plan.ip_share -ceq '1' -and [decimal]$Plan.equity_cap -gt 0 -and [decimal]$Plan.equity_cap -le 40) 'Exact bounded Testnet request required'
  $RequestHash=Sha $Request
  $Checkpoint=@{schema=1;request_sha256=$RequestHash;checks=@{};pending=$null;completed=@();events=@();cleanup=@{complete=$false;uncertain_writes=0;owned_resources_removed=$false}}
  $CheckpointPath=Join-Path $State 'state.json'
  if(Test-Path -LiteralPath $CheckpointPath){
    # PS7 controller keeps durable dictionaries; never load a foreign request/unknown transaction.
    Need ($PSVersionTable.PSVersion.Major -ge 7) 'PS7 controller required for durable phase dictionaries; signed helper still tests PS5.1'
    Private-Path $CheckpointPath $false;$Checkpoint=Get-Content -LiteralPath $CheckpointPath -Raw|ConvertFrom-Json -AsHashtable
    Need ($Checkpoint.request_sha256 -ceq $RequestHash -and $null -eq $Checkpoint.pending) 'Uncertain or foreign native phase; reconcile'
    foreach($Entry in $Checkpoint.events){$Events.Add($Entry)}
  }
  $PowerShell=[IO.Path]::Combine([Environment]::GetFolderPath('Windows'),'System32','WindowsPowerShell','v1.0','powershell.exe')
  $Root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ZunderGuard\testnet-native'
  $NativeHome=Join-Path $Root 'runtime';$Binding=Join-Path $Root 'binding.json'
  $Exe=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'ZunderGuard\testnet-native\zunder-guard.exe'
  $Helper=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('ZunderGuard\management\releases\'+$Plan.tag+'-'+$Plan.manifest_sha256+'\install-windows-service.ps1')
  $Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
  $Management=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ZunderGuard\management'
  $Transaction=Join-Path $Management 'testnet-native.json'
  $Release=Join-Path $Management ('releases\'+$Plan.tag+'-'+$Plan.manifest_sha256)
  if($Stage -eq 'preflight'){
    Need ($Checkpoint.completed.Count -eq 0 -and -not (Test-Path -LiteralPath $Root) -and -not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($Exe))) -and -not (Get-Service -Name 'ZunderGuard-testnet-native' -ErrorAction SilentlyContinue)) 'Fresh keyless native machine required'
    Controller-Guards;Private-Path $Plan.asset_dir $true;$null=Public-Check 'source'
    Need (@(Get-NetTCPConnection -LocalPort 8547 -State Listen -ErrorAction SilentlyContinue).Count -eq 0) 'Native listener already owned'
    $null=Audit-Probe $false
    $Checkpoint.preflight=@{source=$Plan.source;boot_identity=$Boot;os='windows';architecture='amd64';no_paging=$true};Save
    Event 'actual-keyless-windows-preflight' @{source_verified=$true;tools_verified=$true;architecture_verified=$true;fresh_owned_scope=$true;security_audit_verified=$true;custody_started=$false;native_acceptance_claim=$false}
  }elseif($Stage -eq 'prepare'){
    Need (-not (Test-Path -LiteralPath $Root) -and -not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($Exe))) -and $Checkpoint.completed.Count -eq 0 -and [Console]::IsInputRedirected -and -not (Get-Service -Name 'ZunderGuard-testnet-native' -ErrorAction SilentlyContinue)) 'Fresh owned machine state and private stdin required'
    if(Test-Path -LiteralPath $Management){Need (@(Get-ChildItem -LiteralPath $Management -Filter 'testnet-native*').Count -eq 0) 'Unowned same-instance management records exist'}
    Controller-Guards;Flat;Private-Path $Plan.asset_dir $true
    $Subject=Public-Check 'source';$Checkpoint.signed_subject=$Subject;Save
    $Frames=[ZunderNative]::ReadDuplicateFrames()
    try{
      $Reference=@{hex=[ZunderNative]::Fingerprint($Frames,$false);binary=[ZunderNative]::Fingerprint($Frames,$true)}
      $ReferencePath=Join-Path $State 'key-fingerprints.json';Need (-not (Test-Path -LiteralPath $ReferencePath)) 'Private fingerprint path already exists'
      [IO.File]::WriteAllText($ReferencePath,($Reference|ConvertTo-Json));Private-Path $ReferencePath $false
      $Checkpoint.pending='signed-install';Save
      $Loader=Join-Path $Plan.asset_dir 'i.ps1';$env:ZUNDER_GUARD_BASE_URL=$Plan.asset_dir
      $Words=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$Loader,'-Network','testnet','-ManagedService','-NonInteractive','-KeyStdin','-Id','testnet-native','-Account',$Plan.account,'-ConfirmAccount',$Plan.account,'-Rules',$Plan.rules,'-EquityCap',$Plan.equity_cap)
      if($null -ne $Plan.licence){$Words+=@('-Licence',$Plan.licence)}
      try{Native $PowerShell $Words $Frames 600}finally{Remove-Item Env:ZUNDER_GUARD_BASE_URL -ErrorAction SilentlyContinue}
    }finally{[Array]::Clear($Frames,0,$Frames.Length);$Frames=$null}
    $Checkpoint.pending=$null;Save
    Need ((Sha $Helper) -ceq $Plan.assets.'install-windows-service.ps1') 'Exact signed retained helper differs'
    $Subject=Verify-Subject;Check 'signed_install' 'Exact signed manifest/official Sigstore identity/SLSA source/tag and installed ZIP member digest verified' $Subject
    Configured;Confinement;Start-Owned;$Value=Readiness
    Check 'account_network_risk' 'Actual protected SCM account/API/network/rules/cap/share synchronizes under active journal'
    Check 'fee_licence' 'Actual validated configured Testnet licence features matched runtime fee' @{network='testnet';expected_licence_state=$(if($null -eq $Plan.licence){'absent'}else{'valid'});observed_licence_state=$(if($null -eq $Plan.licence){'absent'}else{'valid'});fee_mode=$Value.fee.mode;licence_fee_free=(Fee-Free);entitlement_receipt_sha256=$Plan.entitlement_receipt_sha256}
    $Checkpoint.agent_approved=$true;$Checkpoint.root_creation_utc=(Get-Item -LiteralPath $Root).CreationTimeUtc.ToString('o');$Checkpoint.binary_creation_utc=(Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($Exe))).CreationTimeUtc.ToString('o');$Checkpoint.completed+=@('prepare');Save;Scan-Native
  }elseif($Stage -eq 'exercise'){
    Need ($Checkpoint.completed -contains 'prepare' -and $Checkpoint.completed -notcontains 'exercise') 'Exact actual prepare required'
    $null=Verify-Subject;Configured;Confinement;Flat
    $Paper=Public-Check 'paper' @('--binary',$Exe,'--work',(Join-Path $State 'paper-probe'))
    Check 'pairing' 'Actual shipped signed MCP paired client, durable Paper allow and kill veto, zero venue sends' $Paper
    $BeforePid=(Owned-Service).ProcessId;Stop-Owned;$Before=Snapshot;Check 'explicit_stop' 'Actual owned SCM registration and all admitted runtime processes stopped'
    Start-Owned;Need ((Owned-Service).ProcessId -ne $BeforePid) 'SCM restart retained old broker';Stop-Owned;Preserved $Before
    Check 'restart' 'Actual fresh protected SCM broker/runtime synchronized';Check 'state_preservation' 'Actual stopped config/client/kill and journal prefixes survived restart'
    Start-Owned;Flat;$Service=Owned-Service;$BrokerPid=$Service.ProcessId;$Broker=Get-CimInstance Win32_Process -Filter "ProcessId=$BrokerPid"
    Need ($BrokerPid -gt 0 -and $Broker.ExecutablePath -ieq $Exe) 'Owned crash target identity differs'
    $Checkpoint.pending='actual-broker-crash';Save
    $Target=Get-Process -Id $BrokerPid;Need ($Target.StartTime.ToUniversalTime() -eq $Broker.CreationDate.ToUniversalTime() -and $Target.Path -ieq $Exe) 'Crash PID changed before owned handle kill';$Target.Kill();Need ($Target.WaitForExit(5000)) 'Crash target remains';$Target.Dispose()
    $null=Readiness;Need ((Owned-Service).ProcessId -ne $BrokerPid -and -not (Get-Process -Id $BrokerPid -ErrorAction SilentlyContinue)) 'Actual SCM failure recovery retained crashed broker'
    $Checkpoint.pending=$null;Save;Stop-Owned;Preserved $Before;Scan-Native
    Check 'crash_recovery' 'Actual protected broker killed; SCM restarted distinct broker/runtime; stopped state and native crash/key scans preserved'
    $Credential=Sha (Join-Path $Root 'credential.dpapi');Signed-Upgrade;$null=Verify-Subject;Configured;Preserved $Before;Need ((Sha (Join-Path $Root 'credential.dpapi')) -ceq $Credential) 'Signed reinstall rewrote credential'
    Check 'signed_reinstall' 'Actual same signed release helper Upgrade preserved credential/client/config/journal state'
    Start-Owned;Interrupted-Upgrade
    if($null -eq $Plan.prior_release){$Checkpoint.checks.prior_version_upgrade=@{result='not_applicable:first_release';reason='first_release';observed_at=(Utc);observation='No prior version supplied; acceptance controller must authenticate published stable release history';logs=@('native-events.jsonl')}}else{$Prior=Public-Check 'paper-prior' @('--binary',$Exe,'--work',(Join-Path $State 'previous-paper-probe'));Check 'prior_version_upgrade' 'Actual independently signed prior published Paper home accepted by candidate with exact account/client/config/halt and durable prefixes preserved; Testnet remains separately isolated' $Prior}
    $null=Audit-Probe $false;Flat;$Checkpoint.completed+=@('exercise');Save
  }elseif($Stage -eq 'before-reboot'){
    Need ($Checkpoint.completed -contains 'exercise' -and $Checkpoint.completed -notcontains 'before-reboot') 'Exact actual exercise required'
    Configured;Flat;Stop-Owned;No-Writes;$Checkpoint.snapshot=Snapshot;Start-Owned
    $Checkpoint.boot_before=$Boot;$Checkpoint.completed+=@('before-reboot');Save;Event 'actual-normal-reboot-admitted' @{boot_before=$Boot;delayed_auto=$true}
  }elseif($Stage -eq 'resume'){
    Need ($Checkpoint.completed -contains 'before-reboot' -and $Checkpoint.completed -notcontains 'resume' -and $Boot -cne $Checkpoint.boot_before) 'Actual OS boot did not change'
    Controller-Guards;$null=Verify-Subject;Configured
    $Value=Readiness;$ReadyAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$Audit=Audit-Probe $true $ReadyAt
    Check 'pre_login_readiness' 'Actual distinct boot SCM synchronized before first actual interactive type2 Security4624 machine authentication' $Audit
    Stop-Owned;Preserved $Checkpoint.snapshot;No-Writes;Scan-Native
    Check 'host_reboot' 'Actual Windows boot changed; protected delayed-auto SCM ready before manual start, with preserved state' @{boot_before=$Checkpoint.boot_before;boot_after=$Boot}
    Start-Owned;Flat;$Checkpoint.completed+=@('resume');Save
  }elseif($Stage -eq 'quiesce'){
    Need ($Checkpoint.completed -contains 'resume' -and $Checkpoint.completed -notcontains 'quiesce') 'Actual boot proof must precede quiesce'
    Flat;Configured;Stop-Owned;No-Writes;$Checkpoint.final_snapshot=Snapshot;Confinement
    $Checkpoint.completed+=@('quiesce');Save;Event 'actual-quiesced-before-owner-revocation' @{service_stopped=$true;credential_retained=$true}
  }elseif($Stage -eq 'cleanup'){
    Need ($Checkpoint.completed -contains 'quiesce' -and $Checkpoint.completed -notcontains 'cleanup') 'Owner revocation requires prior actual quiesce'
    Flat;Configured;Stop-Owned;No-Writes;Scan-Native;Preserved $Checkpoint.final_snapshot
    Need ((Get-Item -LiteralPath $Root).CreationTimeUtc.ToString('o') -ceq $Checkpoint.root_creation_utc -and (Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($Exe))).CreationTimeUtc.ToString('o') -ceq $Checkpoint.binary_creation_utc) 'Fresh owned root identities changed'
    $TransactionRecord=Get-Content -LiteralPath $Transaction -Raw|ConvertFrom-Json
    Need ($TransactionRecord.id -ceq 'testnet-native' -and $TransactionRecord.account -ceq $Plan.account -and $TransactionRecord.api_wallet -ceq $Plan.api_wallet -and $TransactionRecord.mode -ceq 'testnet') 'Owned lifecycle transaction differs'
    Action 'uninstall-owned-service' @('-Action','Uninstall','-Network','testnet','-Id','testnet-native','-ConfirmAccount',$Plan.account)
    Need ($null -eq (Get-Service -Name 'ZunderGuard-testnet-native' -ErrorAction SilentlyContinue)) 'Owned SCM registration remains'
    Dispose-Owned $Root;Dispose-Owned ([IO.Path]::GetDirectoryName($Exe))
    foreach($File in @(Get-ChildItem -LiteralPath $Management -Filter 'testnet-native*')){
      Need (-not $File.PSIsContainer -and -not ($File.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $File.Length -le 512MB) 'Unknown owned management disposal resource'
      Private-Path $File.FullName $false;Remove-Item -LiteralPath $File.FullName
    }
    Need (@(Get-ChildItem -LiteralPath $Management -Filter 'testnet-native*').Count -eq 0) 'Owned lifecycle records remain'
    $Checkpoint.cleanup=@{complete=$true;uncertain_writes=0;owned_resources_removed=$true};$Checkpoint.completed+=@('cleanup');Save;Event 'actual-owned-dpapi-runtime-registration-disposed' @{shared_signed_cache_retained=$true}
  }elseif($Stage -eq 'report'){
    $Required=@('signed_install','credential_confinement','account_network_risk','pairing','fee_licence','explicit_stop','restart','crash_recovery','state_preservation','host_reboot','signed_reinstall','interrupted_replacement_rollback','prior_version_upgrade','pre_login_readiness')
    foreach($Name in $Required){Need ($Checkpoint.checks.ContainsKey($Name)) 'Mandatory actual native check absent';$Check=$Checkpoint.checks[$Name];Need ($Check.result -ceq 'passed' -or ($Name -ceq 'prior_version_upgrade' -and $Check.result -ceq 'not_applicable:first_release' -and $Check.reason -ceq 'first_release')) 'Mandatory actual native check failed'}
    Need ($Checkpoint.cleanup.complete -eq $true -and $Checkpoint.cleanup.owned_resources_removed -eq $true -and $Checkpoint.no_venue_orders -eq $true -and $Checkpoint.agent_approved -eq $true) 'Actual native cleanup/zero-order custody proof incomplete'
    Event 'actual-native-report-complete' @{native_trade_credit=$false}
  }
}catch{$Failure='Native Windows stage incomplete; reconcile private checkpoints; no automatic retry'}
finally{
  if($OutputReady -and $null -ne $Checkpoint -and $null -ne $Plan){
    New-Item -ItemType Directory -Path $Output -ErrorAction Stop|Out-Null
    $Log=Join-Path $Output 'native-events.jsonl';$Lines=@($Events|ForEach-Object{$_|ConvertTo-Json -Depth 8 -Compress})
    if($Lines.Count -eq 0){$Lines=@('{"event":"stage-end","details":"no passing acceptance claim"}')}
    [IO.File]::WriteAllText($Log,($Lines -join "`n")+"`n")
    $Receipt=@{schema=1;kind='actual-native-route';stage=$Stage;request_sha256=$RequestHash;started_at=$Started;finished_at=(Utc);boot_identity=$Boot;checks=$Checkpoint.checks;cleanup=$Checkpoint.cleanup;release_ready=$false;failure=$Failure;agent_approved=($Checkpoint.ContainsKey('agent_approved') -and $Checkpoint.agent_approved);no_venue_orders=($Checkpoint.ContainsKey('no_venue_orders') -and $Checkpoint.no_venue_orders);native_trade_credit=$false;binding=@{tag=$Plan.tag;source=$Plan.source;manifest_sha256=$Plan.manifest_sha256;route=$Plan.route;network='testnet';account=$Plan.account;api_wallet=$Plan.api_wallet;equity_cap=$Plan.equity_cap;assets=$Plan.assets;host=$Plan.host;run_id=$Plan.run_id;attempt=$Plan.attempt;challenge=$Plan.challenge};logs=@(@{name='native-events.jsonl';size=(Get-Item -LiteralPath $Log).Length;sha256=(Sha $Log)})}
    [IO.File]::WriteAllText((Join-Path $Output 'receipt.json'),($Receipt|ConvertTo-Json -Depth 32))
  }
}
if($null -ne $Failure){throw 'Native Windows producer incomplete; no passing acceptance claim'}
