# Offline parser/interop checks only. No Guard install, credential, venue or reboot.
[CmdletBinding()]
param([switch]$ParseCompileOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7){throw 'PS7 parser/compiler required'}
$Tokens=$null;$Errors=$null
$Source=Join-Path $PSScriptRoot 'windows.ps1'
$Ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw 'Windows producer parser errors'}
foreach($Name in @('Controller-Guards','Private-Path','Configured','Confinement','Readiness','Fee-Free','Flat','Interrupted-Upgrade','Audit-Probe','Dispose-Owned')){
  $Nodes=@($Ast.FindAll({param($Node)$Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq $Name},$true))
  if($Nodes.Count -ne 1){throw 'Required producer operation absent or duplicated'}
}
$FeeNode=@($Ast.FindAll({param($Node)$Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Fee-Free'},$true))[0]
Invoke-Expression $FeeNode.Extent.Text
function Need([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
$script:Plan=@{licence=$null};if(Fee-Free){throw 'Absent licence has fee-free expectation'}
foreach($Pair in @(@('[]',$false),@('["fee_free"]',$true))){
  $Payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"features":'+$Pair[0]+'}')).TrimEnd('=').Replace('+','-').Replace('/','_')
  $script:Plan=@{licence=('zgl1_'+$Payload+'.cHVibGlj')};if((Fee-Free) -ne $Pair[1]){throw 'Exact configured fee feature differs'}
}
$script:Plan=@{licence='invalid'};$Refused=$false;try{$null=Fee-Free}catch{$Refused=$true};if(-not $Refused){throw 'Invalid explicit licence discarded'}
$Assignments=@($Ast.FindAll({param($Node)$Node -is [Management.Automation.Language.AssignmentStatementAst] -and $Node.Left -is [Management.Automation.Language.VariableExpressionAst]},$true))
foreach($Assignment in $Assignments){
  $Name=$Assignment.Left.VariablePath.UserPath.Split(':')[-1]
  $Automatic=Get-Variable -Name $Name -ErrorAction SilentlyContinue
  if($null -ne $Automatic -and ([int]$Automatic.Options -band 3) -ne 0){throw 'Producer assigns a read-only or constant automatic variable'}
}
# Public SAM cmdlet fakes: never create or query an actual local identity.
$ProbeNode=@($Ast.FindAll({param($Node)$Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Probe-LocalUser'},$true))[0]
Invoke-Expression $ProbeNode.Extent.Text
function Get-LocalUser { [CmdletBinding()]param()
  if($script:FakeQuery -ceq 'failure'){Write-Error 'Synthetic SAM unavailable'}
  elseif($script:FakeQuery -ceq 'present'){return [PSCustomObject]@{Name='public-probe';Sid='public-sid'}}
  elseif($script:FakeQuery -ceq 'duplicate'){return @([PSCustomObject]@{Name='public-probe'},[PSCustomObject]@{Name='public-probe'})}
}
$script:FakeQuery='absent';if($null -ne (Probe-LocalUser 'public-probe')){throw 'Successful SAM absence differs'}
$script:FakeQuery='present';if((Probe-LocalUser 'public-probe').Sid -cne 'public-sid'){throw 'Successful SAM identity differs'}
foreach($Case in @('failure','duplicate')){
  $script:FakeQuery=$Case;$Refused=$false;try{$null=Probe-LocalUser 'public-probe'}catch{$Refused=$true}
  if(-not $Refused){throw 'Unknown or ambiguous SAM query treated as absence'}
}
$AuditNode=@($Ast.FindAll({param($Node)$Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Audit-Probe'},$true))[0]
Invoke-Expression $AuditNode.Extent.Text
function Save {}
function Event {}
function New-LocalUser { [CmdletBinding()]param([string]$Name,[object]$Password,[string]$Description,[DateTime]$AccountExpires)
  $script:FakeCreated=$true;$script:FakeUser=[PSCustomObject]@{Name=$Name;Description=$Description;Sid=[PSCustomObject]@{Value='public-sid'}}
  return $script:FakeUser
}
function Add-LocalGroupMember { [CmdletBinding()]param([string]$Group,[string]$Member);throw 'Synthetic group failure' }
function Remove-LocalUser { [CmdletBinding()]param([string]$Name);$script:FakeCreated=$false;$script:FakeRemoved=$true }
function Get-LocalUser { [CmdletBinding()]param()
  if(($script:FakeCreated -and $script:AuditCase -ceq 'query-failure') -or ($script:FakeRemoved -and $script:AuditCase -ceq 'removal-readback-failure')){Write-Error 'Synthetic SAM unavailable'}
  if($script:FakeCreated){return $script:FakeUser}
}
foreach($Case in @('query-failure','removal-readback-failure','successful-cleanup')){
  $script:AuditCase=$Case;$script:FakeCreated=$false;$script:FakeRemoved=$false
  $script:Plan=@{run_id=1;challenge='public-fixture'};$script:Checkpoint=@{pending=$null}
  try{$null=Audit-Probe $false}catch{}
  $Removed=$script:Checkpoint.probe_identity.ContainsKey('removed') -and $script:Checkpoint.probe_identity.removed
  if($Case -ceq 'successful-cleanup'){
    if($script:FakeCreated -or -not $Removed -or $null -ne $script:Checkpoint.pending){throw 'Successful owned cleanup differs'}
  }elseif($Removed -or $null -eq $script:Checkpoint.pending){throw 'Unknown SAM query falsely cleared custody'}
}
foreach($Function in @('Get-LocalUser','New-LocalUser','Add-LocalGroupMember','Remove-LocalUser','Save','Event')){Remove-Item ('Function:\'+$Function)}

$Code=Join-Path $PSScriptRoot 'windows_native.cs';Add-Type -Path $Code
if($ParseCompileOnly){Write-Output 'PASS: exact Windows producer parser, public-only fee feature fixtures and native C# compile. Win32 Job/frame/lifecycle tests not executed.';return}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Actual harmless Win32 Job/frame tests require native Windows'}
$Temp=Join-Path ([IO.Path]::GetTempPath()) ('zunder-native-offline-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp|Out-Null
$PowerShell=(Get-Process -Id $PID).Path
$Child=$null;$Descendant=$null
try{
  $Public=Join-Path $Temp 'public-fixture';[IO.File]::WriteAllText($Public,'public synthetic data');[ZunderNative]::SingleLink($Public)
  $Cmd=Join-Path $env:windir 'System32\cmd.exe'
  $Value=[ZunderNative]::Execute($Cmd,@('/d','/c','echo public-native-fixture'),$null,10)
  if($Value.Trim() -cne 'public-native-fixture'){throw 'Bounded native command output differs'}
  $Refused=$false
  try{$null=[ZunderNative]::Execute($Cmd,@('/d','/c','ping -n 30 127.0.0.1 >nul'),$null,1)}catch{$Refused=$true}
  if(-not $Refused){throw 'Native command deadline did not refuse'}
  $Probe=Join-Path $Temp 'job-probe.ps1';$PidPath=Join-Path $Temp 'descendant.pid'
  $Text="Add-Type -Path '"+$Code.Replace("'","''")+"'`n[ZunderNative]::OwnControllerJob()`n"+
        "`$p=[Diagnostics.Process]::Start('"+$Cmd.Replace("'","''")+"','/d /c ping -n 60 127.0.0.1 >nul')`n"+
        "[IO.File]::WriteAllText('"+$PidPath.Replace("'","''")+"',[string]`$p.Id)`nStart-Sleep -Seconds 60`n"
  [IO.File]::WriteAllText($Probe,$Text)
  $Info=[Diagnostics.ProcessStartInfo]::new($PowerShell);$Info.UseShellExecute=$false;$Info.RedirectStandardOutput=$true;$Info.RedirectStandardError=$true
  foreach($Word in @('-NoLogo','-NoProfile','-File',$Probe)){$Info.ArgumentList.Add($Word)}
  $Child=[Diagnostics.Process]::new();$Child.StartInfo=$Info;$null=$Child.Start()
  $Until=[DateTimeOffset]::UtcNow.AddSeconds(20)
  while(-not (Test-Path -LiteralPath $PidPath) -and [DateTimeOffset]::UtcNow -lt $Until -and -not $Child.HasExited){Start-Sleep -Milliseconds 100}
  if(-not (Test-Path -LiteralPath $PidPath)){throw 'Actual disposable Job probe did not start'}
  $Descendant=Get-Process -Id ([int][IO.File]::ReadAllText($PidPath));$Child.Kill();if(-not $Child.WaitForExit(5000)){throw 'Disposable controller survived'}
  if(-not $Descendant.WaitForExit(5000)){throw 'Kill-on-close Job left descendant alive'}
  $FrameProbe=Join-Path $Temp 'frame-probe.ps1'
  $Text="Add-Type -Path '"+$Code.Replace("'","''")+"'`n`$bytes=[ZunderNative]::ReadDuplicateFrames()`ntry{[ZunderNative]::Fingerprint(`$bytes,`$false)}finally{[Array]::Clear(`$bytes,0,`$bytes.Length)}`n"
  [IO.File]::WriteAllText($FrameProbe,$Text)
  $Info=[Diagnostics.ProcessStartInfo]::new($PowerShell);$Info.UseShellExecute=$false;$Info.RedirectStandardInput=$true;$Info.RedirectStandardOutput=$true;$Info.RedirectStandardError=$true
  foreach($Word in @('-NoLogo','-NoProfile','-File',$FrameProbe)){$Info.ArgumentList.Add($Word)}
  $FrameChild=[Diagnostics.Process]::new();$FrameChild.StartInfo=$Info;$null=$FrameChild.Start()
  try{
    $Frame=('a1'*32);$Bytes=[Text.Encoding]::ASCII.GetBytes($Frame+"`n"+$Frame+"`n");$FrameChild.StandardInput.BaseStream.Write($Bytes,0,$Bytes.Length);$FrameChild.StandardInput.Close()
    if(-not $FrameChild.WaitForExit(15000) -or $FrameChild.ExitCode -ne 0){throw 'Bounded public duplicate frame check failed'}
    $Expected=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($Frame)))).Replace('-','').ToLowerInvariant()
    if($FrameChild.StandardOutput.ReadToEnd().Trim() -cne $Expected){throw 'Public fixture key fingerprint differs'}
  }finally{if(-not $FrameChild.HasExited){$FrameChild.Kill($true);$null=$FrameChild.WaitForExit(5000)};$FrameChild.Dispose()}
  Write-Output 'PASS: Windows producer parser, C# compile, regular-file link metadata, bounded command/deadline, actual Job descendant death and public duplicate-frame fingerprint.'
}finally{
  if($Child){if(-not $Child.HasExited){$Child.Kill($true);$null=$Child.WaitForExit(5000)};$Child.Dispose()}
  if($Descendant){if(-not $Descendant.HasExited){$Descendant.Kill($true);$null=$Descendant.WaitForExit(5000)};$Descendant.Dispose()}
  Remove-Item -LiteralPath $Temp -Recurse -Force
}
