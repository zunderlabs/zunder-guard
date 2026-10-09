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
