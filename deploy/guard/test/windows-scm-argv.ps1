param([Parameter(Mandatory)][string]$ServicePath,[Parameter(Mandatory)][string]$Recorder)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Tokens=$null;$Errors=$null
$Ast=[Management.Automation.Language.Parser]::ParseFile($ServicePath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw 'Production service helper parse error.'}
foreach($FunctionName in @('ConvertTo-ZgNativeArgument','Invoke-ZgSc')){
 $Nodes=@($Ast.FindAll({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $FunctionName},$true))
 if($Nodes.Count -ne 1){throw 'Production SCM function missing or duplicated.'}
 Invoke-Expression $Nodes[0].Extent.Text
}
$script:ZgSc=[IO.Path]::GetFullPath($Recorder)
$Output=Join-Path $env:TEMP ('argv receipt '+[Guid]::NewGuid().ToString('N')+'.txt')
$PidFile=$Output+'.pid'
$Cases=@('','simple','space separated',"tab`tvalue","line`nbreak",'"','a"b','\"','\\"','C:\Program Files\ZunderGuard\','C:\ends\\','"C:\Program Files\ZunderGuard\guard.exe" service run --binding "C:\ProgramData\ZunderGuard\binding.json"','NT SERVICE\ZunderGuard-test','& | < > ^ %PATH% !name! $(ignored) `semi;colon',([string][char]0x00fc+[char]0x03bb+[char]0x4e2d))
try{
 Invoke-ZgSc (@($Output)+$Cases)
 $Actual=[IO.File]::ReadAllLines($Output)
 if($Actual.Count -ne $Cases.Count){throw 'Native argument count changed.'}
 for($Index=0;$Index -lt $Cases.Count;$Index++){
  $Expected='arg:'+([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($Cases[$Index]))).Replace('-','').ToLowerInvariant()
  if($Actual[$Index] -cne $Expected){throw "Native argument roundtrip failed at case $Index."}
 }
 $Failure=$false
 try { Invoke-ZgSc @('--fail') } catch { if($_.Exception.Message -cne 'SCM operation failed; transaction remains pending.'){throw};$Failure=$true }
 if(-not $Failure){throw 'Nonzero native status was accepted.'}
 $NulRefused=$false
 try { Invoke-ZgSc @('a'+[char]0+'b') } catch { if($_.Exception.Message -cne 'NUL in SCM argument refused; transaction remains pending.'){throw};$NulRefused=$true }
 if(-not $NulRefused){throw 'NUL argument was accepted.'}
 $TimedOut=$false
 $Clock=[Diagnostics.Stopwatch]::StartNew()
 try { Invoke-ZgSc @('--sleep',$PidFile) } catch { if($_.Exception.Message -cne 'SCM client timed out; transaction remains pending.'){throw};$TimedOut=$true }
 if(-not $TimedOut -or $Clock.Elapsed.TotalSeconds -lt 29 -or $Clock.Elapsed.TotalSeconds -gt 37){throw 'Native process deadline was not honored.'}
 $OwnedPid=[int][IO.File]::ReadAllText($PidFile)
 if(Get-Process -Id $OwnedPid -ErrorAction SilentlyContinue){throw 'Timed-out owned native process survived cleanup.'}
 [ordered]@{test='production SCM argv roundtrip, nonzero exit, NUL refusal and timeout cleanup';passed=($Cases.Count+3);failed=0;powershell=$PSVersionTable.PSVersion.ToString();service_source_sha256=(Get-FileHash -LiteralPath $ServicePath -Algorithm SHA256).Hash.ToLowerInvariant();recorder_sha256=(Get-FileHash -LiteralPath $Recorder -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
}finally{foreach($Path in @($Output,$PidFile)){if(Test-Path -LiteralPath $Path){Remove-Item -LiteralPath $Path -Force}}}
