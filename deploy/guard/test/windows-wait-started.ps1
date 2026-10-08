param([string]$Path = (Join-Path $PSScriptRoot 'windows-service-native.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Tokens=$null;$Errors=$null
$Ast=[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw 'Native harness parse error.'}
$Nodes=@($Ast.FindAll({param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Wait-Started'},$true))
if($Nodes.Count -ne 1){throw 'Expected exactly one production Wait-Started function.'}
$Text=$Nodes[0].Extent.Text
if(([regex]::Matches($Text,'AddSeconds\(45\)')).Count -ne 1){throw 'Unexpected production wait deadline.'}
# Only shorten the timeout in the extracted test function, never the actual harness.
Invoke-Expression ($Text.Replace('AddSeconds(45)','AddMilliseconds(150)'))
$Log=Join-Path $env:TEMP ('count-regression-'+[Guid]::NewGuid().ToString('N')+'.log')
$Cases=0
function Expect-Timeout([int]$ExpectedCount){
 $Clock=[Diagnostics.Stopwatch]::StartNew()
 try{$null=Wait-Started $ExpectedCount;throw 'Missing expected timeout.'}
 catch{if($_.Exception.Message -ne 'Synthetic runtime did not start; SCM or credential admission failed.'){throw}}
 if($Clock.Elapsed.TotalMilliseconds -lt 100 -or $Clock.Elapsed.TotalSeconds -gt 3){throw 'Wait function did not honor bounded retry.'}
}
try{
 Expect-Timeout 1;$Cases++
 [IO.File]::WriteAllText($Log,'');Expect-Timeout 1;$Cases++
 [IO.File]::WriteAllText($Log,"started 123`n");if((Wait-Started 1) -ne 123){throw 'Single start mismatch.'};$Cases++
 [IO.File]::WriteAllText($Log,"started 123`nstarted 456`n");if((Wait-Started 2) -ne 456){throw 'Latest start mismatch.'};$Cases++
 Expect-Timeout 3;$Cases++
 [ordered]@{test='Wait-Started empty/single/multiple records';passed=$Cases;failed=0;powershell=$PSVersionTable.PSVersion.ToString();source_sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
}finally{if(Test-Path -LiteralPath $Log){Remove-Item -LiteralPath $Log -Force}}
