param([Parameter(Mandatory)][string]$HarnessPath,[Parameter(Mandatory)][string]$Recorder)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Tokens=$null;$Errors=$null
$Ast=[Management.Automation.Language.Parser]::ParseFile($HarnessPath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw 'Hosted harness parse error.'}
$Nodes=@($Ast.FindAll({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Assert-SyntheticPolicyRefusal'},$true))
if($Nodes.Count -ne 1){throw 'Policy-refusal function missing or duplicated.'}
Invoke-Expression $Nodes[0].Extent.Text
$Directory=Join-Path $env:TEMP ('policy-helper-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Directory | Out-Null
$Cases=0
try{
 foreach($Mode in @('good','wrong-status','wrong-message','stdout','oversize','timeout')){
  $Exe=Join-Path $Directory "policy-$Mode.exe"
  Copy-Item -LiteralPath $Recorder -Destination $Exe
  $Refused=$false
  $Clock=[Diagnostics.Stopwatch]::StartNew()
  try{Assert-SyntheticPolicyRefusal $Exe}catch{
    if($Mode -eq 'timeout' -and $_.Exception.Message -cne 'Policy-refusal fixture timed out.'){throw}
    $Refused=$true
  }
  if($Refused -eq ($Mode -eq 'good')){throw "Policy output admission differs at $Mode."}
  if($Mode -eq 'timeout'){
    if($Clock.Elapsed.TotalSeconds -lt 9 -or $Clock.Elapsed.TotalSeconds -gt 17){throw 'Policy fixture deadline was not honored.'}
    if(Get-Process -Name "policy-$Mode" -ErrorAction SilentlyContinue){throw 'Timed-out policy fixture survived cleanup.'}
  }
  $Cases++
 }
 [ordered]@{test='exact bounded policy-refusal capture';passed=$Cases;failed=0;powershell=$PSVersionTable.PSVersion.ToString();harness_sha256=(Get-FileHash -LiteralPath $HarnessPath -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
}finally{Remove-Item -LiteralPath $Directory -Recurse -Force}
