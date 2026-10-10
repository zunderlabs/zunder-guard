# Public capability queries and one owned empty WHP partition. No feature enable/reboot.
$ErrorActionPreference = 'Stop'
$Result = [ordered]@{schema=1; guest_started=$false; features_changed=$false; host_rebooted=$false; partition_created=$false; partition_deleted=$false}
try {
 $Cpu = Get-CimInstance Win32_Processor -OperationTimeoutSec 10 | Select-Object -First 1
 $Os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 10
 $Computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 10
 $Result.cpu = @{second_level_address_translation=[bool]$Cpu.SecondLevelAddressTranslationExtensions; firmware_virtualization=[bool]$Cpu.VirtualizationFirmwareEnabled; monitor_mode_extensions=[bool]$Cpu.VMMonitorModeExtensions}
 $Result.memory_bytes = [string]$Computer.TotalPhysicalMemory
 $Result.boot_time = $Os.LastBootUpTime.ToUniversalTime().ToString('o')
 $Result.hypervisor_present = [bool]$Computer.HypervisorPresent
} catch { $Result.cim_status='unavailable' }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EmptyHostedWHP {
 [DllImport("WinHvPlatform.dll", ExactSpelling=true)] public static extern int WHvGetCapability(uint code, IntPtr buffer, uint size, out uint written);
 [DllImport("WinHvPlatform.dll", ExactSpelling=true)] public static extern int WHvCreatePartition(out IntPtr partition);
 [DllImport("WinHvPlatform.dll", ExactSpelling=true)] public static extern int WHvDeletePartition(IntPtr partition);
}
'@
$Buffer=[IntPtr]::Zero; $Partition=[IntPtr]::Zero
try {
 $Buffer=[Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
 for($I=0;$I-lt 1024;$I++){[Runtime.InteropServices.Marshal]::WriteByte($Buffer,$I,0)}
 [uint32]$Written=0
 $Code=[EmptyHostedWHP]::WHvGetCapability(0,$Buffer,1024,[ref]$Written)
 $Result.capability_hresult=$Code; $Result.capability_bytes=$Written
 if($Code-eq 0 -and $Written-ge 1){$Result.whp_hypervisor_present=([Runtime.InteropServices.Marshal]::ReadByte($Buffer)-ne 0)}
 $Code=[EmptyHostedWHP]::WHvCreatePartition([ref]$Partition); $Result.partition_hresult=$Code
 if($Code-eq 0){$Result.partition_created=$true}
} catch { $Result.whp_status='unavailable' }
finally {
 if($Partition-ne [IntPtr]::Zero){$Code=[EmptyHostedWHP]::WHvDeletePartition($Partition);$Result.delete_hresult=$Code;$Result.partition_deleted=($Code-eq 0)}
 if($Buffer-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($Buffer)}
}
$Result | ConvertTo-Json -Depth 6 -Compress
if($Result.partition_created -and -not $Result.partition_deleted){exit 1}
