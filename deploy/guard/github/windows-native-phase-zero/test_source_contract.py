"""Inert ABI/report source checks; these never compile C# or execute native Windows APIs."""
import ctypes as c
import json
from pathlib import Path
import re
import unittest

HERE=Path(__file__).parent
NATIVE=(HERE/'PhaseZero.cs').read_text()
GATE=(HERE/'ReportGate.cs').read_text()
WRAPPER=(HERE/'probe.ps1').read_text()
FIXTURES=json.loads((HERE/'report-gate-fixtures.json').read_text())
U32=c.c_uint32;U64=c.c_uint64;I64=c.c_int64
class Boot(c.Structure):_fields_=[('guid',c.c_ubyte*16),('firmware',U32),('flags',U64)]
class Time(c.Structure):_fields_=[('boot',I64),('current',I64),('bias',I64),('zone',U32),('reserved',U32),('bootbias',U64),('sleepbias',U64)]
class Basic(c.Structure):_fields_=[('exit',c.c_int32),('peb',U64),('affinity',U64),('priority',c.c_int32),('pid',U64),('parent',U64)]
class JobBasic(c.Structure):_fields_=[('process',I64),('job',I64),('flags',U32),('min',U64),('max',U64),('active',U32),('affinity',U64),('priority',U32),('scheduling',U32)]
class Job(c.Structure):_fields_=[('basic',JobBasic),('io',U64*6),('memory',U64*4)]
class FileId(c.Structure):_fields_=[('volume',U64),('id',c.c_ubyte*16)]

def strict_pairs(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('duplicate')
  d[k]=v
 return d

def report_model(raw):
 """Independent pure schema counterexample model, NOT execution of ReportGate.cs."""
 try:
  if not 0<len(raw)<=16384 or not raw.isascii():return False
  r=json.loads(raw,object_pairs_hook=strict_pairs)
  baseline=json.loads(FIXTURES['cases'][0]['raw'])
  def shape(value,template):
   if isinstance(template,dict):
    assert isinstance(value,dict) and set(value)==set(template)
    for k,v in template.items():shape(value[k],v)
   elif isinstance(template,list):
    assert isinstance(value,list) and len(value)==len(template)
    for a,b in zip(value,template):shape(a,b)
   elif isinstance(template,bool):assert type(value) is bool
   elif isinstance(template,int):assert type(value) is int and 0<=value<=2**32-1
   elif isinstance(template,str):assert isinstance(value,str) and len(value)<=128
   else:assert value is None
  shape(r,baseline)
  assert r['schema']==1 and r['kind']==baseline['kind'] and r['outcome']=='OBSERVED' and r['error_class']=='none' and r['error_code']==0
  for field in ['source_admitted','runtime_admitted','release_ready','production_windows_service_acceptance','native_credential_retention_proven','same_host_reboot_proven','all_owned_processes_gone']:assert r[field] is False
  assert r['actual_native_getter_executed'] is True and r['self_exit']=='UNKNOWN' and r['vm_removal']=='UNKNOWN' and r['receipt_memory_absence']=='NOT_EXERCISED'
  def tick(x):
   assert re.fullmatch(r'0|[1-9][0-9]{0,19}',x) and int(x)<=2**64-1
   return int(x)
  b=r['boot'];assert b['state']=='OBSERVED' and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',b['guid'])
  assert tick(b['boot_filetime'])>0 and tick(b['boot_filetime'])<=tick(b['observation_before_filetime'])<=tick(b['current_filetime'])<=tick(b['observation_after_filetime'])
  assert tick(b['qpc_before'])<=tick(b['qpc_after']) and tick(b['qpc_frequency'])>0
  assert r['listener']==baseline['listener'] and r['job']==baseline['job'] and r['scm']==baseline['scm'] and r['cleanup']==baseline['cleanup']
  seen=set()
  for f in r['files']:
   assert f['role'] not in seen;seen.add(f['role'])
   assert f['role'] in ['root','executable','marker'] and re.fullmatch('[0-9a-f]{32}',f['file_id']) and f['reparse'] is False and f['protected_dacl_match'] is True and f['owner_class']=='ADMINISTRATORS'
   assert f['links']==1
  assert seen=={'root','executable','marker'}
  for p in r['processes']:
   assert tick(p['creation_filetime'])<=tick(p['observation_after_filetime']) and p['image_sha256']==r['files'][1]['sha256']
  assert r['processes'][1]['parent_pid']==r['processes'][0]['pid']
  return True
 except (AssertionError,ValueError,TypeError,KeyError):return False

class SourceContract(unittest.TestCase):
 def test_explicit_x64_layouts(self):
  self.assertEqual([c.sizeof(x) for x in [Boot,Time,Basic,JobBasic,Job,FileId]],[32,48,48,64,144,24])
  self.assertEqual([Boot.flags.offset,Basic.pid.offset,Basic.parent.offset],[24,32,40])
 def test_fixed_native_queries_no_boot_fallback(self):
  for text in ['N.NtQueryBoot(90, ref boot, 32','N.NtQueryTime(3, ref tod, 48','N.NtQueryInformationProcess(p.P, 0, ref basic, 48','N.GetSystemTimePreciseAsFileTime','N.QueryPerformanceCounter','N.GetProcessTimes','N.QueryFullProcessImageNameW','N.GetExtendedTcpTable']:
   self.assertIn(text,NATIVE)
  for forbidden in ['Registry.GetValue','Win32_OperatingSystem','Environment.TickCount','DateTime.UtcNow','NtInitiatePowerAction','ExitWindowsEx','CryptProtectData','--network','zunder-guard.exe']:
   self.assertNotIn(forbidden,NATIVE)
 def test_unicode_pointer_width_and_safe_compiler(self):
  for name in ['GetModuleFileNameW','QueryFullProcessImageNameW']:
   declaration=next(x for x in NATIVE.splitlines() if 'extern' in x and name in x)
   self.assertIn('CharSet = CharSet.Unicode',declaration)
  self.assertIn('internal UIntPtr Pid, Parent',NATIVE)
  for flag in ['/noconfig','/nostdlib+','/platform:x64','/langversion:5','/unsafe-','/checked+']:
   self.assertIn(flag,WRAPPER)
  self.assertNotIn('vswhere',WRAPPER)
 def test_fixed_resources_and_no_caller_targets(self):
  for fixed in ['C:\\ProgramData\\ZunderPublicWindowsPhaseZero','Global\\ZunderPublicWindowsPhaseZeroJob','const int Port = 18547','const int LimitMs = 120000','args.Length != 1']:
   self.assertIn(fixed,NATIVE)
  for role in ['--probe','--service','--child']:self.assertIn('args[0] == "'+role+'"',NATIVE)
  self.assertIn('CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT',NATIVE)
  self.assertLess(NATIVE.index('N.AssignProcessToJobObject'),NATIVE.index('N.ResumeThread'))
 def test_real_handle_identity_and_no_readiness_cleanup_prerequisite(self):
  for api in ['GetFileInformationByHandleEx','GetFinalPathNameByHandleW','GetSecurityInfo','SetFileInformationByHandle','WaitForSingleObject','ServiceMissing(scm)','RefusedConnect()','JobSecurity(job, sid)']:
   self.assertIn(api,NATIVE)
  self.assertIn('0x02200000',NATIVE)
  self.assertIn('if (serviceConfigured) ConfigMatch(service); else BasicConfigMatch(service)',NATIVE)
  self.assertIn('serviceProcess != null && child != null ? "OBSERVED_TERMINAL" : "UNKNOWN"',NATIVE)
 def test_clock_sampling_and_unknown_authority(self):
  self.assertIn('FT(birth) <= after',NATIVE)
  self.assertIn('before <= after',NATIVE)
  self.assertIn('"self_exit", "UNKNOWN"',NATIVE)
  self.assertIn('"same_host_reboot_proven", false',NATIVE)
  self.assertIn('"runtime_admitted", false',NATIVE)
  self.assertIn('"all_owned_processes_gone", false',NATIVE)
 def test_all_retained_report_cases_are_inert(self):
  self.assertEqual(FIXTURES['kind'],'INERT_REPORT_GATE_FIXTURES')
  self.assertFalse(FIXTURES['native_execution']);self.assertFalse(FIXTURES['source_runtime_admission'])
  self.assertEqual(len(FIXTURES['cases']),26)
  for case in FIXTURES['cases']:
   with self.subTest(case=case['name']):self.assertEqual(report_model(case['raw']),case['accept'])
 def test_gate_source_duplicate_unknown_and_precision_guards(self):
  for text in ['Need(!d.ContainsKey(key))','d.Count == names.Length','x.Length <= 16384','depth <= 8','UInt64.TryParse','"boot_environment", "time_of_day"','creation_filetime','protected_dacl_match']:
   self.assertIn(text,GATE)
  self.assertIn('public static string Validate(string raw)',GATE)
  self.assertNotIn('DllImport',GATE)
 def test_actual_helper_join_and_no_raw_export(self):
  self.assertIn('$images[0].sha256 -cne $helperHash',WRAPPER)
  self.assertIn("$info.EnvironmentVariables.Clear()",WRAPPER)
  self.assertIn("$type.GetMethod('Validate').Invoke",WRAPPER)
  self.assertIn('report_gate_fixture_count = $fixtureCount',WRAPPER)
  self.assertIn("buildCleanup = 'PATH_ABSENCE_OBSERVED_IDENTITY_UNJOINED'",WRAPPER)
  self.assertIn('if ($workOwned)',WRAPPER)
  self.assertIn('[IO.FileMode]::CreateNew',WRAPPER)
  self.assertNotIn('Write-Output $result',WRAPPER)
  self.assertNotIn('Write-Host $',WRAPPER)
 def test_workflow_public_standard_runner_only(self):
  workflow=(HERE.parents[3]/'.github/workflows/hosted-windows-native-phase-zero.yml').read_text()
  self.assertIn('runs-on: windows-2025',workflow)
  self.assertIn('github.event.repository.private == false',workflow)
  self.assertIn('ref: ${{ github.sha }}',workflow)
  self.assertIn('if: always()',workflow)
  for forbidden in ['pull_request:', 'workflow_dispatch:', 'id-token:', 'secrets.', 'environment:', 'self-hosted']:
   self.assertNotIn(forbidden,workflow)

if __name__=='__main__':unittest.main()
