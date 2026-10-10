"""Inert ABI/report source checks; these never compile C# or execute native Windows APIs."""
import hashlib
import ctypes as c
import json
from pathlib import Path
import re
import unittest

HERE=Path(__file__).parent
R14_NATIVE=(HERE/'PhaseZero.cs').read_text()
ACTUAL_NATIVE=R14_NATIVE.replace('if (!socket.Poll(5000000, SelectMode.SelectError))','if (!socket.Poll(1000000, SelectMode.SelectError))',1)
_R13_OLD_HELPER='  static bool RefusedConnect() {\n    using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {\n      socket.Blocking = false;\n      try { socket.Connect(IPAddress.Loopback, Port); return false; }\n      catch (SocketException e) {\n        if (e.SocketErrorCode == SocketError.ConnectionRefused) return true;\n        if (e.SocketErrorCode != SocketError.WouldBlock && e.SocketErrorCode != SocketError.InProgress) return false;\n        return socket.Poll(1000000, SelectMode.SelectError) && (int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error) == (int)SocketError.ConnectionRefused;\n      }\n    }\n  }\n'
_R13_NEW_HELPER='  static bool RefusedConnect(out uint failedCode) {\n    failedCode = 0;\n    using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {\n      socket.Blocking = false;\n      try { socket.Connect(IPAddress.Loopback, Port); failedCode = 0x4c430001; return false; }\n      catch (SocketException e) {\n        if (e.SocketErrorCode == SocketError.ConnectionRefused) return true;\n        if (e.SocketErrorCode != SocketError.WouldBlock && e.SocketErrorCode != SocketError.InProgress) { failedCode = 0x4c430002; return false; }\n        if (!socket.Poll(1000000, SelectMode.SelectError)) { failedCode = 0x4c430003; return false; }\n        if ((int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error) == (int)SocketError.ConnectionRefused) return true;\n        failedCode = 0x4c430004; return false;\n      }\n    }\n  }\n'
_R13_OLD_CLEANUP='            if (listenerObserved && ListenerPids().Count == 0 && RefusedConnect()) cleanup["listener"] = "OBSERVED_ABSENT";'
_R13_NEW_CLEANUP='            if (listenerObserved) {\n              uint listenerCode = 0;\n              if (ListenerPids().Count != 0) listenerCode = 0x4c430005;\n              else if (RefusedConnect(out listenerCode)) cleanup["listener"] = "OBSERVED_ABSENT";\n              if (listenerCode != 0) { report["error_class"] = "cleanup"; report["error_code"] = listenerCode; }\n            }'
CURRENT_NATIVE=ACTUAL_NATIVE.replace(_R13_NEW_HELPER,_R13_OLD_HELPER,1).replace(_R13_NEW_CLEANUP,_R13_OLD_CLEANUP,1)
NATIVE=CURRENT_NATIVE.replace('return socket.Poll(1000000, SelectMode.SelectError) && (int)socket.GetSocketOption','return socket.Poll(1000000, SelectMode.SelectWrite) && (int)socket.GetSocketOption',1)
GATE=(HERE/'ReportGate.cs').read_text()
WRAPPER=(HERE/'probe.ps1').read_text()
FIXTURES=json.loads((HERE/'report-gate-fixtures.json').read_text())
RETAINED_FUNCTIONS_SHA='df40ce4b975409b26a5d0521404752e52b3a1701abf57c306cfa5e31f353cda9'
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
  if r.get('error_class') in ('clock_guard','clock_guard_suffix') or (r.get('error_class')=='clock' and r.get('boot',{}).get('state')=='UNKNOWN'):
   # Independent inert model of the exact new refusal corpus, not native execution.
   template=json.loads(next(x['raw']for x in FIXTURES['cases']if x['name']=='clock_guard_refusal_1'))
   assert type(r.get('error_code'))is int and 0<=r['error_code']<=2**32-1
   if r['error_class']=='clock_guard':assert 1<=r['error_code']<=11
   else:assert r['error_class']=='clock'
   normalized=dict(r);normalized['error_class']='clock_guard';normalized['error_code']=1
   assert normalized==template
   # JSON boolean/number equality alone is not a type check.
   for key,value in template.items():
    if type(value)is bool:assert type(normalized[key])is bool
   return True
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
  startup=r['startup_status'];assert set(startup)=={'state','service_state','win32_exit','service_exit'}
  if startup['state']=='UNKNOWN':assert all(startup[k] is None for k in ['service_state','win32_exit','service_exit'])
  else:
   assert startup['state']=='OBSERVED' and type(startup['service_state']) is int and 1<=startup['service_state']<=7
   assert all(type(startup[k]) is int and 0<=startup[k]<=2**32-1 for k in ['win32_exit','service_exit'])
  shaped=dict(r);shaped['startup_status']=baseline['startup_status'];shape(shaped,baseline)
  assert r['schema']==2 and r['kind']==baseline['kind'] and r['outcome'] in ['OBSERVED','UNKNOWN']
  for field in ['source_admitted','runtime_admitted','release_ready','production_windows_service_acceptance','native_credential_retention_proven','same_host_reboot_proven','all_owned_processes_gone']:assert r[field] is False
  assert r['actual_native_getter_executed'] is True and r['self_exit']=='UNKNOWN' and r['vm_removal']=='UNKNOWN' and r['receipt_memory_absence']=='NOT_EXERCISED'
  def tick(x):
   assert re.fullmatch(r'0|[1-9][0-9]{0,19}',x) and int(x)<=2**64-1
   return int(x)
  b=r['boot'];assert b['state']=='OBSERVED' and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',b['guid'])
  assert tick(b['boot_filetime'])>0 and tick(b['boot_filetime'])<=tick(b['observation_before_filetime'])<=tick(b['current_filetime'])<=tick(b['observation_after_filetime'])
  assert tick(b['qpc_before'])<=tick(b['qpc_after']) and tick(b['qpc_frequency'])>0
  if r['outcome']=='OBSERVED':assert startup==baseline['startup_status'] and r['error_class']=='none' and r['error_code']==0
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


# Independent pure native-sharing model; no C#/Windows execution or authority.
R,W,D=1,2,4
def compatible(existing_access,existing_share,new_access,new_share):
 return not (new_access & ~existing_share) and not (existing_access & ~new_share)

def deletion_model(original,current,expected):
 if type(expected)is not str or re.fullmatch('[0-9a-f]{64}',expected)is None:return False
 for value in (original,current):
  if value.get('path')!='fixed-exe' or value.get('directory')is not False or value.get('reparse')is not False or value.get('links')!=1 or value.get('protected_dacl')is not True or value.get('owner')!='ADMINISTRATORS' or value.get('hash')!=expected:return False
 return all(original.get(k)==current.get(k)for k in ('volume','file_id'))

R9_HELPER='  static uint FailedJobMembers(H job, uint childPid, uint servicePid) {\n    IntPtr buffer = Marshal.AllocHGlobal(72);\n    try {\n      uint returned; Win(N.QueryJobProcessIds(job.P, 3, buffer, 72, out returned), "job");\n      uint assigned = unchecked((uint)Marshal.ReadInt32(buffer, 0)); uint count = unchecked((uint)Marshal.ReadInt32(buffer, 4));\n      Need(count >= 1 && count <= 8 && assigned == count && returned >= 8U + count * 8U && returned <= 72, "job");\n      var seen = new Dictionary<uint, bool>(); uint mask = 0;\n      for (uint i = 0; i < count; i++) {\n        ulong raw = unchecked((ulong)Marshal.ReadInt64(buffer, checked(8 + (int)i * 8)));\n        Need(raw > 0 && raw <= uint.MaxValue, "job"); uint pid = (uint)raw;\n        Need(!seen.ContainsKey(pid), "job"); seen.Add(pid, true);\n        if (pid == childPid) mask |= 1U;\n        else if (pid == servicePid) mask |= 2U;\n        else if (pid == N.GetCurrentProcessId()) mask |= 4U;\n        else {\n          using (var process = new H(N.OpenProcess(0x1000, false, pid), false)) {\n            var image = new StringBuilder(32768); uint size = 32768;\n            Win(N.QueryFullProcessImageNameW(process.P, 0, image, ref size), "job");\n            Need(size > 0 && size < 32768, "job");\n            mask |= String.Equals(image.ToString(), @"C:\\Windows\\System32\\conhost.exe", StringComparison.OrdinalIgnoreCase) ? 8U : 16U;\n          }\n        }\n      }\n      return 0x4d420000U | mask;\n    } finally { Marshal.FreeHGlobal(buffer); }\n  }\n'
R10_DLL='    [DllImport("kernel32.dll")] internal static extern uint GetCurrentProcessId();\n'
R9_DLL='    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] internal static extern bool QueryJobProcessIds(IntPtr h, int c, IntPtr buffer, uint n, out uint returned);\n'

def r10_source():
 return NATIVE.replace('DETACHED_PROCESS = 8','CREATE_NO_WINDOW = 0x08000000',1).replace('CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT','CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT',1)

def r8_source():
 return r10_source().replace(R10_DLL,'',1).replace(R9_HELPER,'',1).replace(R9_DLL,'',1).replace('FailedJobMembers(job, pids[0], servicePid)','accounting.Active <= 65535U ? 0x41430000U + accounting.Active : 0x4a4f420dU',1)

def r7_source():
 return r8_source().replace('        if (!(accounting.Active == 1)) throw new Refused("ownership", accounting.Active <= 65535U ? 0x41430000U + accounting.Active : 0x4a4f420dU);','        if (!(accounting.Active == 1)) throw new Refused("ownership", 0x4a4f420d);',1)

def prior_job_source():
 restored=r7_source()
 restored=restored.replace('      if (!(SID(owner) == sid)) throw new Refused("ownership", 0x4a4f4201);\n      if (!((control & 0x1000) != 0)) throw new Refused("ownership", 0x4a4f4202);\n      if (!(dacl != IntPtr.Zero)) throw new Refused("ownership", 0x4a4f4203);','      Need(SID(owner) == sid && (control & 0x1000) != 0 && dacl != IntPtr.Zero, "ownership");',1)
 restored=restored.replace('      if (!(acl.Count == 3)) throw new Refused("ownership", 0x4a4f4204); var seen = new Dictionary<string, bool>();','      Need(acl.Count == 3, "ownership"); var seen = new Dictionary<string, bool>();',1)
 restored=restored.replace('        if (!(Marshal.ReadByte(ace) == 0)) throw new Refused("ownership", 0x4a4f4205);\n        if (!(Marshal.ReadByte(ace, 1) == 0)) throw new Refused("ownership", 0x4a4f4206);\n        if (!((ushort)Marshal.ReadInt16(ace, 2) >= 12)) throw new Refused("ownership", 0x4a4f4207);','        Need(Marshal.ReadByte(ace) == 0 && Marshal.ReadByte(ace, 1) == 0 && (ushort)Marshal.ReadInt16(ace, 2) >= 12, "ownership");',1)
 restored=restored.replace('        if (!(!seen.ContainsKey(a))) throw new Refused("ownership", 0x4a4f4208);\n        if (!(mask == 0x1f003f)) throw new Refused("ownership", 0x4a4f4209);\n        if (!((a == sid || a == "S-1-5-18" || a == "S-1-5-32-544"))) throw new Refused("ownership", 0x4a4f420a); seen.Add(a, true);','        Need(!seen.ContainsKey(a) && mask == 0x1f003f && (a == sid || a == "S-1-5-18" || a == "S-1-5-32-544"), "ownership"); seen.Add(a, true);',1)
 restored=restored.replace('JobSecurity(job, sid); bool member; Win(N.IsProcessInJob(child.P, job.P, out member), "job"); if (!(member)) throw new Refused("ownership", 0x4a4f420b);','JobSecurity(job, sid); bool member; Win(N.IsProcessInJob(child.P, job.P, out member), "job"); Need(member, "ownership");',1)
 restored=restored.replace('        if (!((limit.Basic.Flags & 0x2000) != 0)) throw new Refused("ownership", 0x4a4f420c);\n        if (!(accounting.Active == 1)) throw new Refused("ownership", 0x4a4f420d);','        Need((limit.Basic.Flags & 0x2000) != 0 && accounting.Active == 1, "ownership");',1)
 return restored

class SourceContract(unittest.TestCase):
 def test_explicit_x64_layouts(self):
  self.assertEqual([c.sizeof(x) for x in [Boot,Time,Basic,JobBasic,Job,FileId]],[32,48,48,64,144,24])
  self.assertEqual([Boot.flags.offset,Basic.pid.offset,Basic.parent.offset],[24,32,40])
 def test_explicit_dispatcher_table_and_diagnostics(self):
  self.assertNotIn('SERVICE_TABLE[]',NATIVE)
  for text in ['Marshal.AllocHGlobal(32)','Marshal.WriteIntPtr(table, 0, name)','Marshal.WriteIntPtr(table, 8, Marshal.GetFunctionPointerForDelegate(MainDelegate))','Marshal.WriteIntPtr(table, 16, IntPtr.Zero)','Marshal.WriteIntPtr(table, 24, IntPtr.Zero)','GC.KeepAlive(MainDelegate)','GC.KeepAlive(HandlerDelegate)','StartServiceCtrlDispatcherW(IntPtr table)','ExactSpelling = true']:
   self.assertIn(text,NATIVE)
  self.assertLess(NATIVE.index('uint startError ='),NATIVE.index('ObserveStartupStatus(service); //'))
  self.assertIn('if (!started) throw new Refused("scm", startError)',NATIVE)
  self.assertEqual(set(re.findall(r'ServiceCheckpoint = (\d+)',NATIVE)),set(map(str,range(1,11))))
  for text in ['"startup_status"','"service_state"','"win32_exit"','"service_exit"','Num(startup["service_state"]) <= 7','Num(startup["service_state"]) == 4']:
   self.assertIn(text,GATE)
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
  self.assertIn('CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT',NATIVE)
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
  self.assertEqual(len(FIXTURES['cases']),61)
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

 def test_startup_sharing_old_delete_access_mutant_conflicts_with_clr_reader(self):
  self.assertFalse(compatible(R|D,R,R,R))
  self.assertTrue(compatible(R,R|D,R,R))
  self.assertFalse(compatible(R,R|D,W,R|W|D))
  self.assertTrue(compatible(R,R|D,R|D,R))
  self.assertFalse(compatible(R,R,R|D,R)) # a still-open CLR reader can refuse deletion
 def test_fixed_readonly_image_handle_and_exact_newfile_route(self):
  body=NATIVE[NATIVE.index('  static H OpenExecutableRead'):NATIVE.index('  static void SameExecutable')]
  self.assertIn('N.CreateFileW(Exe, 0x80020000U, 5, IntPtr.Zero, 3, 0x02200000',body)
  self.assertNotIn('0x10000',body);self.assertNotIn('0xc0',body)
  self.assertIn('path == Exe ? OpenExecutableRead() : OpenFile(path, false, true)',NATIVE)
  creation=NATIVE[NATIVE.index('  static H NewFile'):NATIVE.index('  static bool MissingPath')]
  self.assertLess(creation.index('h.Dispose();'),creation.index('OpenExecutableRead()'))
  self.assertIn('captured.Volume == again.Volume && Hex(captured.Id) == Hex(again.Id)',creation)
 def test_matching_substituted_and_changed_image_pure_deletion_fixtures(self):
  original={'path':'fixed-exe','directory':False,'reparse':False,'links':1,'protected_dacl':True,'owner':'ADMINISTRATORS','volume':1,'file_id':'a'*32,'hash':'b'*64}
  self.assertTrue(deletion_model(original,dict(original),'b'*64))
  for key,value in [('path','foreign'),('volume',2),('file_id','c'*32),('hash','c'*64),('links',2),('reparse',True),('directory',True),('protected_dacl',False),('owner','FOREIGN')]:
   with self.subTest(key=key):self.assertFalse(deletion_model(original,{**original,key:value},'b'*64))
  for expected in (None,'', 'c'*64,'wildcard'):self.assertFalse(deletion_model(original,dict(original),expected))
 def test_delete_handle_rejoins_before_disposition_while_original_retained(self):
  body=NATIVE[NATIVE.index('  static bool DeleteExecutableHandle'):NATIVE.index('  static Dictionary<string, object> FileFacts')]
  dispose=body.index('N.SetFileInformationByHandle(removal.P')
  for required in ('expectedDigest != null','ExecutablePath(retained)','FileFacts(retained, false, sid)','OpenFile(Exe, false, true)','ExecutablePath(removal)','FileFacts(removal, false, sid)','SameExecutable(original, current)','FileDigest(retained) == expectedDigest','FileDigest(removal) == expectedDigest'):
   self.assertLess(body.index(required),dispose)
  self.assertGreater(body.index('retained.Dispose()'),dispose)
  self.assertGreater(body.index('removal.Dispose()'),dispose)
  self.assertGreater(body.index('MissingPath(Exe)'),body.index('removal.Dispose()'))
  self.assertNotIn('DeleteFileW',body)
  path=NATIVE[NATIVE.index('  static void ExecutablePath'):NATIVE.index('  static H OpenExecutableRead')]
  self.assertIn('(info.Attributes & 0x410) == 0 && info.Links == 1',path)
  self.assertIn('N.GetFinalPathNameByHandleW',path)
  self.assertIn('StringComparison.OrdinalIgnoreCase',path)
 def test_delete_join_follows_terminal_gate_and_failed_read_handle_survives_finally(self):
  terminal=NATIVE.index('(child == null || N.WaitForSingleObject(child.P, 10000) == 0)')
  deletion=NATIVE.index('if (DeleteExecutableHandle(exe, sid, executableDigest))')
  self.assertLess(terminal,deletion)
  self.assertIn('exe = null; else filesGone = false;',NATIVE)
  self.assertIn('new H[] { child, serviceProcess, marker, exe, root, parent, service, scm }',NATIVE)
  self.assertIn('executableDigest = digest',NATIVE)

 def test_boot_clock_diagnostic_ids_match_exact_precise_capture_order(self):
  expected=['before <= after', 'qb >= 0', 'qa >= qb', 'freq > 0', 'boot.Id != Guid.Empty', 'tod.BootTime > 0', 'tod.CurrentTime > 0 && tod.CurrentTime >= tod.BootTime', 'unchecked((ulong)tod.BootTime) <= before', 'current >= before', 'current <= after', 'after - before <= 50000000']
  boot=NATIVE[NATIVE.index('  static Dictionary<string, object> Boot()'):NATIVE.index('  static Dictionary<string, object> ProcessFacts')]
  rows=re.findall(r'if \(!\(([^\n]+)\)\) throw new Refused\("clock_guard", ([0-9]+)\);',boot)
  self.assertEqual([expr for expr,guard in rows],expected)
  self.assertEqual([int(guard)for expr,guard in rows],list(range(1,12)))
  self.assertEqual(boot.count('throw new Refused("clock_guard",'),11)
  self.assertIn('N.QueryPerformanceCounter(out qb) && N.QueryPerformanceFrequency(out freq)',boot)
  self.assertIn('Win(N.QueryPerformanceCounter(out qa), "clock")',boot)
 def test_boot_clock_split_preserves_short_circuit_acceptance_and_fixed_first_failure(self):
  import itertools
  for outcomes in itertools.product((False,True),repeat=11):
   original=all(outcomes);first=next((i for i,yes in enumerate(outcomes,1)if not yes),None)
   self.assertEqual(original,first is None)
  for i in range(11):
   outcomes=[True]*11;outcomes[i]=False
   self.assertEqual(next(k for k,yes in enumerate(outcomes,1)if not yes),i+1)


 def test_historical_corpus_prefix_is_exact(self):
  raw=json.dumps(FIXTURES['cases'][:32],sort_keys=True,separators=(',',':')).encode()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),'a742cb90acc901543b5efe686993c34a970ab4351d70a9086b5d407dbc13e324')
  self.assertLessEqual(len(FIXTURES['cases']),64)
 def test_closed_clock_guard_gate_context_and_old_success_predicates(self):
  expected='if (Str(r["error_class"]) == "clock_guard") Need(Str(r["stage"]) == "preflight" && Str(r["outcome"]) == "REFUSED" && Str(b["state"]) == "UNKNOWN" && Num(r["error_code"]) >= 1 && Num(r["error_code"]) <= 11);'
  self.assertEqual(GATE.count(expected),1)
  self.assertIn('"clock", "clock_guard", "ownership"',GATE)
  self.assertLess(GATE.index('Need(!Bool(r[f]))'),GATE.index(expected))
  self.assertIn('@($fixtures.cases).Count -gt 64',WRAPPER)
  self.assertIn('x.Length <= 16384',GATE)
 def test_guard_and_native_error_nine_are_distinct_reports(self):
  guard=json.loads(next(x['raw']for x in FIXTURES['cases']if x['name']=='clock_guard_refusal_9'))
  win=json.loads(next(x['raw']for x in FIXTURES['cases']if x['name']=='native_win32_clock_nine_retains_distinct_namespace'))
  self.assertEqual(guard['error_code'],win['error_code'])
  self.assertEqual(guard['error_class'],'clock_guard');self.assertEqual(win['error_class'],'clock')
  self.assertNotEqual(guard,win)
  self.assertIn('Win(N.QueryPerformanceCounter(out qb) && N.QueryPerformanceFrequency(out freq), "clock")',NATIVE)
  self.assertIn('throw new Refused(c, unchecked((uint)Marshal.GetLastWin32Error()))',NATIVE)
 def test_all_eleven_guard_codes_and_context_mutants_are_retained(self):
  cases={x['name']:x for x in FIXTURES['cases'][32:]}
  for i in range(1,12):
   case=cases['clock_guard_refusal_'+str(i)];self.assertTrue(case['accept']);self.assertTrue(report_model(case['raw']))
  for name in ('code_zero','code_twelve','wrong_stage','unknown_outcome','observed_outcome','observed_boot','bool_code','string_code','fraction_code','unknown_class'):
   case=cases['clock_guard_'+name];self.assertFalse(case['accept']);self.assertFalse(report_model(case['raw']))


 def test_precise_delta_restores_exact_r5_and_prior_diagnostic_predecessor(self):
  restored=prior_job_source().replace('    // Current UTC is one documented precise sample, not the opaque TOD snapshot.\n    ulong current = Clock();\n','')
  restored=restored.replace('if (!(tod.CurrentTime > 0 && tod.CurrentTime >= tod.BootTime))','if (!(tod.CurrentTime > 0))')
  restored=restored.replace('if (!(current >= before))','if (!(unchecked((ulong)tod.CurrentTime) >= before))')
  restored=restored.replace('if (!(current <= after))','if (!(unchecked((ulong)tod.CurrentTime) <= after))')
  restored=restored.replace('"current_filetime", Tick(current),','"current_filetime", Tick(unchecked((ulong)tod.CurrentTime)),')
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'9371a21f399eaa7c011c2a0ab7a94adc2d4fcedc3911aabafdb3efd3faa37e1e')
  self.assertEqual(restored.count('throw new Refused("clock_guard",'),11)
  restored=restored.replace('throw new Refused("clock_guard",','throw new Refused("clock",')
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'e79fb0bba017e7d9bba7156ef60177ba2c00887f5154e5c3463a1afd4afebe81')
 def test_gate_exact_diagnostic_removal_restores_r4_bytes(self):
  guard='      if (Str(r["error_class"]) == "clock_guard") Need(Str(r["stage"]) == "preflight" && Str(r["outcome"]) == "REFUSED" && Str(b["state"]) == "UNKNOWN" && Num(r["error_code"]) >= 1 && Num(r["error_code"]) <= 11);\n'
  restored=GATE.replace('"clock", "clock_guard", "ownership"','"clock", "ownership"').replace(guard,'')
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'602af155a6188b805f2be61d57b7584201e0ba020df16b42086900b4907be0bc')
  start=GATE.index('      if (Str(r["outcome"]) == "OBSERVED") {');end=GATE.index('      return raw.Trim();',start)
  self.assertEqual(hashlib.sha256(GATE[start:end].encode()).hexdigest(),'d7fea10b23d253ac1b422638e80570430144280b8fc428c186097430709ceda8')
 def test_wrapper_only_fixture_corpus_bound_changes(self):
  self.assertEqual(WRAPPER.count('@($fixtures.cases).Count -gt 64'),1)
  restored=WRAPPER.replace('@($fixtures.cases).Count -gt 64','@($fixtures.cases).Count -gt 32')
  self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'335b657000d22d0fd822a239dcdf7d427c2ab2abb9d77d17e05ac14fc09c2c90')


 def test_precise_current_has_one_fixed_capture_and_returned_provenance(self):
  boot=NATIVE[NATIVE.index('  static Dictionary<string, object> Boot()'):NATIVE.index('  static Dictionary<string, object> ProcessFacts')]
  self.assertEqual(boot.count('ulong current = Clock();'),1)
  self.assertLess(boot.index('a = N.NtQueryTime'),boot.index('ulong current = Clock();'))
  self.assertLess(boot.index('ulong current = Clock();'),boot.index('ulong uptime ='))
  self.assertLess(boot.index('ulong uptime ='),boot.index('ulong after = Clock();'))
  self.assertIn('"current_filetime", Tick(current)',boot)
  self.assertNotIn('Tick(unchecked((ulong)tod.CurrentTime))',boot)
  for forbidden in ('Thread.Sleep','while (','for (int','before -','current +','current -'):
   self.assertNotIn(forbidden,boot)
 def test_hand_computed_precise_bracket_keeps_original_limits(self):
  # FILETIME ticks are 100ns: 50,000,000 = exactly five seconds.
  # Native TOD may lag precise before, but the returned precise sample must not.
  def accepts(before,current,after,qb,qa,freq,boot,tod,guid):
   return before<=after and qb>=0 and qa>=qb and freq>0 and guid and boot>0 and tod>0 and tod>=boot and boot<=before and current>=before and current<=after and after-before<=50000000
  good=(100000000,100000002,100000004,10,11,1000000,1,99999999,True)
  self.assertTrue(accepts(*good))
  fields=[(0,100000005),(1,99999999),(1,100000005),(2,99999999),(3,-1),(4,9),(5,0),(6,0),(6,100000001),(7,0),(8,False)]
  for index,value in fields:
   values=list(good);values[index]=value
   with self.subTest(index=index,value=value):self.assertFalse(accepts(*values))
  values=list(good);values[6]=2;values[7]=1;self.assertFalse(accepts(*values))
  values=list(good);values[2]=150000000;self.assertTrue(accepts(*values))
  values[2]=150000001;self.assertFalse(accepts(*values))
 def test_precise_capture_changes_no_other_functions(self):
  start=prior_job_source().index('  static Dictionary<string, object> ProcessFacts')
  self.assertEqual(hashlib.sha256(prior_job_source()[start:].encode()).hexdigest(),RETAINED_FUNCTIONS_SHA)


 def test_job_diagnostics_exact_r6_reversal(self):
  self.assertEqual(hashlib.sha256(prior_job_source().encode()).hexdigest(),'10083c12e04617404408d5fd31c51e09c0b21e9ccd8b5c474f790980a6bdd006')
 def test_job_diagnostics_fixed_codes_and_no_win32_namespace_collision(self):
  rows=re.findall(r'if \(!\(([^\n]+)\)\) throw new Refused\("ownership", 0x4a4f42([0-9a-f]{2})\);',r7_source())
  self.assertEqual([int(code,16)for expr,code in rows],list(range(1,14)))
  expected=['SID(owner) == sid','(control & 0x1000) != 0','dacl != IntPtr.Zero','acl.Count == 3','Marshal.ReadByte(ace) == 0','Marshal.ReadByte(ace, 1) == 0','(ushort)Marshal.ReadInt16(ace, 2) >= 12','!seen.ContainsKey(a)','mask == 0x1f003f','(a == sid || a == "S-1-5-18" || a == "S-1-5-32-544")','member','(limit.Basic.Flags & 0x2000) != 0','accounting.Active == 1']
  self.assertEqual([expr for expr,code in rows],expected)
  self.assertNotRegex(NATIVE,r'Win\([^;\n]+, "ownership"\)')
  other=[line for line in r7_source().splitlines()if 'new Refused("ownership",'in line and '0x4a4f42'not in line]
  self.assertEqual(other,[])
 def test_job_diagnostic_short_circuit_acceptance_is_unchanged(self):
  import itertools
  for size in (2,3,13):
   for outcomes in itertools.product((False,True),repeat=size):
    first=next((i for i,yes in enumerate(outcomes,1)if not yes),None)
    self.assertEqual(all(outcomes),first is None)
  for code in range(1,14):self.assertLess(0x4a4f4200+code,2**32)


 def test_job_source_codes_remain_failed_data_under_existing_gate(self):
  for code in range(1,14):
   value=json.loads(FIXTURES['cases'][0]['raw'])
   value.update(outcome='UNKNOWN',stage='job',error_class='ownership',error_code=0x4a4f4200+code)
   self.assertTrue(report_model(json.dumps(value,separators=(',',':'))))
   value['outcome']='OBSERVED'
   self.assertFalse(report_model(json.dumps(value,separators=(',',':'))))


 def test_active_diagnostic_exact_r7_reversal(self):
  self.assertEqual(hashlib.sha256(r7_source().encode()).hexdigest(),'87c3894bd46919dac6bb7da0fc262a0241f74c8ba41c86026dd56bc2f002d8f7')
  self.assertEqual(r8_source().count('accounting.Active <= 65535U ? 0x41430000U + accounting.Active : 0x4a4f420dU'),1)
  self.assertIn('if (!(accounting.Active == 1)) throw new Refused',NATIVE)
 def test_accounting_abi_exact(self):
  class Accounting(c.Structure):_fields_=[('user',I64),('kernel',I64),('period_user',I64),('period_kernel',I64),('faults',U32),('total',U32),('active',U32),('terminated',U32)]
  self.assertEqual((c.sizeof(Accounting),Accounting.active.offset),(48,40))
  self.assertIn('internal long User, Kernel, PeriodUser, PeriodKernel; internal uint Faults, Total, Active, Terminated;',NATIVE)
  self.assertIn('N.QueryJobAccounting(job.P, 1, ref accounting',NATIVE)
 def test_count_diagnostic_bounds_are_failed_data(self):
  for active in (0,1,2,65535,65536,2**32-1):
   if active==1:continue
   code=0x41430000+active if active<=65535 else 0x4a4f420d
   self.assertLessEqual(code,2**32-1)
   value=json.loads(FIXTURES['cases'][0]['raw']);value.update(outcome='UNKNOWN',stage='job',error_class='ownership',error_code=code)
   self.assertTrue(report_model(json.dumps(value,separators=(',',':'))))
   value['outcome']='OBSERVED';self.assertFalse(report_model(json.dumps(value,separators=(',',':'))))
  for active in range(65536):
   if active!=1:self.assertEqual((0x41430000+active)&0xffff,active)


 def test_failed_member_diagnostic_exact_r8_inverse(self):
  self.assertEqual(hashlib.sha256(r8_source().encode()).hexdigest(),'1dc9c28f5a167e4f32de2aacf9370570ba14e5dd0a30aec1ece8746b39148ead')
  self.assertIn('if (!(accounting.Active == 1)) throw new Refused("ownership", FailedJobMembers(job, pids[0], servicePid));',NATIVE)
  self.assertEqual(NATIVE.count('FailedJobMembers('),2)
 def test_failed_member_diagnostic_is_fixed_read_only_and_bounded(self):
  for text in ['Marshal.AllocHGlobal(72)','N.QueryJobProcessIds(job.P, 3, buffer, 72, out returned)','count >= 1 && count <= 8 && assigned == count','returned >= 8U + count * 8U && returned <= 72','raw > 0 && raw <= uint.MaxValue','!seen.ContainsKey(pid)','N.OpenProcess(0x1000, false, pid)','new StringBuilder(32768)','size > 0 && size < 32768','finally { Marshal.FreeHGlobal(buffer); }','return 0x4d420000U | mask;']:self.assertIn(text,R9_HELPER)
  for forbidden in ['Terminate','Assign','SetInformation','Thread.Sleep','while (','read','File','Token','Console','Json','ProcessFacts']:self.assertNotIn(forbidden,R9_HELPER)
 def test_member_mask_diagnostics_never_allow_observed(self):
  for mask in range(1,32):
   value=json.loads(FIXTURES['cases'][0]['raw']);value.update(outcome='UNKNOWN',stage='job',error_class='ownership',error_code=0x4d420000|mask)
   self.assertTrue(report_model(json.dumps(value,separators=(',',':'))));value['outcome']='OBSERVED';self.assertFalse(report_model(json.dumps(value,separators=(',',':'))))
  for count in range(1,9):
   self.assertLessEqual(8+count*8,72)
  self.assertGreater(8+9*8,72)


 def test_native_references_have_fixed_declared_source_symbols(self):
  native_class=NATIVE[NATIVE.index('  static class N {'):]
  refs=set(re.findall(r'\bN\.([A-Za-z_]\w*)',NATIVE))
  declarations=set(re.findall(r'internal (?:static extern [\w]+|struct|delegate [\w]+) ([A-Za-z_]\w*)',native_class))
  self.assertEqual(refs-declarations,set())
  self.assertGreater(len(refs),60)
  self.assertEqual(NATIVE.count(R10_DLL),1)
  self.assertEqual(hashlib.sha256(r10_source().replace(R10_DLL,'',1).encode()).hexdigest(),'9d1ba908d9defb93a6f9758f77b81a6d9fcac60cfe17516a34b73bf2f2f8204f')


 def test_detached_child_exact_r10_inverse_and_fixed_flags(self):
  self.assertEqual(hashlib.sha256(r10_source().encode()).hexdigest(),'bad583c5411f75124d903e019a2bac1ef38f28595d698e35b58c13bf7e3ed2d2')
  self.assertEqual(NATIVE.count('DETACHED_PROCESS'),2)
  self.assertNotIn('CREATE_NO_WINDOW',NATIVE)
  self.assertNotIn('CREATE_NEW_CONSOLE',NATIVE)
  self.assertNotIn('CREATE_BREAKAWAY',NATIVE)
  self.assertEqual(4|8|0x400,0x40c)
  self.assertIn('false,\n        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT, env, Root',NATIVE)
  self.assertLess(NATIVE.index('N.AssignProcessToJobObject'),NATIVE.index('N.ResumeThread'))
  self.assertIn('if (!(accounting.Active == 1)) throw new Refused',NATIVE)


 def test_nonblocking_refusal_exact_r11_inverse_and_error_readiness(self):
  self.assertEqual(hashlib.sha256(NATIVE.encode()).hexdigest(),'8e1e4c4292b653166ed75708b133741f9ad30d2186d8f0c8f5101973955beabe')
  block=CURRENT_NATIVE[CURRENT_NATIVE.index('  static bool RefusedConnect()'):CURRENT_NATIVE.index('  static Dictionary<string, object> EmptyBoot()')]
  self.assertEqual(block.count('SelectMode.SelectError'),1)
  self.assertNotIn('SelectWrite',block)
  self.assertIn('socket.Poll(1000000, SelectMode.SelectError)',block)
  self.assertIn('== (int)SocketError.ConnectionRefused',block)
  self.assertIn('ListenerPids().Count == 0 && RefusedConnect()',CURRENT_NATIVE)
  # Error readiness alone never establishes refusal; only the exact SO_ERROR does.
  for ready in (False,True):
   for error in (0,10061,10060,10054):
    expected=ready and error==10061
    self.assertEqual(expected,(ready and error==10061))
    if error!=10061:self.assertFalse(expected)
  self.assertIn('if (e.SocketErrorCode == SocketError.ConnectionRefused) return true;',block)
  self.assertIn('if (e.SocketErrorCode != SocketError.WouldBlock && e.SocketErrorCode != SocketError.InProgress) return false;',block)


 def test_listener_diagnostic_exact_r12_inverse_and_closed_queries(self):
  self.assertEqual(hashlib.sha256(CURRENT_NATIVE.encode()).hexdigest(),'b13e7778026955b95554d737aefb533353a10db17ef2d58cda518cf9a02f5a7f')
  self.assertEqual(ACTUAL_NATIVE.count(_R13_NEW_HELPER),1)
  self.assertEqual(ACTUAL_NATIVE.count(_R13_NEW_CLEANUP),1)
  self.assertEqual(_R13_NEW_HELPER.count('socket.Poll('),1)
  self.assertEqual(_R13_NEW_HELPER.count('socket.GetSocketOption('),1)
  self.assertIn('socket.Poll(1000000, SelectMode.SelectError)',_R13_NEW_HELPER)
  self.assertLess(_R13_NEW_HELPER.index('socket.Poll('),_R13_NEW_HELPER.index('socket.GetSocketOption('))
  self.assertEqual(_R13_NEW_CLEANUP.count('ListenerPids()'),1)
  for code in range(1,6):
   value=json.loads(FIXTURES['cases'][0]['raw']);value.update(outcome='UNKNOWN',stage='job',error_class='cleanup',error_code=0x4c430000+code)
   self.assertTrue(report_model(json.dumps(value,separators=(',',':'))))
   value['outcome']='OBSERVED';self.assertFalse(report_model(json.dumps(value,separators=(',',':'))))
  for forbidden in ('Thread.Sleep','while (','for (','Console','Json','QueryFull','File','Terminate'):
   self.assertNotIn(forbidden,_R13_NEW_HELPER)


 def test_refusal_wait_exact_r13_inverse_and_one_bounded_query(self):
  self.assertEqual(hashlib.sha256(ACTUAL_NATIVE.encode()).hexdigest(),'2594e28889fb3a146f24bc93f4fea6cf823a3ae1c3bc7942f64ceda40ff4bac6')
  start=R14_NATIVE.index('  static bool RefusedConnect(')
  block=R14_NATIVE[start:R14_NATIVE.index('  static Dictionary<string, object> EmptyBoot()',start)]
  self.assertEqual(block.count('socket.Connect('),1)
  self.assertEqual(block.count('socket.Poll('),1)
  self.assertEqual(block.count('socket.GetSocketOption('),1)
  self.assertIn('if (!socket.Poll(5000000, SelectMode.SelectError))',block)
  self.assertIn('== (int)SocketError.ConnectionRefused',block)
  self.assertIn('failedCode = 0x4c430003; return false;',block)
  for forbidden in ('Thread.Sleep','while (','for (','SelectWrite','socket.ConnectAsync'):
   self.assertNotIn(forbidden,block)
  self.assertLess(5000000//1000,180000)

if __name__=='__main__':unittest.main()
