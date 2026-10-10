"""Inert policy probes; no host settings, network, keys or native installation."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import mac_hosted_policy as policy

POWER='AC Power:\n hibernatemode 0\n standby 0\n autopoweroff 0\n sleep 0\n'
ASSERTIONS='pid 123(caffeinate): PreventUserIdleSystemSleep named: test\npid 123(caffeinate): PreventSystemSleep named: test\n'

class Fixtures(unittest.TestCase):
    def fixture(self,**changes):
        data=dict(swap='total = 0.00M used = 0.00M (encrypted)',vault='FileVault is Off.',power=POWER,
            core='1',core_limits=(0,0),prevent_sleep_pid=123,assertions=ASSERTIONS);data.update(changes)
        return policy.validate(**data)
    def test_approved_coverage_is_truthful_even_with_zero_swap_usage(self):
        row=self.fixture();self.assertFalse(row['filevault']);self.assertFalse(row['no_swap'])
        self.assertFalse(row['heap_locking']);self.assertFalse(row['strict_native_memory_satisfied'])
        self.assertFalse(row['no_disk_persistence_proven']);self.assertTrue(row['prevent_sleep_process_observed'])
        self.assertEqual(row['filevault_coverage'],'untested')
    def test_policy_unknown_or_lost_refuses(self):
        changes=[dict(swap='total = 0'),dict(vault='FileVault is On.'),dict(core='unknown'),
                 dict(core_limits=(0,-1)),dict(power=POWER.replace('hibernatemode 0','hibernatemode 3')),
                 dict(power=POWER.replace('standby 0','standby 1')),dict(power=POWER.replace('autopoweroff 0','autopoweroff 1')),
                 dict(power='AC Power:\n hibernatemode 0\n'),dict(assertions=ASSERTIONS.replace('123','124')),
                 dict(assertions='pid 123(caffeinate): PreventUserIdleSystemSleep')]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(RuntimeError):self.fixture(**change)
    def test_all_power_sources_are_inspected(self):
        with self.assertRaises(RuntimeError):self.fixture(power=POWER+POWER.replace('AC Power:','Battery Power:').replace('standby 0','standby 1'))
        self.fixture(power=POWER+POWER.replace('AC Power:','Battery Power:'))
    def test_existing_sleep_image_refuses_even_if_empty(self):
        with tempfile.TemporaryDirectory()as tmp:
            sleep=Path(tmp)/'sleepimage';sleep.touch()
            with patch.object(policy.os,'geteuid',return_value=0),patch.object(Path,'lstat',return_value=type('S',(),{'st_mode':0o100600,'st_uid':0})()):
                with self.assertRaises(RuntimeError):policy.inspect_sleep_and_core([sleep])
    def test_overall_sample_deadline_refuses_slow_success_before_remaining_probes(self):
        tick=[10.0];calls=[]
        def slow(argv,**kwargs):
            calls.append((argv,kwargs['deadline']));tick[0]+=1.6;return '(encrypted)'
        with patch.object(policy.platform,'system',return_value='Darwin'),patch.object(policy.platform,'machine',return_value='arm64'),\
             patch.object(policy.os,'geteuid',return_value=0),patch.object(policy.resource,'getrlimit',return_value=(0,0)),\
             patch.object(policy.time,'monotonic',side_effect=lambda:tick[0]),patch.object(policy,'public',side_effect=slow),\
             patch.object(policy,'inspect_sleep_and_core')as inventory,self.assertRaises(RuntimeError):
            policy.observe(prevent_sleep_pid=123)
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][1],10.75);inventory.assert_not_called()
    def test_each_fixed_probe_uses_remaining_overall_deadline(self):
        from types import SimpleNamespace
        with patch.object(policy.time,'monotonic',side_effect=[10,10.1]),patch.object(policy.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'1'))as run:
            self.assertEqual(policy.public(['/usr/sbin/sysctl','-n','kern.coredump'],deadline=10.5),'1')
        self.assertEqual(run.call_args.kwargs['timeout'],.5)
        with patch.object(policy.time,'monotonic',side_effect=[10,10.6]),patch.object(policy.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'1')),self.assertRaises(RuntimeError):
            policy.public(['/usr/sbin/sysctl','-n','kern.coredump'],deadline=10.5)
    def test_no_policy_modifications_or_secret_input_exist(self):
        text=Path(policy.__file__).read_text()
        for forbidden in ('pmset -a','boot-args','csrutil','stdin.read','/exchange','key-stdin'):
            self.assertNotIn(forbidden,text)

    def test_no_secret_probe_uses_custody_predicate_and_reports_guard_refusal(self):
        from unittest.mock import Mock
        import mac_process_identity
        process=Mock();process.pid=123;process.poll.return_value=None
        proc=Mock();proc.read.return_value={'pid':123,'start_sec':1,'start_usec':2,'uid':0,
            'ppid':policy.os.getpid(),'path':'/usr/bin/caffeinate'}
        for power,eligible in ((POWER,True),(POWER.replace('standby 0','standby 1'),False)):
            with self.subTest(eligible=eligible),patch.object(policy.platform,'system',return_value='Darwin'),\
                 patch.object(policy.platform,'machine',return_value='arm64'),patch.object(policy.os,'geteuid',return_value=0),\
                 patch.object(policy.resource,'setrlimit'),patch.object(policy.resource,'getrlimit',return_value=(0,0)),\
                 patch.object(policy,'inspect_sleep_and_core',return_value=True),\
                 patch.object(policy,'public',side_effect=['(encrypted)','FileVault is Off.',power,'1',ASSERTIONS]*2),\
                 patch.object(mac_process_identity,'DarwinProcesses',return_value=proc),\
                 patch.object(policy.subprocess,'Popen',return_value=process)as spawn:
                result=policy.probe();self.assertEqual(result['eligible'],eligible)
                self.assertFalse(result['privateInput']);self.assertFalse(result['releaseReady']);self.assertFalse(result['host_policy_modified'])
                self.assertEqual(result['coverage']['filevault'],False)
                spawn.assert_called_once();self.assertEqual(spawn.call_args.args[0],['/usr/bin/caffeinate','-dimsu'])

    def readiness_fixture(self,assertions,*,deadline=20,rows=None):
        from unittest.mock import Mock
        helper=Mock();helper.pid=123;helper.poll.return_value=None
        proc=Mock();owned={'pid':123,'start_sec':1,'start_usec':2,'uid':0,
                          'ppid':policy.os.getpid(),'path':'/usr/bin/caffeinate'}
        if rows is None:proc.read.return_value=owned
        else:proc.read.side_effect=rows(owned)
        tick=[10.0];status={}
        def delay(seconds):tick[0]+=seconds
        context=[patch.object(policy.time,'monotonic',side_effect=lambda:tick[0]),
                 patch.object(policy.time,'sleep',side_effect=delay),
                 patch.object(policy,'public',side_effect=assertions if type(assertions)is list else lambda *_a,**_k:assertions)]
        return helper,proc,status,tick,context,deadline

    def test_startup_wait_requires_both_owned_assertions_without_clock_reset(self):
        helper,proc,status,tick,context,deadline=self.readiness_fixture(['',ASSERTIONS.splitlines()[0],ASSERTIONS])
        with context[0],context[1],context[2]as read:
            identity,_=policy.wait_owned_assertions(helper,proc,deadline=deadline,status=status)
        self.assertEqual(read.call_count,3);self.assertEqual(identity,{'pid':123,'start_sec':1,'start_usec':2})
        self.assertTrue(status['passed']);self.assertTrue(all(status['required_assertions'].values()))
        self.assertLessEqual(tick[0]-10,1)
        self.assertEqual({call.kwargs['deadline']for call in read.call_args_list},{11.0})
        self.assertNotIn('assertions',status)

    def test_missing_or_other_pid_assertions_remain_refused_with_fixed_diagnostics(self):
        for assertions in ('',ASSERTIONS.replace('123','124'),ASSERTIONS.splitlines()[0],ASSERTIONS.replace('PreventSystemSleep','PreventSystemSleepFake')):
            helper,proc,status,tick,context,deadline=self.readiness_fixture(assertions)
            with context[0],context[1],context[2]as read,self.assertRaises(RuntimeError):
                policy.wait_owned_assertions(helper,proc,deadline=deadline,status=status)
            self.assertFalse(status['passed']);self.assertFalse(status['required_assertions']['prevent_system_sleep'])
            self.assertEqual(status['stage'],'owned-assertion-readiness')
            self.assertEqual(status['reason'],'owned-required-assertions-missing')
            self.assertLessEqual(read.call_count,20);self.assertLessEqual(tick[0]-10,1.001)

    def test_changed_birth_or_root_parent_executable_refuses_before_admission(self):
        mutations=[{'start_usec':3},{'uid':501},{'ppid':99},{'path':'/tmp/caffeinate'}]
        for change in mutations:
            helper,proc,status,tick,context,deadline=self.readiness_fixture(ASSERTIONS,
                rows=lambda owned:[owned,dict(owned,**change)])
            with context[0],context[1],context[2]as read,self.assertRaises(RuntimeError):
                policy.wait_owned_assertions(helper,proc,deadline=deadline,status=status)
            self.assertEqual(status['reason'],'owned-helper-identity-changed');self.assertFalse(status['passed'])
            self.assertEqual(read.call_count,1)

    def test_original_probe_deadline_tightens_startup_wait(self):
        helper,proc,status,tick,context,deadline=self.readiness_fixture('',deadline=10.02)
        with context[0],context[1],context[2]as read,self.assertRaises(RuntimeError):
            policy.wait_owned_assertions(helper,proc,deadline=deadline,status=status)
        self.assertLessEqual(tick[0],10.02);self.assertEqual(read.call_args.kwargs['deadline'],10.02)
        self.assertEqual(status['reason'],'original-probe-deadline-expired');self.assertFalse(status['passed'])

    def test_readback_error_is_unknown_and_never_exports_raw_text(self):
        helper,proc,status,tick,context,deadline=self.readiness_fixture('')
        with context[0],context[1],patch.object(policy,'public',side_effect=RuntimeError('private raw output')),self.assertRaises(RuntimeError):
            policy.wait_owned_assertions(helper,proc,deadline=deadline,status=status)
        self.assertEqual(status['reason'],'assertion-readback-unavailable');self.assertFalse(status['observed'])
        self.assertNotIn('private raw output',str(status))
