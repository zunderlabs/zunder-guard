"""Pure fixtures only. No native command/process/provider runs."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('probe', HERE/'probe.py')
p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)

class ProbeTests(unittest.TestCase):
    def records(self):
        raw={'build':'25D60','machine':'arm64','boot_before':'12345678-1234-1234-1234-123456789abc',
             'boot_after':'12345678-1234-1234-1234-123456789abc',
             'swap':'total = 0.00M used = 0.00M free = 0.00M (encrypted)', 'core':'0',
             'filevault':'FileVault is Off.',
             'power':'AC Power:\n hibernatemode 0\n standby 0\n autopoweroff 0',
             'live':'Currently in use:\n hibernatemode 0\n standby 0\n autopoweroff 0',
             'cap':'Capabilities for AC Power:\n standby'}
        return {k:{'code':'observed','text':v,'cleanup':True} for k,v in raw.items()}
    def report(self, records=None, **kw):
        defaults={'provider':'circleci','commit':'a'*40,'source_sha':'b'*64,'records':self.records() if records is None else records,
                  'tools':{str(i):'c'*64 for i in range(5)},'core_limits':[{'infinite':False,'bytes':0}]*2,'root_uid':0,'elapsed':1000}
        defaults.update(kw);return p.summarize(**defaults)
    def test_complete_observation_has_zero_authority(self):
        r=self.report();self.assertEqual(r['status'],'observed');self.assertFalse(any(r['authority'].values()))
    def test_both_providers_same_false_flags(self):
        self.assertEqual(self.report()['authority'],self.report(provider='codemagic')['authority'])
    def test_omitted_capability_is_unknown(self):
        self.assertEqual(self.report()['capabilities']['features']['autopoweroff'],'unknown')
    def test_power_missing_is_not_zero(self):
        r=self.records();r['power']['text']='AC Power:\n standby 0'
        self.assertFalse(self.report(r)['power']['required']['hibernatemode']['zero_in_all'])
    def test_duplicate_custom_refuses(self):
        self.assertFalse(p.power_diagnostic('AC Power:\n standby 0\n standby 0')['format_observed'])
    def test_duplicate_live_unknown(self):
        self.assertIsNone(p.live_power_diagnostic('Currently in use:\n standby 0\n standby 0')['required']['standby']['zero'])
    def test_prefix_not_adopted(self):
        r=p.live_power_diagnostic('System-wide power settings:\n standby 0\nCurrently in use:\n hibernatemode 0')
        self.assertEqual(r['required']['standby']['presence'],'absent')
    def test_malicious_header_refuses(self):
        self.assertFalse(p.live_power_diagnostic('secret:\nCurrently in use:\n standby 0')['observed'])
    def test_duplicate_cap_refuses(self):
        self.assertFalse(p.capability_diagnostic('Capabilities for AC Power:\n standby\n standby')['observed'])
    def test_oversize_parsers(self):
        for fn in (p.power_diagnostic,p.capability_diagnostic,p.live_power_diagnostic):
            self.assertNotIn('x'*65537,str(fn('x'*65537)))
    def test_swap_positive_snapshot(self):
        self.assertEqual(p.swap_view('total = 1.00G used = 512.00M free = 512.00M')['usedZero'],False)
    def test_swap_malformed(self):
        for text in ('secret','total = nanM used = 0.00M free = 0.00M','total = 1.00M used = 2.00M free = 0.00M', 'total = 0.00M used = 0.00M free = 0.00M\nsecret'):
            self.assertFalse(p.swap_view(text)['observed'])
    def test_changed_boot_holds(self):
        r=self.records();r['boot_after']['text']='87654321-1234-1234-1234-123456789abc'
        self.assertEqual(self.report(r)['status'],'held');self.assertIsNone(self.report(r)['bootSession'])
    def test_expiry_holds(self):
        for elapsed in (20000,21000,-1):self.assertEqual(self.report(elapsed=elapsed)['status'],'held')
    def test_missing_tool_holds(self):self.assertEqual(self.report(tools={})['status'],'held')
    def test_nonroot_holds(self):self.assertEqual(self.report(root_uid=501)['status'],'held')
    def test_cleanup_unknown_holds(self):
        r=self.records();r['core']['cleanup']=False
        self.assertEqual(self.report(r)['status'],'held')
    def test_command_failure_holds_no_raw_output(self):
        r=self.records();r['core']={'text':None,'code':'command-refused','cleanup':True}
        self.assertEqual(self.report(r)['status'],'held');self.assertNotIn('text',self.report(r)['commands']['core'])
    def test_fixed_argv_no_shell(self):
        tree=ast.parse((HERE/'probe.py').read_text())
        self.assertEqual(len(p.COMMANDS),10);self.assertTrue(all(argv[0].startswith('/usr/') for argv in p.COMMANDS.values()))
        self.assertFalse(any(isinstance(n,ast.keyword) and n.arg=='shell' for n in ast.walk(tree)))
        self.assertEqual(p.ENV,{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    def test_expired_no_spawn(self):
        with patch.object(p.time,'monotonic',return_value=100),patch.object(p.subprocess,'Popen',side_effect=AssertionError('no spawn')):
            self.assertEqual(p.run_fixed('core',99)['code'],'deadline')
    def test_scalar_rejects_extra_output(self):
        self.assertIsNone(p.scalar('0\nsecret',r'[01]'))
    def test_core_unknown_holds(self):
        r=self.records();r['core']['text']='2';self.assertIsNone(self.report(r)['kernelCoreDumpEnabled'])
    def test_output_closed_and_bounded(self):
        import json
        r=self.report();self.assertLess(len(json.dumps(r)),16384)
        self.assertEqual(set(r['commands']),set(p.COMMANDS));self.assertNotIn('/usr/',json.dumps(r))

    def test_extracted_parser_exact_reviewed_bytes(self):
        source=(HERE/'probe.py').read_text()
        expected={'capability_diagnostic': '1090d2397bd8a40ea23e32000f15586e54169c087bf7bf5984e6c284dea23b2e', 'live_power_diagnostic': '8aa54f67a245e3b76640f185b30d8f71b0debc30951f80924c50946d544c61a7', 'power_diagnostic': '9df9a428ce61241547b2ce3916a84795afd686d554ec0f90ca926d5f2e63f810'}
        actual={node.name:hashlib.sha256(ast.get_source_segment(source,node).encode()).hexdigest()
                for node in ast.parse(source).body if isinstance(node,ast.FunctionDef) and node.name in expected}
        self.assertEqual(actual,expected)
    def test_kill_group_precedes_reap(self):
        events=[]
        class Stdout:
            def close(self): pass
        class Child:
            pid=123;stdout=Stdout()
            def wait(self,timeout):events.append('reap');return 0
        class Selector:
            def register(self,*args):pass
            def get_map(self):return {}
            def close(self):pass
        def kill(pid,sig):
            events.append('kill' if sig else 'check')
            if not sig:raise ProcessLookupError()
        with patch.object(p.time,'monotonic',return_value=1),patch.object(p.subprocess,'Popen',return_value=Child()),patch.object(p.selectors,'DefaultSelector',return_value=Selector()),patch.object(p.os,'killpg',side_effect=kill):
            result=p.run_fixed('core',10)
        self.assertEqual(events,['kill','reap','check']);self.assertEqual(result['code'],'observed')
    def test_workflow_source_has_no_authority_integrations(self):
        source_root=HERE.parents[3]
        circle=(source_root/'.circleci/config.yml').read_text();codemagic=(source_root/'codemagic.yaml').read_text()
        self.assertIn('resource_class: m4pro.medium',circle);self.assertIn('instance_type: mac_mini_m2',codemagic)
        for text in (circle,codemagic):
            self.assertIn('"26.4.1"',text);self.assertIn('sudo -n /usr/bin/env -i',text)
            self.assertIn('codex/no-key-free-mac-capability',text)
            for forbidden in ('publishing:', 'contexts:', 'groups:', 'integrations:', 'orbs:', 'curl ', 'wget ', 'pip install', 'npm install', 'mac_mini_m4'):
                self.assertNotIn(forbidden,text)
    def test_nonzero_exit_never_observed(self):
        class Stdout:
            def close(self):pass
        class Child:
            pid=123;stdout=Stdout()
            def wait(self,timeout):return -9
        class Selector:
            def register(self,*args):pass
            def get_map(self):return {}
            def close(self):pass
        def kill(pid,sig):
            if not sig:raise ProcessLookupError()
        with patch.object(p.time,'monotonic',return_value=1),patch.object(p.subprocess,'Popen',return_value=Child()),patch.object(p.selectors,'DefaultSelector',return_value=Selector()),patch.object(p.os,'killpg',side_effect=kill):
            self.assertEqual(p.run_fixed('core',10)['code'],'command-refused')

if __name__=='__main__':unittest.main()
