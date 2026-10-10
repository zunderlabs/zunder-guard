"""Pure diagnostics and mocked bounded reads; never executes native probes."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('capability_mac_policy',Path(__file__).with_name('mac_hosted_policy.py'))
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
CAP='Capabilities for AC Power:\nstandby\nsleep\nhibernatemode\nautopoweroff\n'
LIVE='Currently in use:\nhibernatemode 0\nstandby 0\nautopoweroff 0\n'
CUSTOM='AC Power:\nhibernatemode 0\nstandby 0\nautopoweroff 0\n'


class Capability(unittest.TestCase):
    def test_supported(self):
        row=policy.capability_diagnostic(CAP)
        self.assertTrue(row['observed']);self.assertEqual(row['power_source'],'ac')
        self.assertEqual(set(row['features'].values()),{'supported'})
    def test_current_source(self):
        for source in ('AC','Battery','UPS'):
            self.assertEqual(policy.capability_diagnostic(CAP.replace('AC',source))['power_source'],source.lower())
    def test_negative_api_result_separate_from_missing_value(self):
        row=policy.capability_diagnostic('Capabilities for AC Power:\nstandby\n')
        self.assertEqual(row['features']['hibernatemode'],'unknown')
        live=policy.live_power_diagnostic('Currently in use:\nstandby 0\n')
        self.assertEqual(live['required']['hibernatemode'],{'presence':'absent','zero':None})
    def test_incomplete_or_negative_vocabulary_never_proves_unsupported(self):
        for text in ('Capabilities for AC Power:\nsleep\n','Capabilities for AC Power:\nstandby\n','Capabilities for AC Power:\nautopoweroff\n'):
            row=policy.capability_diagnostic(text)
            self.assertNotIn('unsupported',row['features'].values())
            self.assertTrue(any(v=='unknown'for v in row['features'].values()))
    def test_empty_malformed_unknown(self):
        for text in ('','Capabilities for AC Power:\n','Capabilities for AC Power:\n\n',CAP+'standby\n',CAP+'extra key\n',CAP.replace('AC','mystery'),'private secret'):
            with self.subTest(text=text):
                row=policy.capability_diagnostic(text);self.assertFalse(row['observed'])
                self.assertEqual(set(row['features'].values()),{'unknown'})
    def test_cap_bounds(self):
        for text in (None,False,{},b'private','x'*65537,'Capabilities for AC Power:\n'+'sleep\n'*65):
            self.assertFalse(policy.capability_diagnostic(text)['observed'])
    def test_live_zero(self):
        row=policy.live_power_diagnostic(LIVE)
        self.assertTrue(row['observed']);self.assertTrue(all(v=={'presence':'present','zero':True}for v in row['required'].values()))
    def test_live_nonzero_and_noncanonical_zero(self):
        for value in ('1','25','00'):
            row=policy.live_power_diagnostic(LIVE.replace('hibernatemode 0','hibernatemode '+value))
            self.assertEqual(row['required']['hibernatemode'],{'presence':'present','zero':False})
    def test_live_duplicate_and_bad_value(self):
        for suffix in ('standby 0','standby 1','standby 0 private','standby secret','standby -1'):
            row=policy.live_power_diagnostic(LIVE+suffix+'\n')
            self.assertEqual(row['required']['standby'],{'presence':'unknown','zero':None})
    def test_live_unknown_header_and_bounds(self):
        for text in (None,{},'','AC Power:\nstandby 0\n','x'*65537,'Currently in use:\n'+'\n'*4096):
            self.assertFalse(policy.live_power_diagnostic(text)['observed'])
    def test_unrelated_override_does_not_become_required(self):
        row=policy.live_power_diagnostic(LIVE+'sleep 1 (sleep prevented by SENSITIVE)\n')
        self.assertTrue(row['observed']);self.assertTrue(row['required']['standby']['zero'])
        self.assertNotIn('SENSITIVE',json.dumps(row))
    def test_never_echoes_payload(self):
        secret='SENSITIVE-private-provider-output'
        for row in (policy.capability_diagnostic(CAP+secret+'\n'),policy.live_power_diagnostic(LIVE+'standby '+secret+'\n')):
            self.assertNotIn(secret,json.dumps(row))
    def test_fixed_reads_share_original_deadline(self):
        calls=[]
        def read(argv,*,deadline):
            calls.append((argv,deadline));return CAP if argv[-1]=='cap'else LIVE
        with patch.object(policy,'public',side_effect=read):row=policy.power_capability_probe(deadline=123)
        self.assertEqual(calls,[(['/usr/bin/pmset','-g','cap'],123),(['/usr/bin/pmset','-g','live'],123)])
        self.assertTrue(row['capabilities']['observed']);self.assertFalse(row['universal_hibernation_absence_proven'])
        self.assertFalse(row['universal_crash_capture_prevention_proven'])
    def test_read_refusal_no_exception_text(self):
        with patch.object(policy,'public',side_effect=RuntimeError('SENSITIVE')):row=policy.power_capability_probe(deadline=0)
        self.assertEqual(row['capabilities']['reason'],'readback-unavailable');self.assertFalse(row['live']['observed'])
        self.assertNotIn('SENSITIVE',json.dumps(row))
    def test_source_supported_optional_system_prefix(self):
        row=policy.live_power_diagnostic('System-wide power settings:\n SleepDisabled 0\n'+LIVE)
        self.assertTrue(row['observed']);self.assertTrue(row['required']['standby']['zero'])
        self.assertEqual(row['shape'],{'line_count':6,'system_header_count':1,'live_header_count':1,
            'unknown_header_count':0,'prefix_line_count':1,'live_line_count':3,
            'required_duplicate_count':0,'required_multifield_count':0})
    def test_system_values_never_adopted_into_live_section(self):
        row=policy.live_power_diagnostic('System-wide power settings:\nhibernatemode 0\nautopoweroff 0\nCurrently in use:\nstandby 0\n')
        self.assertTrue(row['observed'])
        self.assertEqual(row['required']['hibernatemode'],{'presence':'absent','zero':None})
        self.assertEqual(row['required']['autopoweroff'],{'presence':'absent','zero':None})
    def test_duplicate_missing_reversed_headings_stay_unknown(self):
        cases=[('System-wide power settings:\nstandby 0\n','header-count-refused'),
            (LIVE+LIVE,'header-count-refused'),
            ('System-wide power settings:\nSystem-wide power settings:\n'+LIVE,'header-count-refused'),
            (LIVE+'System-wide power settings:\nSleepDisabled 0\n','header-order-refused')]
        for text,reason in cases:
            row=policy.live_power_diagnostic(text);self.assertFalse(row['observed']);self.assertEqual(row['reason'],reason)
            self.assertTrue(all(v=={'presence':'unknown','zero':None}for v in row['required'].values()))
    def test_unknown_prefix_or_heading_cannot_merge_sections(self):
        for text in ('SENSITIVE 0\n'+LIVE,'AC Power:\n'+LIVE,LIVE+'SENSITIVE:\nstandby 0\n'):
            row=policy.live_power_diagnostic(text);self.assertFalse(row['observed'])
            self.assertNotIn('SENSITIVE',json.dumps(row));self.assertIsNone(row['required']['standby']['zero'])
    def test_required_ambiguities_counted_inside_live_only(self):
        row=policy.live_power_diagnostic('System-wide power settings:\nstandby 0 extra\n'+LIVE+'standby 0 extra\n')
        self.assertEqual(row['shape']['required_duplicate_count'],1)
        self.assertEqual(row['shape']['required_multifield_count'],1)
        self.assertEqual(row['required']['standby'],{'presence':'unknown','zero':None})
    def test_blank_lines_and_empty_live_section(self):
        row=policy.live_power_diagnostic('\n\nSystem-wide power settings:\n\n'+LIVE)
        self.assertTrue(row['observed']);self.assertEqual(row['shape']['prefix_line_count'],0)
        row=policy.live_power_diagnostic('System-wide power settings:\nSleepDisabled 0\nCurrently in use:\n')
        self.assertFalse(row['observed']);self.assertEqual(row['reason'],'empty-live-section')
    def test_closed_shape_has_no_payload(self):
        row=policy.live_power_diagnostic('System-wide power settings:\nSENSITIVE unknown /private/path\n'+LIVE+'sleep 1 (SENSITIVE)\n')
        self.assertTrue(row['observed']);text=json.dumps(row)
        for forbidden in ('SENSITIVE','/private/path','SleepDisabled','sleep 1'):
            self.assertNotIn(forbidden,text)
        self.assertFalse('eligible'in row);self.assertFalse('coverage'in row)
    def test_original_eligibility_stays_strict(self):
        self.assertEqual(len(policy.power_settings(CUSTOM)),1)
        self.assertTrue(policy.validate('0 (encrypted)','FileVault is Off.',CUSTOM,'1',(0,0))['hibernation_disabled'])
        policy.capability_diagnostic('Capabilities for AC Power:\nsleep\n')
        with self.assertRaises(RuntimeError):policy.validate('0 (encrypted)','FileVault is Off.','AC Power:\nstandby 0\n','1',(0,0))
    def test_probe_exports_observation_without_authority_or_helper_gate_change(self):
        def read(argv,**kwargs):
            return {'cap':CAP,'live':LIVE,'custom':'AC Power:\nstandby 0\n','vm.swapusage':'0 (encrypted)','status':'FileVault is Off.','kern.coredump':'1'}[argv[-1]]
        with patch.object(policy,'public',side_effect=read),patch.object(policy.platform,'system',return_value='Linux'),patch.object(policy.platform,'machine',return_value='arm64'),patch.object(policy.os,'geteuid',return_value=0),patch.object(policy.resource,'setrlimit'),patch.object(policy.resource,'getrlimit',return_value=(0,0)),patch.object(policy,'inspect_sleep_and_core',return_value=True),patch.object(policy.subprocess,'Popen',side_effect=AssertionError('no native execution')):
            row=policy.probe()
        self.assertTrue(row['power_capability_observation']['capabilities']['observed'])
        self.assertFalse(row['eligible']);self.assertFalse(row['privateInput']);self.assertFalse(row['releaseReady'])


if __name__=='__main__':unittest.main()
