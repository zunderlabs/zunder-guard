"""Inert shape fixtures; no native commands or policy modification."""
import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('closed_mac_policy',Path(__file__).with_name('mac_hosted_policy.py'))
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
GOOD='AC Power:\nhibernatemode 0\nstandby 0\nautopoweroff 0\n'


class PowerFormat(unittest.TestCase):
    def detail(self,text):return policy.power_format_diagnostic(text)
    def test_canonical(self):
        row=self.detail(GOOD);self.assertEqual(row['reason'],'canonical-shape')
        self.assertEqual(row['section_count'],1)
        self.assertTrue(all(v['zero_in_all']for v in row['required'].values()))
        self.assertEqual(len(policy.power_settings(GOOD)),1)
    def test_multiword_extra_remains_ineligible(self):
        text=GOOD+'Sleep On Power Button 1\n'
        row=self.detail(text);self.assertEqual(row['reason'],'multiple-fields')
        self.assertEqual(row['multifield_count'],1)
        self.assertTrue(all(v['zero_in_all']for v in row['required'].values()))
        self.assertFalse(policy.power_diagnostic(text)['format_observed'])
        with self.assertRaises(RuntimeError):policy.power_settings(text)
    def test_headerless(self):
        row=self.detail('extra 1\n'+GOOD);self.assertEqual(row['reason'],'headerless-lines')
        self.assertEqual(row['headerless_count'],1)
    def test_required_duplicate_is_ambiguous(self):
        row=self.detail(GOOD+'standby 0\n');self.assertEqual(row['reason'],'duplicate-fields')
        self.assertTrue(row['required']['standby']['ambiguous'])
        self.assertFalse(row['required']['standby']['present_in_all'])
        self.assertFalse(row['required']['standby']['zero_in_all'])
    def test_extra_duplicate(self):
        row=self.detail(GOOD+'extra 1\nextra 1\n');self.assertEqual(row['duplicate_count'],1)
    def test_required_multifield_is_ambiguous(self):
        row=self.detail(GOOD+'standby 0 extra\n');self.assertTrue(row['required']['standby']['ambiguous'])
        self.assertFalse(row['required']['standby']['zero_in_all'])
    def test_nonzero_required(self):
        row=self.detail(GOOD.replace('standby 0','standby 1'))
        self.assertTrue(row['required']['standby']['present_in_all'])
        self.assertFalse(row['required']['standby']['zero_in_all'])
    def test_missing_required(self):
        row=self.detail(GOOD.replace('standby 0\n',''))
        self.assertFalse(row['required']['standby']['present_in_all'])
    def test_all_sections(self):
        row=self.detail(GOOD+GOOD.replace('AC Power:','Battery Power:').replace('standby 0','standby 1'))
        self.assertEqual(row['section_count'],2);self.assertFalse(row['required']['standby']['zero_in_all'])
    def test_section_bound(self):
        self.assertEqual(self.detail(GOOD*4)['reason'],'section-bound-refused')
    def test_line_bound(self):
        self.assertEqual(self.detail('\n'*4097)['reason'],'line-bound-refused')
    def test_input_bound(self):
        for text in (None,False,b'AC Power:',{},'x'*65537):
            self.assertEqual(self.detail(text)['reason'],'input-refused')
    def test_no_sections(self):
        self.assertEqual(self.detail('private_key secret\n')['reason'],'no-sections')
    def test_never_echoes_provider_values(self):
        secret='SENSITIVE-provider-path-and-value'
        raw=json.dumps(self.detail(GOOD+secret+' value\n'+secret+' extra fields\n'))
        self.assertNotIn(secret,raw);self.assertNotIn('value',raw)
    def test_observation_has_no_authority(self):
        self.assertEqual(set(self.detail(GOOD)),{'kind','reason','line_count','section_count','headerless_count','multifield_count','duplicate_count','required'})


if __name__=='__main__':unittest.main()
