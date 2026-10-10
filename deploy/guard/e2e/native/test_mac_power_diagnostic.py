"""Inert closed power readback fixtures; the original custody predicate is unchanged."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import mac_hosted_policy as p


class PowerDiagnostic(unittest.TestCase):
    def section(self,name='AC',mode='0',extra=''):
        return name+' Power:\n hibernatemode '+mode+'\n standby 0\n autopoweroff 0\n'+extra
    def test_positive_unchanged_predicate(self):
        for text in(self.section(),self.section()+self.section('Battery')):
            self.assertTrue(p.power_settings(text))
            d=p.power_diagnostic(text)
            self.assertTrue(d['format_observed'])
            self.assertTrue(all(v['present_in_all']and v['zero_in_all']for v in d['required'].values()))
    def test_missing_or_nonzero_field_still_refuses(self):
        for text in(self.section(mode='3'),self.section().replace(' standby 0\n',''),self.section()+self.section('Battery',mode='3')):
            with self.assertRaises(RuntimeError):p.power_settings(text)
            d=p.power_diagnostic(text)
            self.assertTrue(d['format_observed'])
            self.assertFalse(all(v['zero_in_all']for v in d['required'].values()))
    def test_malformed_or_unbounded_observation_is_closed(self):
        for text in('',None,'private-value',self.section(extra=' bad multiple fields\n'),self.section(extra=' standby 0\n'),self.section()*4,'x'*65537):
            self.assertEqual(p.power_diagnostic(text),p.power_diagnostic(''))
    def test_no_provider_text_or_unknown_fields_exported(self):
        marker='PRIVATE_PAYLOAD_SENTINEL'
        d=p.power_diagnostic(self.section(extra=' '+marker+' '+marker+'\n'))
        self.assertNotIn(marker,json.dumps(d))
        self.assertEqual(set(d),{'format_observed','section_count','required'})
        self.assertEqual(set(d['required']),{'hibernatemode','standby','autopoweroff'})
        for row in d['required'].values():
            self.assertEqual(set(row),{'present_in_all','zero_in_all'})
            self.assertTrue(all(type(v)is bool for v in row.values()))


if __name__=='__main__':unittest.main()
