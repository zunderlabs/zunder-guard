#!/usr/bin/env python3
"""Offline installed-binding, loaded systemd condition and restore-race regressions."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('host',ROOT/'host-control.py');h=importlib.util.module_from_spec(s);s.loader.exec_module(h)


class Tests(unittest.TestCase):
    def properties(self):
        return dict(Id=h.UNIT+'.service',LoadState='loaded',NeedDaemonReload=False,
                    DropInPaths=[str(h.DROPIN)],Conditions=[['ConditionPathExists',False,True,str(h.LEASE),0]])
    def test_loaded_exact_nontrigger_negated_condition(self):
        p=self.properties()
        with patch.object(h,'installed_binding'),patch.object(h,'bus_property',side_effect=lambda n,s:p[n]):
            self.assertTrue(h.boot_inhibition())
    def test_unloaded_missing_malformed_foreign_or_trigger_condition_refused(self):
        changes=[('Id','foreign.service'),('LoadState','not-found'),('NeedDaemonReload',True),
                 ('DropInPaths',[]),('Conditions',[]),('Conditions','bad'),
                 ('Conditions',[['ConditionPathExists',True,True,str(h.LEASE),0]]),
                 ('Conditions',[['ConditionPathExists',False,False,str(h.LEASE),0]]),
                 ('Conditions',[['ConditionPathExists',False,True,'/foreign/lease.json',0]]),
                 ('Conditions',[['ConditionPathExists',False,True,str(h.LEASE),False]])]
        for name,value in changes:
            p=self.properties();p[name]=value
            with self.subTest(name=name,value=value),patch.object(h,'installed_binding'),patch.object(h,'bus_property',side_effect=lambda n,s:p[n]),self.assertRaises(RuntimeError):h.boot_inhibition()
    def test_missing_installed_binding_blocks_before_dbus(self):
        with patch.object(h,'installed_binding',side_effect=FileNotFoundError),patch.object(h,'bus_property') as bus,self.assertRaises(FileNotFoundError):h.boot_inhibition()
        bus.assert_not_called()
    def test_stop_refuses_before_touching_service_without_boot_inhibition(self):
        with patch.object(h.os,'geteuid',return_value=0),patch.object(h.os,'open',return_value=123),patch.object(h.os,'close'),patch.object(h.fcntl,'flock'),patch.object(h,'boot_inhibition',side_effect=RuntimeError),patch.object(h,'systemctl') as systemctl,self.assertRaises(RuntimeError):h.main('stop','1-1','0'*64)
        systemctl.assert_not_called()
    def test_exact_installed_policy_hashes_and_scope(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root=Path(temp);lease=root/'state'/'lease.json';lease.parent.mkdir();dropin=root/'dropin.conf'
            for path,data in [(root/'host-control.py',b'control'),(root/'journey.py',b'journey'),(dropin,b'dropin')]:path.write_bytes(data)
            policy=dict(unit=h.UNIT+'.service',lease_path=str(lease),dropin_path=str(dropin),dropin_sha256=hashlib.sha256(b'dropin').hexdigest(),host_control_sha256=hashlib.sha256(b'control').hexdigest(),journey_sha256=hashlib.sha256(b'journey').hexdigest())
            (root/'host-policy.json').write_text(json.dumps(policy))
            with patch.object(h,'ROOT',root),patch.object(h,'LEASE',lease),patch.object(h,'DROPIN',dropin),patch.object(h,'__file__',str(root/'host-control.py')),patch.object(h,'trusted'):
                self.assertEqual(h.installed_binding(),policy)
                for field,value in [('unit','foreign.service'),('lease_path','/foreign/lease.json'),('dropin_sha256','0'*64),('host_control_sha256','0'*64),('journey_sha256','0'*64)]:
                    bad=dict(policy);bad[field]=value;(root/'host-policy.json').write_text(json.dumps(bad))
                    with self.subTest(field=field),self.assertRaises(RuntimeError):h.installed_binding()
                (root/'host-policy.json').write_text(json.dumps(policy));dropin.unlink()
                with self.assertRaises(FileNotFoundError):h.installed_binding()
    def test_bus_signature_or_shape_drift_refused(self):
        for raw in (b'{}',b'{"type":"s","data":[]}',b'{"type":"a(sbbsi)","data":[],"extra":true}'):
            result=subprocess.CompletedProcess([],0,stdout=raw)
            with patch.object(h.subprocess,'run',return_value=result),self.assertRaises(RuntimeError):h.bus_property('Conditions','a(sbbsi)')
    def test_pending_job_blocks_stopped_proof(self):
        with patch.object(h,'bus_property',return_value=[7,'/org/freedesktop/systemd1/job/7']):self.assertFalse(h.no_pending_job())
        with patch.object(h,'bus_property',return_value=[0,'/']):self.assertTrue(h.no_pending_job())
    def test_delayed_start_after_timeout_is_cancelled_before_paused_claim(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            lease=Path(temp)/'lease.json';events=[];state={'active':True,'pending':True}
            def write(value):events.append('lease');lease.write_text(json.dumps(value))
            def systemctl(action):
                events.append(action)
                if action=='stop':state.update(active=False,pending=False)
                if action=='is-active':return 'active' if state['active'] else 'inactive'
            out=io.StringIO()
            with patch.object(h,'LEASE',lease),patch.object(h,'write_lease',side_effect=write),patch.object(h,'systemctl',side_effect=systemctl),patch.object(h,'no_pending_job',side_effect=lambda:not state['pending']),patch.object(h,'boot_inhibition',return_value=True),redirect_stdout(out),self.assertRaises(RuntimeError):h.recover_failed_restore(dict(lease='1-1'))
            self.assertEqual(events[:2],['lease','stop']);self.assertFalse(state['active']);self.assertFalse(state['pending'])
            report=json.loads(out.getvalue());self.assertTrue(report['stopped_confirmed']);self.assertFalse(report['root_reconciliation_required']);self.assertTrue(report['restore_failed'])
    def test_stop_timeout_does_not_claim_retained_pause(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            lease=Path(temp)/'lease.json';out=io.StringIO()
            def systemctl(action):
                if action=='stop':raise subprocess.TimeoutExpired('systemctl',45)
                return 'active'
            with patch.object(h,'LEASE',lease),patch.object(h,'write_lease',side_effect=lambda v:lease.write_text(json.dumps(v))),patch.object(h,'systemctl',side_effect=systemctl),redirect_stdout(out),self.assertRaises(RuntimeError):h.recover_failed_restore(dict(lease='1-1'))
            report=json.loads(out.getvalue());self.assertFalse(report['stopped_confirmed']);self.assertTrue(report['root_reconciliation_required']);self.assertEqual(report['runner_state'],'active')
    def test_pending_job_does_not_claim_retained_pause(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            lease=Path(temp)/'lease.json';out=io.StringIO()
            with patch.object(h,'LEASE',lease),patch.object(h,'write_lease',side_effect=lambda v:lease.write_text(json.dumps(v))),patch.object(h,'systemctl',return_value='inactive'),patch.object(h,'no_pending_job',return_value=False),redirect_stdout(out),self.assertRaises(RuntimeError):h.recover_failed_restore(dict(lease='1-1'))
            report=json.loads(out.getvalue());self.assertFalse(report['stopped_confirmed']);self.assertTrue(report['root_reconciliation_required'])

    def test_full_restore_start_timeout_cancels_delayed_activation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root=Path(temp);lease=root/'lease.json';lock=root/'lock';events=[]
            value=dict(lease='1-1',service=h.UNIT,previous='active');lease.write_text(json.dumps(value))
            (root/'journey.py').write_bytes(b'offline fixture')
            (root/'host-policy.json').write_text(json.dumps(dict(journey_sha256=hashlib.sha256(b'offline fixture').hexdigest())))
            state=dict(pending=False,active=False)
            class Reads:
                def __init__(self,*args,**kwargs):pass
                def flat_all(self):events.append('flat');return True
            module=SimpleNamespace(Reads=Reads)
            spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m:None))
            def systemctl(action):
                events.append(action)
                if action=='start':
                    state['pending']=True
                    raise subprocess.TimeoutExpired('systemctl',45)
                if action=='stop':state.update(pending=False,active=False)
                if action=='is-active':
                    if state['pending']:state['active']=True  # Activation after the start call timed out.
                    return 'active' if state['active'] else 'inactive'
            out=io.StringIO()
            with patch.object(h,'ROOT',root),patch.object(h,'LEASE',lease),patch.object(h,'LOCK',lock),patch.object(h.os,'geteuid',return_value=0),patch.object(h,'boot_inhibition',return_value=True),patch.object(h,'no_pending_job',side_effect=lambda:not state['pending']),patch.object(h,'systemctl',side_effect=systemctl),patch.object(h.importlib.util,'spec_from_file_location',return_value=spec),patch.object(h.importlib.util,'module_from_spec',return_value=module),redirect_stdout(out),self.assertRaises(RuntimeError):h.main('restore','1-1','a'*64)
            self.assertLess(events.index('flat'),events.index('start'));self.assertLess(events.index('start'),events.index('stop'))
            self.assertTrue(lease.exists());self.assertFalse(state['pending']);self.assertFalse(state['active'])
            report=json.loads(out.getvalue());self.assertTrue(report['restore_failed']);self.assertTrue(report['stopped_confirmed'])

    def test_foreign_owner_or_symlink_installed_binding_refused(self):
        for owner,mode in ((1,0o100644),(0,0o120777),(0,0o100666)):
            def info(path):
                return SimpleNamespace(st_uid=owner if str(path)=='/fixture' else 0,
                    st_mode=mode if str(path)=='/fixture' else 0o40755,st_nlink=1)
            with patch.object(Path,'lstat',info),self.assertRaises(RuntimeError):h.trusted(Path('/fixture'))


if __name__=='__main__':
    os.umask(0o077);unittest.main()
