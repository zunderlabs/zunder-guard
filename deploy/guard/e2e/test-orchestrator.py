#!/usr/bin/env python3
"""Offline policy, trigger, render and injection tests; no network/cloud/venue access."""
import importlib.util
from datetime import datetime, timezone
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
def load(name):
    s=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
o=load('orchestrator');r=load('render')
j=load('journey')
with patch.dict(__import__('sys').modules, {'journey':j}): scanner=load('scan')
SHA='1'*40
WALLET='0x'+'2'*40


class Tests(unittest.TestCase):
    def admission(self,event_name,event,**changes):
        args=dict(repository=o.REPO,ref='refs/heads/main',workflow_ref=o.REPO+'/.github/workflows/release-e2e.yml@refs/heads/main',policy_sha=SHA)
        args.update(changes);return o.admitted(event_name,event,**args)
    def run_event(self):
        return dict(workflow_run=dict(event='push',status='completed',conclusion='success',path='.github/workflows/release.yml',repository={'full_name':o.REPO},head_repository={'full_name':o.REPO},head_sha=SHA,id=42,head_branch='v1.0.1'))
    def test_dispatch(self):
        self.assertEqual(self.admission('workflow_dispatch',{'inputs':{'tag':'v1.0.1'}}),'v1.0.1')
    def test_release(self):
        self.assertEqual(self.admission('workflow_run',self.run_event()),'v1.0.1')
    def test_other_events(self):
        for e in ('pull_request','pull_request_target','push','repository_dispatch'):
            with self.assertRaises(RuntimeError):self.admission(e,{})
    def test_untrusted_context(self):
        for changes in (dict(repository='fork/zunder-guard'),dict(ref='refs/pull/2/merge'),dict(ref='refs/tags/v1.0.1'),dict(workflow_ref=o.REPO+'/.github/workflows/evil.yml@refs/heads/main'),dict(policy_sha='main')):
            with self.assertRaises(RuntimeError):self.admission('workflow_dispatch',{'inputs':{'tag':'v1.0.1'}},**changes)
    def test_untrusted_release_runs(self):
        for key,value in (('event','pull_request'),('status','in_progress'),('conclusion','failure'),('path','.github/workflows/evil.yml'),('repository',{'full_name':'fork/x'}),('head_repository',{'full_name':'fork/x'}),('head_sha','main'),('id',True),('head_branch','main')):
            event=self.run_event();event['workflow_run'][key]=value
            with self.assertRaises(RuntimeError):self.admission('workflow_run',event)
    def test_tag_injections(self):
        for tag in ('v1.0.1;id','$(id)','v1.0.1\n','../v1.0.1','v1.0.1-rc1','main',None):
            with self.assertRaises(RuntimeError):o.tag(tag)
    def test_control_injections(self):
        for operation,lease,digest in (('stop;id','1-1','0'*64),('stop','1-1;id','0'*64),('restore','1-1','$(id)')):
            with patch.object(o,'aws') as aws, self.assertRaises(RuntimeError):o.control(operation,lease,digest)
            aws.assert_not_called()
    def test_safe_environment(self):
        with patch.dict(os.environ,{'ZUNDER_MAINNET_CONFIRM':'bad','ZUNDER_HL_TESTNET_KEY':'fixture','HTTPS_PROXY':'evil','AWS_ENDPOINT_URL':'evil','DYLD_LIBRARY_PATH':'evil'}):e=o.env()
        for name in ('ZUNDER_MAINNET_CONFIRM','ZUNDER_HL_TESTNET_KEY','HTTPS_PROXY','AWS_ENDPOINT_URL','DYLD_LIBRARY_PATH','AWS_SECRET_ACCESS_KEY'):self.assertNotIn(name,e)
    def test_fixed_root(self):
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','E2E_PRIVATE_ROOT':'/tmp/zunder-release-e2e-123-1'}):self.assertEqual(str(o.private_root()),'/tmp/zunder-release-e2e-123-1')
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'123;id','GITHUB_RUN_ATTEMPT':'1','E2E_PRIVATE_ROOT':'/tmp/evil'}),self.assertRaises(RuntimeError):o.private_root()
    def test_render_immutable_and_least_privilege(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            out=Path(temp)/'out';r.render(SHA,WALLET,'alias/aws/ssm',out)
            trust=json.loads((out/'aws-trust-policy.json').read_text())
            sub=trust['Statement'][0]['Condition']['StringEquals']['token.actions.githubusercontent.com:sub']
            self.assertEqual(sub,'repo:zunderlabs@338317604/zunder-guard@1409357189:environment:release-testnet-e2e')
            self.assertNotIn('job_workflow_ref',sub);self.assertNotIn('*',sub)
            expected=json.loads((out/'oidc-expected-claims.json').read_text())
            self.assertTrue(expected['use_default']);self.assertTrue(expected['use_immutable_subject'])
            self.assertTrue(expected['evidence_workflow_ref'].endswith('@'+SHA))
            self.assertFalse((out/'github-oidc-subject-template.json').exists())
            self.assertEqual(trust,json.loads((ROOT/'aws-trust-policy.json').read_text()))
            policy=json.loads((out/'aws-permissions-policy.json').read_text())
            allows=[s for s in policy['Statement'] if s['Effect']=='Allow']
            self.assertEqual({a for s in allows for a in s['Action']},{'ssm:GetParameter','ssm:SendCommand','ssm:GetCommandInvocation'})
            self.assertNotIn('AUTOMATION_COMMIT',(out/'release-e2e.yml').read_text())
            p=json.loads((out/'policy.json').read_text());self.assertEqual(p['approved_public_api_wallet'],WALLET)
            self.assertEqual(p['aws_credential_trust_scope'],'canonical-repository-and-environment')
            self.assertNotIn('automation_commit',p)
    def test_render_rejects_bad_inputs(self):
        for commit,wallet,kms in (('main',WALLET,'alias/aws/ssm'),(SHA,WALLET+';id','alias/aws/ssm'),(SHA,'0x'+'0'*40,'alias/aws/ssm'),(SHA,WALLET,'arn:evil')):
            with tempfile.TemporaryDirectory(dir=ROOT) as temp, self.assertRaises(AssertionError):r.render(commit,wallet,kms,Path(temp)/'out')
    def test_fixed_document(self):
        d=json.loads((ROOT/'ssm-document.json').read_text())
        self.assertEqual(d['parameters']['operation']['allowedValues'],['stop','status','restore'])
        for p in d['parameters'].values():self.assertEqual(p['interpolationType'],'ENV_VAR')
        cmd=d['mainSteps'][0]['inputs']['runCommand'][0]
        self.assertNotIn('{{',cmd);self.assertIn('/usr/local/libexec/zunder-release-e2e/host-control.py',cmd)
    def test_attest_job_has_no_aws_or_key_access(self):
        text=(ROOT.parents[2]/'.github/workflows/release-e2e-run.yml').read_text().split('\n  attest:\n')[1]
        self.assertNotIn('configure-aws-credentials',text);self.assertNotIn('AWS_',text);self.assertNotIn('secrets.',text)
        self.assertIn("p['release_ready'] is False",text)
    def test_no_cancel_or_pr_secret_flow(self):
        t=(ROOT/'release-e2e.yml.in').read_text();self.assertIn('cancel-in-progress: false',t)
        self.assertNotIn('pull_request:',t);self.assertNotIn('secrets: inherit',t)
    def test_no_automatic_host_recovery_without_flat(self):
        t=(ROOT/'host-control.py').read_text()
        self.assertLess(t.index('.flat_all()'),t.index("systemctl('start')"))
        self.assertNotIn('resume_after_review',t)
        self.assertLess(t.index('.flat_all()'),t.index('LEASE.unlink()'))
        self.assertIn('/var/lib/zunder-release-e2e/lease.json',t)
        self.assertIn('ConditionPathExists=!/var/lib/zunder-release-e2e/lease.json',(ROOT/'runner-lease.conf').read_text())

    def test_actual_producer_scanner_parent_flat_contract(self):
        with tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve())) as temp:
            root=Path(temp);stop=root/'stop.json';flat=root/'flat.json';pause=root/'pause.json'
            binding=dict(tag='v1.0.1',source=SHA,manifest_sha256='2'*64)
            o.json_write(stop,o.make_stop(binding))
            self.assertTrue(json.loads(stop.read_text())['observed_at'].endswith('Z'))
            class Reads:
                def __init__(self,*unused,**kwargs):pass
                def flat_all(self):
                    stamp=o.utc();names=['']
                    self.flat_observation=dict(started_at=stamp,finished_at=stamp,user_abstraction='disabled',
                        dexes=names,inventory_sha256=j.json_hash(names),inventory_before_sha256='3'*64,
                        inventory_after_sha256='3'*64,observations=[dict(dex='',observed_at=stamp,positions=0,
                        open_orders=0,positive_equity=True,clearinghouse_sha256='4'*64,frontend_open_orders_sha256='5'*64)])
                    return True
            args=SimpleNamespace(runner_stop=stop,receipt=flat,tag=binding['tag'],source=SHA,
                                 manifest_sha256=binding['manifest_sha256'],account=o.ACCOUNT)
            with patch.object(scanner.j,'Reads',Reads),redirect_stdout(io.StringIO()):scanner.scan(args)
            o.json_write(pause,o.make_pause(binding,stop,flat))
            value=json.loads(pause.read_text())
            self.assertTrue(value['observed_at'].endswith('Z'));self.assertTrue(value['expires_at'].endswith('Z'))
            args.pause=pause;args.preflight_flat=flat
            self.assertTrue(j.parent_flat(args))
            value['observed_at']=value['observed_at'].replace('Z','+00:00')
            pause.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):j.parent_flat(args)

    def test_noncanonical_stop_is_rejected_before_scan(self):
        with tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve())) as temp:
            root=Path(temp);stop=root/'stop.json';value=o.make_stop(dict(tag='v1.0.1',source=SHA))
            value['observed_at']=value['observed_at'].replace('Z','+00:00');o.json_write(stop,value)
            args=SimpleNamespace(runner_stop=stop,receipt=root/'flat.json',tag='v1.0.1',source=SHA,
                                 manifest_sha256='2'*64,account=o.ACCOUNT)
            with patch.object(scanner.j,'Reads') as reads,self.assertRaises(RuntimeError):scanner.scan(args)
            reads.assert_not_called();self.assertFalse(args.receipt.exists())

    def test_utc_refuses_naive_time(self):
        with self.assertRaises(RuntimeError):o.utc(datetime(2026,10,8))


if __name__=='__main__':
    os.umask(0o077);unittest.main()
