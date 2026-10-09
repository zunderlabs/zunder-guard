"""Synthetic SDK/token/workflow fixtures only; never actual STS proof."""
import base64
import json
import contextlib
import io
from pathlib import Path
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch
import acceptance_identity as identity
from acceptance_admission import REPOSITORY,REPOSITORY_ID,OWNER_ID,ENVIRONMENT,SUBJECT,NEGATIVE_WORKFLOW,ROLE
from native_epoch import ACCOUNT
from release_flow import Refused

SOURCE='a'*40
class IdentityTests(unittest.TestCase):
    def sdk(self,result=None,error=None):
        self.calls=[]
        class STS:
            def assume_role_with_web_identity(_,**arguments):
                self.calls.append(arguments)
                if error:raise error
                return result
        boto=ModuleType('boto3');boto.session=SimpleNamespace(Session=lambda:SimpleNamespace(client=lambda *args,**kwargs:STS()))
        botocore=ModuleType('botocore');botocore.UNSIGNED='unsigned'
        config=ModuleType('botocore.config');config.Config=lambda **kwargs:kwargs
        return patch.dict('sys.modules',{'boto3':boto,'botocore':botocore,'botocore.config':config})
    def positive(self,result):
        bindings={'source':SOURCE,'caller_source':'b'*40,'run_id':123,'attempt':1}
        with self.sdk(result),patch.object(identity,'no_swap'),patch.object(identity,'private_diagnostics'),patch.object(identity,'checkout_head',return_value=SOURCE),patch.object(identity,'oidc_token',return_value='synthetic-token'),patch.object(identity,'claims_before_sts',return_value=bindings),patch.object(identity,'workflows_at',return_value={}),patch.object(identity,'admit',return_value={'release_ready':False}):
            return identity.probe(SOURCE)
    def negative_token(self):
        value={'repository_id':str(REPOSITORY_ID),'repository_owner_id':str(OWNER_ID),'ref':'refs/heads/main','sub':SUBJECT,'aud':'sts.amazonaws.com','environment':ENVIRONMENT,'job_workflow_ref':REPOSITORY+'/'+NEGATIVE_WORKFLOW+'@'+SOURCE,'run_id':'123','run_attempt':'1'}
        return 'synthetic.'+base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')+'.invalid-fixture'
    def negative(self,result=None,error=None):
        with self.sdk(result,error),patch.object(identity,'no_swap'),patch.object(identity,'private_diagnostics'),patch.object(identity,'checkout_head',return_value=SOURCE),patch.object(identity,'oidc_token',return_value=self.negative_token()):
            return identity.probe(SOURCE,negative=True)
    def test_positive_exact_identity_and_credentials_discarded(self):
        credentials={'AccessKeyId':'fixture-never-real'}
        result={'Credentials':credentials,'SubjectFromWebIdentityToken':SUBJECT,'Audience':'sts.amazonaws.com','AssumedRoleUser':{'Arn':'arn:aws:sts::'+ACCOUNT+':assumed-role/zunder-release-owner-controller/acceptance-123-1'}}
        observed=self.positive(result)
        self.assertFalse(observed['owner_parameter_read']);self.assertFalse(observed['release_ready'])
        self.assertEqual(credentials,{});self.assertEqual(result,{})
        self.assertEqual(self.calls[0]['RoleArn'],ROLE);self.assertEqual(self.calls[0]['DurationSeconds'],900)
    def test_wrong_role_fails_without_retaining_credentials(self):
        result={'Credentials':{},'SubjectFromWebIdentityToken':SUBJECT,'Audience':'sts.amazonaws.com','AssumedRoleUser':{'Arn':'other'}}
        with self.assertRaises(Refused):self.positive(result)
        self.assertEqual(result,{})
    def test_access_denied_is_only_negative_success(self):
        class Failure(Exception):response={'Error':{'Code':'AccessDenied'}}
        observed=self.negative(error=Failure())
        self.assertTrue(observed['policy_denied']);self.assertFalse(observed['owner_parameter_read'])
    def test_invalid_signature_is_not_policy_denial_proof(self):
        class Failure(Exception):response={'Error':{'Code':'InvalidIdentityToken'}}
        with self.assertRaises(Refused):self.negative(error=Failure())
    def test_negative_acceptance_fails_and_discards_credentials(self):
        credentials={'AccessKeyId':'fixture'};result={'Credentials':credentials}
        with self.assertRaises(Refused):self.negative(result=result)
        self.assertEqual(credentials,{});self.assertEqual(result,{})
    def test_rendered_caller_pins_literal_commit(self):
        from render_acceptance_caller import render
        value=render(SOURCE)
        self.assertIn('/release-acceptance-run.yml@'+SOURCE,value)
        self.assertIn('/release-owner-admission-negative.yml@'+SOURCE,value)
        self.assertNotIn('${{',value)
        with self.assertRaises(Refused):render('main')
    def test_diagnostics_only_fixed_stage_never_exception_or_token(self):
        sentinel='synthetic.JWT.request.SDK.credential-never-log'
        class Failure(Exception):
            def __str__(self):raise AssertionError('Exception must never stringify')
        for name in identity.PROBE_STAGES:
            def fail():identity.stage(name);raise Failure(sentinel)
            err=io.StringIO()
            with patch.object(identity,'main',side_effect=fail),patch.object(identity.signal,'signal'),contextlib.redirect_stderr(err):
                self.assertEqual(identity.cli(),1)
            suffix=' clause=unknown'if name in('positive_claims','admission')else ''
            if name in('control_workflows','caller_workflows','admission'):suffix+=' api=unknown'
            self.assertEqual(err.getvalue(), 'Actual owner admission probe incomplete at stage='+name+suffix+'; no owner key was read.\n')
            self.assertNotIn(sentinel,err.getvalue())
    def test_clause_diagnostic_never_emits_jwt_claim_values_or_exception(self):
        from acceptance_admission import claims_before_sts,WORKFLOW,CALLER,CLAIM_CLAUSES
        baseline={'iss':'https://token.actions.githubusercontent.com','aud':'sts.amazonaws.com','sub':SUBJECT,
            'repository':REPOSITORY,'repository_id':str(REPOSITORY_ID),'repository_owner_id':str(OWNER_ID),
            'environment':ENVIRONMENT,'event_name':'workflow_dispatch','runner_environment':'github-hosted',
            'sha':'b'*40,'ref':'refs/heads/main','workflow_sha':'b'*40,'job_workflow_sha':SOURCE,
            'workflow_ref':REPOSITORY+'/'+CALLER+'@refs/heads/main','job_workflow_ref':REPOSITORY+'/'+WORKFLOW+'@'+SOURCE,
            'run_id':'123','run_attempt':'1'}
        encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        token=lambda value:encode({'alg':'RS256','kid':'synthetic-public-fixture'})+'.'+encode(value)+'.synthetic-invalid-signature'
        emitted=[]
        actual=claims_before_sts(token(baseline),SOURCE,checkpoint=emitted.append)
        self.assertEqual(actual['run_id'],123);self.assertEqual(emitted,list(CLAIM_CLAUSES))
        wrong={'subject':'sub','repository_id':'repository_id','environment':'environment',
            'caller_workflow_sha':'workflow_sha','reusable_workflow_sha':'job_workflow_sha',
            'caller_workflow_ref':'workflow_ref','reusable_workflow_ref':'job_workflow_ref','run_attempt':'run_attempt'}
        sentinel='synthetic.JWT.claim-value-NEVER-LOG'
        for clause,key in wrong.items():
            emitted=[]
            with self.subTest(clause=clause),self.assertRaises(Refused):claims_before_sts(token({**baseline,key:sentinel}),SOURCE,checkpoint=emitted.append)
            self.assertEqual(emitted[-1],clause);self.assertTrue(set(emitted)<=set(CLAIM_CLAUSES))
            with patch.object(identity,'_current_stage','positive_claims'),patch.object(identity,'_current_claim_clause',clause):
                message=identity.safe_failure_message();self.assertIn('clause='+clause+';',message);self.assertNotIn(sentinel,message)
        with patch.object(identity,'_current_stage','positive_claims'),patch.object(identity,'_current_claim_clause',sentinel):
            self.assertIn('clause=unknown;',identity.safe_failure_message());self.assertNotIn(sentinel,identity.safe_failure_message())
        with self.assertRaises(Refused):identity.claim_checkpoint(sentinel)
    def test_immutable_subject_is_exact_and_legacy_subject_refused(self):
        from acceptance_admission import claims_before_sts,trust_policy,WORKFLOW,CALLER
        self.assertEqual(SUBJECT,'repo:zunderlabs@338317604/zunder-guard@1409357189:environment:release-owner-controller')
        condition=trust_policy(SOURCE)['Statement'][0]['Condition']['StringEquals']
        self.assertEqual(condition['token.actions.githubusercontent.com:sub'],SUBJECT)
        self.assertEqual(condition['token.actions.githubusercontent.com:repository_id'],str(REPOSITORY_ID))
        self.assertEqual(condition['token.actions.githubusercontent.com:repository_owner_id'],str(OWNER_ID))
        base={'iss':'https://token.actions.githubusercontent.com','aud':'sts.amazonaws.com','sub':SUBJECT,
            'repository':REPOSITORY,'repository_id':str(REPOSITORY_ID),'repository_owner_id':str(OWNER_ID),
            'environment':ENVIRONMENT,'event_name':'workflow_dispatch','runner_environment':'github-hosted',
            'sha':'b'*40,'ref':'refs/heads/main','workflow_sha':'b'*40,'job_workflow_sha':SOURCE,
            'workflow_ref':REPOSITORY+'/'+CALLER+'@refs/heads/main','job_workflow_ref':REPOSITORY+'/'+WORKFLOW+'@'+SOURCE,
            'run_id':'123','run_attempt':'1'}
        encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        for subject in('repo:'+REPOSITORY+':environment:'+ENVIRONMENT,SUBJECT.replace('@338317604','@1'),
            SUBJECT.replace('@1409357189','@2'),SUBJECT.replace('release-owner-controller','other')):
            names=[];token=encode({'alg':'RS256','kid':'fixture'})+'.'+encode({**base,'sub':subject})+'.synthetic-invalid-signature'
            with self.subTest(subject=subject),self.assertRaises(Refused):claims_before_sts(token,SOURCE,checkpoint=names.append)
            self.assertEqual(names[-1],'subject')
    def test_bad_structure_decode_and_algorithm_emit_only_fixed_clause(self):
        from acceptance_admission import claims_before_sts
        encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        cases=[('bad-token','token_structure'),('!.e30.signature','header_decode'),
            (encode({'alg':'RS256','kid':'fixture'})+'.!.signature','payload_decode'),
            (encode({'alg':'none','kid':'fixture'})+'.e30.signature','algorithm')]
        for token,clause in cases:
            names=[]
            with self.subTest(clause=clause),self.assertRaises(Exception):claims_before_sts(token,SOURCE,checkpoint=names.append)
            self.assertEqual(names[-1],clause)
    def test_unknown_diagnostic_value_is_not_printed(self):
        with patch.object(identity,'_current_stage','synthetic-token'):
            self.assertIn('stage=unknown;',identity.safe_failure_message())
            self.assertNotIn('synthetic-token',identity.safe_failure_message())
        with self.assertRaises(Refused):identity.stage('synthetic-token')
    def test_hosted_swap_remains_refused(self):
        with patch.object(identity.sys,'platform','linux'),patch.object(identity.Path,'is_file',return_value=True),patch.object(identity.Path,'read_text',return_value='Filename Type Size Used Priority\n/swapfile file 100 0 -2\n'),patch.object(identity.resource,'setrlimit')as core:
            with self.assertRaises(Refused):identity.no_swap()
            core.assert_not_called()
    def test_no_swap_and_core_zero_required(self):
        with patch.object(identity.sys,'platform','linux'),patch.object(identity.Path,'is_file',return_value=True),patch.object(identity.Path,'read_text',return_value='Filename Type Size Used Priority\n'),patch.object(identity.resource,'setrlimit')as core,patch.object(identity.resource,'getrlimit',return_value=(0,0)):
            identity.no_swap();core.assert_called_once_with(identity.resource.RLIMIT_CORE,(0,0))
    def test_api_checkpoints_are_exact_fixed_routes_never_path_values(self):
        prefix='repos/'+REPOSITORY+'/'
        routes={'environment':'environments/'+ENVIRONMENT,
            'branch_policies':'environments/'+ENVIRONMENT+'/deployment-branch-policies?per_page=100',
            'run_attempt':'actions/runs/123/attempts/1','git_commit':'git/commits/'+SOURCE,
            'git_tree':'git/trees/'+SOURCE+'?recursive=1','git_blob':'git/blobs/'+SOURCE}
        identity.api_checkpoint(prefix[:-1]);self.assertEqual(identity._current_api_clause,'repository')
        with self.assertRaises(Refused):identity.api_checkpoint(prefix)
        for expected,path in routes.items():
            identity.api_checkpoint(prefix+path)
            self.assertEqual(identity._current_api_clause,expected)
        sentinel='synthetic-token-NEVER-LOG'
        with self.assertRaises(Refused):identity.api_checkpoint(prefix+sentinel)
        with patch.object(identity,'_current_stage','admission'),patch.object(identity,'_current_admission_clause',sentinel),patch.object(identity,'_current_api_clause',sentinel):
            self.assertIn('clause=unknown api=unknown;',identity.safe_failure_message())
            self.assertNotIn(sentinel,identity.safe_failure_message())
        identity._current_api_clause='unknown'
    def test_documented_read_permission_propagates_from_caller(self):
        import yaml
        from render_acceptance_caller import render
        for job in yaml.load(render(SOURCE),Loader=yaml.BaseLoader)['jobs'].values():
            self.assertEqual(job['permissions'],{'contents':'read','actions':'read','id-token':'write'})
    def test_runtime_and_memory_preflight_exact_workflow_closure(self):
        import yaml
        repo=Path(__file__).resolve().parents[3]
        for name,job in [('release-acceptance-run.yml','acceptance'),('release-owner-admission-negative.yml','deny')]:
            template=repo/'deploy/guard/github/workflows'/name
            published=repo/'.github/workflows'/name
            self.assertEqual(published.read_bytes(),template.read_bytes())
            job_definition=yaml.load(template.read_bytes(),Loader=yaml.BaseLoader)['jobs'][job]
            self.assertEqual(job_definition['permissions'],{'contents':'read','actions':'read','id-token':'write'})
            steps=job_definition['steps']
            memory=steps[1]['run'];runtime=steps[2]['run'];probe=steps[3]
            self.assertIn('/usr/bin/sudo --non-interactive /usr/sbin/swapoff --all',memory)
            self.assertIn("len(swaps.read_text().splitlines()) != 1",memory)
            self.assertIn('ulimit -c 0',memory);self.assertNotIn('env',steps[1])
            self.assertIn('--only-binary=:all: --require-hashes -r deploy/guard/e2e/admission-requirements.txt',runtime)
            self.assertIn('GH_TOKEN',probe['env']);self.assertIn('acceptance_identity.py',probe['run'])
            self.assertEqual(steps[0]['with']['persist-credentials'],'false')
    def test_actual_workflow_source_audit(self):
        from acceptance_admission import audit_workflows,WORKFLOW,CALLER
        from render_acceptance_caller import render
        root=Path(__file__).resolve().parents[1]/'github/workflows'
        definitions={WORKFLOW:(root/'release-acceptance-run.yml').read_bytes(),NEGATIVE_WORKFLOW:(root/'release-owner-admission-negative.yml').read_bytes()}
        for raw in definitions.values():
            self.assertEqual(raw.count(b'${{ fromJSON(toJSON(job)).workflow_sha }}'),2)
            self.assertIn(b'ref: ${{ fromJSON(toJSON(job)).workflow_sha }}',raw)
            self.assertIn(b'CONTROL_SOURCE: ${{ fromJSON(toJSON(job)).workflow_sha }}',raw)
        audit_workflows(definitions,SOURCE,caller=False)
        audit_workflows({**definitions,CALLER:render(SOURCE).encode()},SOURCE)

if __name__=='__main__':unittest.main()
