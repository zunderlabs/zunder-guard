"""Synthetic SDK/token/workflow fixtures only; never actual STS proof."""
import base64
import json
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
