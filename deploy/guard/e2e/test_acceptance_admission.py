"""Synthetic admission fixtures only; no GitHub/AWS/key operation."""
import base64
import json
import unittest
from acceptance_admission import *
from release_flow import Refused
SHA='a'*40;CALLER_SHA='b'*40
PRODUCER={WORKFLOW:b'on:\n  workflow_call: {}\njobs:\n  acceptance:\n    environment: release-owner-controller\n'}
WORKFLOWS={**PRODUCER,CALLER:('on:\n  workflow_dispatch: {}\njobs:\n  verify:\n    uses: '+REPOSITORY+'/'+WORKFLOW+'@'+SHA+'\n').encode()}

class Admission(unittest.TestCase):
    def setUp(self):
        self.claims={'iss':'https://token.actions.githubusercontent.com','aud':'sts.amazonaws.com','sub':SUBJECT,
            'repository':REPOSITORY,'repository_id':str(REPOSITORY_ID),'repository_owner_id':str(OWNER_ID),
            'environment':ENVIRONMENT,'event_name':'workflow_dispatch','runner_environment':'github-hosted',
            'ref':'refs/heads/main','sha':CALLER_SHA,'workflow_sha':CALLER_SHA,'job_workflow_sha':SHA,
            'workflow_ref':REPOSITORY+'/'+CALLER+'@refs/heads/main',
            'job_workflow_ref':REPOSITORY+'/'+WORKFLOW+'@'+SHA,'run_id':'123','run_attempt':'1'}
        p='repos/'+REPOSITORY+'/'
        self.rows={p:{'id':REPOSITORY_ID,'full_name':REPOSITORY,'owner':{'id':OWNER_ID}},
            p+'environments/'+ENVIRONMENT:{'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True}},
            p+'environments/'+ENVIRONMENT+'/deployment-branch-policies?per_page=100':{'total_count':1,'branch_policies':[{'name':'main','type':'branch'}]},
            p+'actions/runs/123/attempts/1':{'id':123,'run_attempt':1,'event':'workflow_dispatch','head_sha':CALLER_SHA,
                'head_branch':'main','path':CALLER,'repository':{'id':REPOSITORY_ID},'head_repository':{'id':REPOSITORY_ID},'status':'in_progress'}}
    def token(self):
        enc=lambda x:base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip('=')
        return enc({'alg':'RS256','kid':'synthetic'})+'.'+enc(self.claims)+'.synthetic-unverified'
    def verify(self):
        value=claims_before_sts(self.token(),SHA)
        return admit(lambda p:self.rows[p],value,PRODUCER,SHA,WORKFLOWS)
    def test_source_claims_are_rejection_only_then_actual_controls_required(self):
        self.assertFalse(self.verify()['release_ready'])
    def test_pr_wrong_pin_or_foreign_repository_refuses(self):
        for field,value in [('ref','refs/pull/1/merge'),('event_name','pull_request'),('runner_environment','self-hosted'),
            ('repository_id','1'),('job_workflow_sha','c'*40),('job_workflow_ref',REPOSITORY+'/'+WORKFLOW+'@main')]:
            previous=self.claims[field];self.claims[field]=value
            with self.subTest(field=field),self.assertRaises(Refused):claims_before_sts(self.token(),SHA)
            self.claims[field]=previous
    def test_environment_main_only_and_actual_run_required(self):
        p='repos/'+REPOSITORY+'/'
        changes=[(p+'environments/'+ENVIRONMENT+'/deployment-branch-policies?per_page=100','branch_policies',[{'name':'*','type':'branch'}]),
            (p+'actions/runs/123/attempts/1','head_sha','c'*40),(p+'actions/runs/123/attempts/1','event','pull_request')]
        for path,key,value in changes:
            old=self.rows[path][key];self.rows[path][key]=value
            with self.subTest(key=key),self.assertRaises(Refused):self.verify()
            self.rows[path][key]=old
    def test_other_environment_job_dynamic_environment_or_extra_caller_refuses(self):
        for extra in [b'on: {workflow_dispatch: {}}\njobs:\n  other:\n    environment: release-owner-controller\n',
                      b'on: {workflow_dispatch: {}}\njobs:\n  other:\n    environment: "${{ inputs.env }}"\n',
                      ('on: {workflow_dispatch: {}}\njobs:\n  other:\n    uses: '+REPOSITORY+'/'+WORKFLOW+'@'+SHA+'\n').encode()]:
            with self.assertRaises(Refused):audit_workflows({**WORKFLOWS,'.github/workflows/other.yml':extra},SHA)
    def test_aws_trust_binds_exact_current_documented_workflow_claim(self):
        row=trust_policy(SHA)['Statement'][0]['Condition']['StringEquals']
        self.assertEqual(row['token.actions.githubusercontent.com:job_workflow_ref'],REPOSITORY+'/'+WORKFLOW+'@'+SHA)
        self.assertEqual(row['token.actions.githubusercontent.com:ref'],'refs/heads/main')
        self.assertEqual(row['token.actions.githubusercontent.com:repository_id'],str(REPOSITORY_ID))
        self.assertNotIn('token.actions.githubusercontent.com:workflow_sha',row)
    def test_admission_subclauses_do_not_emit_actual_api_body_or_path(self):
        value=claims_before_sts(self.token(),SHA);names=[]
        admit(lambda p:self.rows[p],value,PRODUCER,SHA,WORKFLOWS,checkpoint=names.append)
        self.assertEqual(names,list(ADMISSION_CLAUSES))
        prefix='repos/'+REPOSITORY+'/'
        for path,clause in [(prefix,'repository_request'),(prefix+'environments/'+ENVIRONMENT,'environment_request'),
            (prefix+'environments/'+ENVIRONMENT+'/deployment-branch-policies?per_page=100','branch_policies_request'),
            (prefix+'actions/runs/123/attempts/1','run_attempt_request')]:
            names=[]
            def api(request):
                if request==path:raise RuntimeError('synthetic-token-NEVER-LOG')
                return self.rows[request]
            with self.subTest(clause=clause),self.assertRaises(RuntimeError):admit(api,value,PRODUCER,SHA,WORKFLOWS,checkpoint=names.append)
            self.assertEqual(names[-1],clause)
        names=[]
        wrong={**self.rows[prefix+'actions/runs/123/attempts/1'],'status':'completed'}
        with self.assertRaises(Refused):admit(lambda p:wrong if p.endswith('/attempts/1')else self.rows[p],value,PRODUCER,SHA,WORKFLOWS,checkpoint=names.append)
        self.assertEqual(names[-1],'run_attempt_identity')
    def test_owner_role_cannot_read_native_epoch_or_bulk_history(self):
        from acceptance_owner_policy import documents,OWNER_ARN
        value=documents(SHA);rows=value['permissions']['Statement']
        allows=[r for r in rows if r['Effect']=='Allow' and r['Action']=='ssm:GetParameter']
        self.assertEqual([r['Resource'] for r in allows],[OWNER_ARN]);self.assertFalse(value['live_applied'])
if __name__=='__main__':unittest.main()
