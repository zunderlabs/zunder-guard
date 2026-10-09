"""Exact SHA-pinned reusable OIDC admission; no operation on import.

AWS currently documents job_workflow_ref/ref/environment/repository ID trust
keys. Real positive and negative STS probes must pass before owner custody.
workflow_sha itself remains a local, token/source-closure check.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
from release_flow import decode, need

REPOSITORY='zunderlabs/zunder-guard'
REPOSITORY_ID=1409357189
OWNER_ID=338317604
ENVIRONMENT='release-owner-controller'
CALLER='.github/workflows/release-acceptance.yml'
WORKFLOW='.github/workflows/release-acceptance-run.yml'
NEGATIVE_WORKFLOW='.github/workflows/release-owner-admission-negative.yml'
ROLE='arn:aws:iam::436632189317:role/zunder-release-owner-controller'
# GitHub immutable default for this actual post-15July2026 repository.
# Exact repository/org IDs are also separately required by source and IAM.
SUBJECT='repo:zunderlabs@338317604/zunder-guard@1409357189:environment:'+ENVIRONMENT


CLAIM_CLAUSES=('token_structure','header_decode','payload_decode','algorithm','key_identifier',
    'issuer','audience','subject','repository','repository_id','repository_owner_id','environment',
    'event','runner','control_source','caller_source','ref','caller_workflow_sha','reusable_workflow_sha',
    'caller_workflow_ref','reusable_workflow_ref','run_id','run_attempt','attempt_bound')

def claims_before_sts(token,control_source,*,checkpoint=None):
    """Untrusted rejection only. Diagnostics emit fixed clause names, never JWT values."""
    def mark(name):
        need(name in CLAIM_CLAUSES,'Fixed OIDC clause required')
        if checkpoint is not None:checkpoint(name)
    mark('token_structure')
    need(type(token)is str and len(token)<=32768 and len(token.split('.'))==3,'Bounded GitHub OIDC token required')
    header,payload,_=token.split('.')
    unpack=lambda raw:decode(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)),32768)
    mark('header_decode');metadata=unpack(header)
    mark('payload_decode');claims=unpack(payload)
    mark('algorithm');need(metadata.get('alg')=='RS256','Expected GitHub token algorithm required')
    mark('key_identifier');need(type(metadata.get('kid'))is str,'Expected GitHub token key identifier required')
    checks=(('issuer','iss','https://token.actions.githubusercontent.com'),('audience','aud','sts.amazonaws.com'),
        ('subject','sub',SUBJECT),('repository','repository',REPOSITORY),('repository_id','repository_id',str(REPOSITORY_ID)),
        ('repository_owner_id','repository_owner_id',str(OWNER_ID)),('environment','environment',ENVIRONMENT),
        ('event','event_name','workflow_dispatch'),('runner','runner_environment','github-hosted'))
    for name,key,expected in checks:
        mark(name);need(claims.get(key)==expected,'Canonical controller OIDC claim differs')
    mark('control_source')
    need(type(control_source)is str and re.fullmatch('[0-9a-f]{40}',control_source),'Real reviewed controller commit required')
    source=claims.get('sha');mark('caller_source')
    need(type(source)is str and re.fullmatch('[0-9a-f]{40}',source),'Exact caller commit required')
    checks=(('ref','ref','refs/heads/main'),('caller_workflow_sha','workflow_sha',source),
        ('reusable_workflow_sha','job_workflow_sha',control_source),
        ('caller_workflow_ref','workflow_ref',REPOSITORY+'/'+CALLER+'@refs/heads/main'),
        ('reusable_workflow_ref','job_workflow_ref',REPOSITORY+'/'+WORKFLOW+'@'+control_source))
    for name,key,expected in checks:
        mark(name);need(claims.get(key)==expected,'Main caller or SHA-pinned reusable workflow differs')
    for name in('run_id','run_attempt'):
        mark(name);need(type(claims.get(name))is str and re.fullmatch('[1-9][0-9]{0,18}',claims[name]),'Exact workflow run identity required')
    mark('attempt_bound');need(int(claims['run_attempt'])<=100,'Bounded workflow attempt required')
    return {'source':control_source,'caller_source':source,'run_id':int(claims['run_id']),'attempt':int(claims['run_attempt']),
            'workflow':WORKFLOW,'caller':CALLER,'environment':ENVIRONMENT}


def audit_workflows(workflows,control_source,*,caller=True):
    """All workflow definitions from this actual immutable checkout are audited."""
    import yaml
    need(type(workflows) is dict and WORKFLOW in workflows and (not caller or CALLER in workflows),'Full immutable workflow closure required')
    found=[];calls=[];negative_calls=[]
    for name,raw in workflows.items():
        need(re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',name)
             and type(raw) is bytes and 0<len(raw)<=1048576,'Bounded workflow source required')
        value=yaml.load(raw,Loader=yaml.BaseLoader)
        need(type(value) is dict and type(value.get('jobs')) is dict,'Workflow must have auditable jobs')
        for job_id,job in value['jobs'].items():
            need(type(job) is dict,'Auditable fixed job definition required')
            environment=job.get('environment')
            if environment is not None:
                actual=environment.get('name') if type(environment) is dict else environment
                need(type(actual) is str and '${{' not in actual,'Dynamic environments prevent owner admission')
                if actual==ENVIRONMENT:found.append((name,job_id))
            uses=job.get('uses')
            if uses is not None:
                need(type(uses) is str and '${{' not in uses,'Dynamic reusable workflow prevents admission')
                if 'release-acceptance-run.yml' in uses:calls.append((name,job_id,uses))
                if 'release-owner-admission-negative.yml'in uses:negative_calls.append((name,job_id,uses))
    allowed=[(WORKFLOW,'acceptance')]
    if NEGATIVE_WORKFLOW in workflows:allowed.append((NEGATIVE_WORKFLOW,'deny'))
    need(sorted(found)==sorted(allowed),'Only designated owner job and immutable no-secret negative probe may reference owner environment')
    expected=REPOSITORY+'/'+WORKFLOW+'@'+control_source
    need(calls==([(CALLER,'verify',expected)] if caller else []),'Only designated caller may invoke exact SHA-pinned owner workflow')
    need(negative_calls==([(CALLER,'negative',REPOSITORY+'/'+NEGATIVE_WORKFLOW+'@'+control_source)]if caller and NEGATIVE_WORKFLOW in workflows else []),
         'Only designated no-secret probe caller may invoke exact negative workflow')
    caller_value=yaml.load(workflows[CALLER],Loader=yaml.BaseLoader) if caller else None
    producer=yaml.load(workflows[WORKFLOW],Loader=yaml.BaseLoader)
    need((not caller or set(caller_value.get('on',{}))=={'workflow_dispatch'}) and set(producer.get('on',{}))=={'workflow_call'},
         'Owner workflow may only execute through exact dispatched caller')
    if NEGATIVE_WORKFLOW in workflows:
        negative=yaml.load(workflows[NEGATIVE_WORKFLOW],Loader=yaml.BaseLoader)
        need(set(negative.get('on',{}))=={'workflow_call'} and set(negative['jobs'])=={'deny'},'Negative probe may only execute immutable deny job')
    return {name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(workflows.items())}


def workflows_at(api,source):
    """Read the exact commit tree and actual blob bytes, never a moving main ref."""
    prefix='repos/'+REPOSITORY+'/'
    commit=api(prefix+'git/commits/'+source)
    need(commit.get('sha')==source and re.fullmatch('[0-9a-f]{40}',commit.get('tree',{}).get('sha','')),'Exact workflow commit tree required')
    tree=api(prefix+'git/trees/'+commit['tree']['sha']+'?recursive=1')
    need(tree.get('truncated') is False and type(tree.get('tree')) is list and len(tree['tree'])<=20000,'Full source tree required')
    rows={}
    for row in tree['tree']:
        name=row.get('path','')
        if not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',name):continue
        need(row.get('type')=='blob' and row.get('mode')=='100644' and re.fullmatch('[0-9a-f]{40}',row.get('sha','')),'Regular immutable workflow blob required')
        blob=api(prefix+'git/blobs/'+row['sha'])
        need(blob.get('encoding')=='base64' and blob.get('sha')==row['sha'] and type(blob.get('size')) is int
             and 0<blob['size']<=1048576,'Bounded workflow blob required')
        data=base64.b64decode(blob['content'].replace('\n',''),validate=True)
        need(len(data)==blob['size'] and hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==row['sha'],'Actual Git workflow blob differs')
        rows[name]=data
    return rows


def admit(api,identity,workflows,checkout_source,caller_workflows):
    """api reads actual GitHub state. Never accept a caller-supplied admission receipt."""
    need(checkout_source==identity['source'],'Actual checkout differs from signed controller source')
    hashes=audit_workflows(workflows,identity['source'],caller=False)
    caller_hashes=audit_workflows(caller_workflows,identity['source'])
    prefix='repos/'+REPOSITORY+'/'
    repo=api(prefix)
    need(repo.get('id')==REPOSITORY_ID and repo.get('full_name')==REPOSITORY
         and repo.get('owner',{}).get('id')==OWNER_ID,'Canonical repository identity changed')
    environment=api(prefix+'environments/'+ENVIRONMENT)
    branch_policy=environment.get('deployment_branch_policy')
    need(branch_policy=={'protected_branches':False,'custom_branch_policies':True},'Owner environment must use exact main policy')
    branches=api(prefix+'environments/'+ENVIRONMENT+'/deployment-branch-policies?per_page=100')
    need(branches.get('total_count')==1 and type(branches.get('branch_policies')) is list
         and len(branches['branch_policies'])==1
         and branches['branch_policies'][0].get('name')=='main'
         and branches['branch_policies'][0].get('type')=='branch','Owner environment admits other refs')
    run=api(prefix+'actions/runs/'+str(identity['run_id'])+'/attempts/'+str(identity['attempt']))
    need(run.get('id')==identity['run_id'] and run.get('run_attempt')==identity['attempt']
         and run.get('event')=='workflow_dispatch' and run.get('head_sha')==identity['caller_source']
         and run.get('head_branch')=='main' and run.get('path')==CALLER
         and run.get('repository',{}).get('id')==REPOSITORY_ID
         and run.get('head_repository',{}).get('id')==REPOSITORY_ID
         and run.get('status')=='in_progress','Actual immutable controller run differs')
    return {'schema':1,'kind':'actual-immutable-owner-controller-admission','identity':identity,
            'workflow_hashes':hashes,'caller_workflow_hashes':caller_hashes,'owner_role':ROLE,'release_ready':False}


def trust_policy(control_source):
    need(type(control_source) is str and re.fullmatch('[0-9a-f]{40}',control_source),'Real reviewed control commit required')
    return {'Version':'2012-10-17','Statement':[{'Effect':'Allow',
        'Principal':{'Federated':'arn:aws:iam::436632189317:oidc-provider/token.actions.githubusercontent.com'},
        'Action':'sts:AssumeRoleWithWebIdentity','Condition':{'StringEquals':{
            'token.actions.githubusercontent.com:aud':'sts.amazonaws.com',
            'token.actions.githubusercontent.com:sub':SUBJECT,
            'token.actions.githubusercontent.com:repository_id':str(REPOSITORY_ID),
            'token.actions.githubusercontent.com:repository_owner_id':str(OWNER_ID),
            'token.actions.githubusercontent.com:repository':REPOSITORY,
            'token.actions.githubusercontent.com:ref':'refs/heads/main',
            'token.actions.githubusercontent.com:environment':ENVIRONMENT,
            'token.actions.githubusercontent.com:job_workflow_ref':REPOSITORY+'/'+WORKFLOW+'@'+control_source}}}]}
