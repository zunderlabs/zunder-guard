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
SUBJECT='repo:'+REPOSITORY+':environment:'+ENVIRONMENT


def claims_before_sts(token,control_source):
    """Untrusted decode for rejection only. STS must verify this exact JWT before SSM."""
    need(type(token) is str and len(token)<=32768 and len(token.split('.'))==3,'Bounded GitHub OIDC token required')
    header,payload,_=token.split('.')
    unpack=lambda raw:decode(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)),32768)
    metadata=unpack(header);claims=unpack(payload)
    need(metadata.get('alg')=='RS256' and type(metadata.get('kid')) is str,'Expected GitHub token algorithm required')
    need(claims.get('iss')=='https://token.actions.githubusercontent.com'
         and claims.get('aud')=='sts.amazonaws.com' and claims.get('sub')==SUBJECT,'Exact controller OIDC subject required')
    need(claims.get('repository')==REPOSITORY and claims.get('repository_id')==str(REPOSITORY_ID)
         and claims.get('repository_owner_id')==str(OWNER_ID) and claims.get('environment')==ENVIRONMENT
         and claims.get('event_name')=='workflow_dispatch' and claims.get('runner_environment')=='github-hosted',
         'Canonical hosted dispatched controller required')
    need(type(control_source) is str and re.fullmatch('[0-9a-f]{40}',control_source),'Real reviewed controller commit required')
    source=claims.get('sha')
    need(type(source) is str and re.fullmatch('[0-9a-f]{40}',source)
         and claims.get('ref')=='refs/heads/main' and claims.get('workflow_sha')==source
         and claims.get('job_workflow_sha')==control_source
         and claims.get('workflow_ref')==REPOSITORY+'/'+CALLER+'@refs/heads/main'
         and claims.get('job_workflow_ref')==REPOSITORY+'/'+WORKFLOW+'@'+control_source,
         'Main caller or SHA-pinned reusable workflow differs')
    for name in ('run_id','run_attempt'):
        need(type(claims.get(name)) is str and re.fullmatch('[1-9][0-9]{0,18}',claims[name]),'Exact workflow run identity required')
    need(int(claims['run_attempt'])<=100,'Bounded workflow attempt required')
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
