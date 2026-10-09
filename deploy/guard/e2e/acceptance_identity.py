#!/usr/bin/env python3
"""Actual no-venue-secret OIDC/STS admission probes. No operation on import."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import subprocess
import time
from urllib.parse import urlparse,parse_qsl,urlencode,urlunparse
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from acceptance_admission import *
from native_epoch import private_diagnostics,ACCOUNT,REGION
from run_producers import write_new

PROBE_STAGES=('arguments','memory_preflight','checkout','oidc_request','positive_claims','control_workflows','caller_workflows','admission','negative_claims','sdk_initialization','sts_assumption','response_validation','receipt_write')
_current_stage='arguments'
_current_claim_clause='unknown'
_current_admission_clause='unknown'
_current_api_clause='unknown'
API_CLAUSES=('repository','environment','branch_policies','run_attempt','git_commit','git_tree','git_blob')
def stage(name):
    global _current_stage
    need(type(name)is str and name in PROBE_STAGES,'Fixed admission stage required');_current_stage=name

def claim_checkpoint(name):
    global _current_claim_clause
    need(type(name)is str and name in CLAIM_CLAUSES,'Fixed claim diagnostic required');_current_claim_clause=name

def admission_checkpoint(name):
    global _current_admission_clause
    need(type(name)is str and name in ADMISSION_CLAUSES,'Fixed admission diagnostic required');_current_admission_clause=name

def api_checkpoint(path):
    global _current_api_clause
    prefix='repos/'+REPOSITORY+'/'
    routes=((r'environments/'+ENVIRONMENT,'environment'),
        (r'environments/'+ENVIRONMENT+r'/deployment-branch-policies\?per_page=100','branch_policies'),
        (r'actions/runs/[1-9][0-9]{0,18}/attempts/[1-9][0-9]{0,2}','run_attempt'),
        (r'git/commits/[0-9a-f]{40}','git_commit'),(r'git/trees/[0-9a-f]{40}\?recursive=1','git_tree'),
        (r'git/blobs/[0-9a-f]{40}','git_blob'))
    _current_api_clause='unknown'
    need(type(path)is str,'Canonical GitHub admission API required')
    if path=='repos/'+REPOSITORY:
        _current_api_clause='repository';return
    need(path.startswith(prefix),'Canonical GitHub admission API required')
    match=[name for pattern,name in routes if re.fullmatch(pattern,path[len(prefix):])]
    need(len(match)==1,'Fixed GitHub admission API route required');_current_api_clause=match[0]

def safe_failure_message():
    value=_current_stage if type(_current_stage)is str and _current_stage in PROBE_STAGES else 'unknown'
    clause=_current_claim_clause if type(_current_claim_clause)is str and _current_claim_clause in CLAIM_CLAUSES else 'unknown'
    suffix=(' clause='+clause)if value=='positive_claims'else ''
    if value=='admission':
        current=_current_admission_clause if type(_current_admission_clause)is str and _current_admission_clause in ADMISSION_CLAUSES else 'unknown'
        suffix=' clause='+current
    if value in('control_workflows','caller_workflows','admission'):
        current=_current_api_clause if type(_current_api_clause)is str and _current_api_clause in API_CLAUSES else 'unknown'
        suffix+=' api='+current
    return 'Actual owner admission probe incomplete at stage='+value+suffix+'; no owner key was read.'

def no_swap():
    need(sys.platform=='linux' and Path('/proc/swaps').is_file()
         and len(Path('/proc/swaps').read_text().splitlines())==1,'Actual hosted Linux no-swap required')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));need(resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'Actual core-zero required')

def checkout_head():
    result=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
    need(result.returncode==0 and len(result.stdout)<=128,'Actual source checkout read failed')
    return result.stdout.decode().strip()

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*_):raise RuntimeError('Admission redirect refused')

def http_json(url,token,limit=1048576):
    opener=build_opener(ProxyHandler({}),NoRedirect())
    with opener.open(Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/json'}),timeout=15) as response:
        need(response.status==200,'Admission API request failed');raw=response.read(limit+1)
    return decode(raw,limit)

def oidc_token():
    url=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL','');bearer=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
    parsed=urlparse(url)
    need(parsed.scheme=='https' and parsed.hostname is not None and parsed.hostname.endswith('.actions.githubusercontent.com')
         and parsed.username is None and parsed.password is None and parsed.port in (None,443)
         and parsed.fragment=='' and bearer and len(bearer)<32768,'Actual GitHub OIDC request endpoint required')
    query=dict(parse_qsl(parsed.query));query['audience']='sts.amazonaws.com'
    value=http_json(urlunparse(parsed._replace(query=urlencode(query))),bearer,32768)
    need(type(value.get('value')) is str,'Actual OIDC token missing')
    return value['value']

def github_api(path):
    api_checkpoint(path)
    token=os.environ.get('GH_TOKEN','');need(token,'Actual workflow read token required')
    return http_json('https://api.github.com/'+path,token)

def probe(control_source,negative=False):
    stage('memory_preflight');no_swap();private_diagnostics()
    stage('checkout');checkout=checkout_head()
    need(checkout==control_source,'Actual probe checkout differs')
    stage('oidc_request');token=oidc_token()
    if not negative:
        stage('positive_claims');identity=claims_before_sts(token,control_source,checkpoint=claim_checkpoint)
        stage('control_workflows');control_workflows=workflows_at(github_api,control_source)
        stage('caller_workflows');caller_workflows=workflows_at(github_api,identity['caller_source'])
        stage('admission');admission=admit(github_api,identity,control_workflows,checkout,caller_workflows,checkpoint=admission_checkpoint)
    else:
        # The separate negative workflow receives a genuine correctly signed
        # token. Do not alter a JWT and confuse invalid signature with IAM denial.
        stage('negative_claims');parts=token.split('.');need(len(parts)==3,'Actual negative token missing')
        claims=decode(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)),32768)
        need(claims.get('repository_id')==str(REPOSITORY_ID) and claims.get('repository_owner_id')==str(OWNER_ID)
             and claims.get('ref')=='refs/heads/main' and claims.get('sub')==SUBJECT
             and claims.get('aud')=='sts.amazonaws.com' and claims.get('environment')==ENVIRONMENT
             and claims.get('job_workflow_ref')==REPOSITORY+'/.github/workflows/release-owner-admission-negative.yml@'+control_source,
             'Negative probe must change only the genuine reusable workflow identity')
        identity={'run_id':int(claims['run_id']),'attempt':int(claims['run_attempt']),'source':control_source}
        admission=None
    stage('sdk_initialization')
    from botocore import UNSIGNED
    from botocore.config import Config
    import boto3
    config=Config(region_name=REGION,retries={'total_max_attempts':1,'mode':'standard'},connect_timeout=10,read_timeout=15,
                  proxies={},signature_version=UNSIGNED)
    sts=boto3.session.Session().client('sts',region_name=REGION,endpoint_url='https://sts.'+REGION+'.amazonaws.com',config=config)
    private_diagnostics()
    stage('sts_assumption')
    try:
        reply=sts.assume_role_with_web_identity(RoleArn=ROLE,RoleSessionName='acceptance-'+str(identity['run_id'])+'-'+str(identity['attempt']),
            WebIdentityToken=token,DurationSeconds=900)
    except Exception as error:
        code=getattr(error,'response',{}).get('Error',{}).get('Code')
        need(negative and code=='AccessDenied','Actual STS probe did not meet expected policy outcome')
        return {'schema':1,'kind':'actual-owner-oidc-negative-probe','identity':identity,
                'policy_denied':True,'owner_parameter_read':False,'release_ready':False}
    finally:token=None
    # Successful negative assumption is a setup failure. No SSM/KMS call exists.
    stage('response_validation');credentials=reply.pop('Credentials',None)
    try:
        need(not negative and type(credentials) is dict and reply.get('SubjectFromWebIdentityToken')==SUBJECT
             and reply.get('Audience')=='sts.amazonaws.com','Owner role incorrectly admitted negative workflow')
        assumed=reply.get('AssumedRoleUser',{}).get('Arn','')
        need(assumed=='arn:aws:sts::'+ACCOUNT+':assumed-role/zunder-release-owner-controller/acceptance-'+str(identity['run_id'])+'-'+str(identity['attempt']),
             'Actual assumed controller identity differs')
        return {'schema':1,'kind':'actual-owner-oidc-positive-probe','admission':admission,
                'assumed_role':assumed,'owner_parameter_read':False,'release_ready':False}
    finally:
        if credentials:credentials.clear()
        reply.clear()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--control-source',required=True)
    p.add_argument('--negative',action='store_true');p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();need(re.fullmatch('[0-9a-f]{40}',args.control_source),'Actual reviewed source required')
    os.umask(0o077);need(args.output.is_absolute() and args.output.parent.is_dir() and not args.output.exists(),'Fresh private probe receipt required')
    receipt=probe(args.control_source,args.negative)
    stage('receipt_write');write_new(args.output,receipt)
def cli():
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    stage('arguments')
    try:main()
    except BaseException:print(safe_failure_message(),file=sys.stderr);return 1
    return 0

if __name__=='__main__':sys.exit(cli())
