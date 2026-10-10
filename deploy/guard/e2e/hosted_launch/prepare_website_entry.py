#!/usr/bin/env python3
"""Fixed public pre-custody invoker. No saved admission or private authority."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler

if __package__ in (None,''):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from hosted_launch.contracts import ROOT,SOURCE,CHECKOUT,PUBLIC,canonical,decode,digest,need,sha
from hosted_launch.inventory import read,tree,write_new
from hosted_launch import prepare_website as recipe

WORKFLOW='.github/workflows/hosted-website-build-preparation.yml'
REPOSITORY='zunderlabs/zunder-guard'
RAW='deploy/guard/github/hosted-delivery/raw-admissions/'
PYTHON=ROOT/'runtime/python/bin/python3.12'
NODE=ROOT/'runtime/node/bin/node'
NPM=ROOT/'runtime/node/lib/node_modules/npm/bin/npm-cli.js'
RUSTUP=ROOT/'runtime/node/bin/rustup'
RUSTUP_URL='https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init'
RUSTUP_SHA='dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71'
RUSTUP_BYTES=21113232
CONTEXT={'GITHUB_REPOSITORY','GITHUB_REF','GITHUB_REF_TYPE','GITHUB_EVENT_NAME','GITHUB_SHA'}
BASE_ENV={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
_STAGES={'arguments','public-source','reader','raw-source','rustup','preparation','metadata'}
_STAGE='arguments'


def exact(value,keys):
    need(type(value)is dict and set(value)==set(keys),'Fixed preparation input refused');return value


def git(workspace,args,maximum=268435456):
    result=subprocess.run(['/usr/bin/git','-c','safe.directory='+str(workspace),'-C',str(workspace),*args],
        env=BASE_ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60)
    need(result.returncode==0 and len(result.stdout)<=maximum,'Public source refused');return result.stdout


def context(commit,env,*,reader=False):
    sha(commit,40)
    allowed=set(BASE_ENV)|CONTEXT|({'PRIVATE_ARTIFACT_READ_TOKEN','GITHUB_TOKEN'}if reader else set())
    need(set(env)<=allowed and all(env.get(k)==v for k,v in BASE_ENV.items()),'Preparation environment refused')
    need(env.get('GITHUB_REPOSITORY')==REPOSITORY and env.get('GITHUB_REF')=='refs/heads/main'
        and env.get('GITHUB_REF_TYPE')=='branch'and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and env.get('GITHUB_SHA')==commit,'Public main dispatch refused')
    if reader:need(all(type(env.get(k))is str and env[k]for k in('PRIVATE_ARTIFACT_READ_TOKEN','GITHUB_TOKEN')),'Reader grants absent')
    else:recipe.no_credentials(env)


def public_source(workspace,commit,identifier):
    sha(commit,40);need(re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',identifier or ''),'Admission ID refused')
    workspace=Path(workspace)
    need(workspace.is_absolute()and workspace.resolve(strict=True)==workspace,'Public workspace refused')
    need(git(workspace,['rev-parse','HEAD'],128).decode().strip()==commit and git(workspace,['status','--porcelain'],1048576)==b'',
        'Current clean public checkout required')
    report=decode(read(PUBLIC/'reports/preparation.json'))
    need(report.get('schema')==1 and type(report['schema'])is int and report.get('kind')=='actual-free-hosted-ordinary-preparation'
        and report.get('controlSource')==commit and all(report.get(k)is False for k in
        ('privateInput','providerRolesAssumed','venueOrders','nativeAcceptance','fullJourney','releaseReady')),'Original bootstrap refused')
    src=exact(report['source'],{'commit','archiveSha256','controllerRoot','genuineCheckout','gitDatabaseInSourceInventory'})
    need(src['commit']==commit and src['controllerRoot']==str(SOURCE)and src['genuineCheckout']==str(CHECKOUT)
        and src['gitDatabaseInSourceInventory']is False and digest(git(workspace,['archive','--format=tar',commit]))==src['archiveSha256']
        and git(CHECKOUT,['rev-parse','HEAD'],128).decode().strip()==commit,'Original bootstrap source differs')
    ref=exact(report['inventories']['source'],{'file','sha256'})
    need(ref['file']==str(PUBLIC/'reports/source-inventory.json'),'Original source inventory path refused')
    raw=read(Path(ref['file']));need(digest(raw)==ref['sha256'],'Original source inventory differs')
    source_map=decode(raw);need(source_map==tree(SOURCE),'Original copied source changed')
    # Root-maintained committed pin and source roster are independently joined
    # to the actual Git object and original bootstrap's protected source bytes.
    values=[]
    for suffix in('.json','.source.json'):
        name=RAW+identifier+suffix
        blob=git(workspace,['show',commit+':'+name],16*1024*1024)
        need(digest(blob)==source_map['files'].get(name)and read(SOURCE/name,16*1024*1024)==blob,'Committed source admission absent or changed')
        values.append((blob,decode(blob,16*1024*1024)))
    pin_raw,pin=values[0];_,roster=values[1]
    reader_path=SOURCE/'deploy/guard/github/hosted-delivery/raw_build_reader.py'
    spec=importlib.util.spec_from_file_location('fixed_raw_build_reader',reader_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.load_pin(pin,identifier)
    validate_roster(pin_raw,pin,roster,identifier)
    return pin,roster,report,module


def validate_roster(pin_raw,pin,roster,identifier):
    exact(roster,{'schema','id','rawAdmissionSha256','sourceCommit','sourceJsonSha256','sourceInventorySha256','sourceFiles','sourceBytes','candidateSha256'})
    need(type(roster['schema'])is int and roster['schema']==1 and roster['id']==identifier
        and roster['rawAdmissionSha256']==digest(pin_raw)and roster['sourceCommit']==pin['sourceCommit']
        and type(roster['sourceFiles'])is int and 0<roster['sourceFiles']<=12000
        and type(roster['sourceBytes'])is int and 0<roster['sourceBytes']<=768*1024*1024,'Committed source roster refused')
    for name in('sourceJsonSha256','sourceInventorySha256','candidateSha256'):sha(roster[name])


def read_raw(workspace,commit,identifier,env):
    global _STAGE
    _STAGE='public-source';context(commit,env,reader=True);pin,_,report,_=public_source(workspace,commit,identifier)
    need(os.geteuid()==0 and Path(sys.executable).resolve(strict=True)==PYTHON,'Managed root reader required')
    tools(report)
    _STAGE='reader'
    scoped={**BASE_ENV,**{k:env[k]for k in CONTEXT},
        **{k:env[k]for k in('PRIVATE_ARTIFACT_READ_TOKEN','GITHUB_TOKEN')}}
    # Original trusted CLI independently requires actual DELETE204 before inert
    # staging. No credential enters argv or a compilation child.
    try:
        result=subprocess.run([str(PYTHON),'-I','-B',str(SOURCE/'deploy/guard/github/hosted-delivery/raw_build_reader.py'),identifier],
            env=scoped,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=600)
    finally:scoped.clear()
    need(result.returncode==0 and 0<len(result.stdout)<=8192,'Raw reader refused')
    value=decode(result.stdout,8192)
    exact(value,{'schema','admission','purpose','sourceCommit','artifactId','artifactDigest','inventorySha256','manifestSha256',
        'tokenRevoked','stageReceiptSha256','privateInput','releaseReady'})
    need(type(value['schema'])is int and value['schema']==1 and value['admission']==identifier
        and value['purpose']==pin['purpose']and value['sourceCommit']==pin['sourceCommit']
        and value['artifactId']==pin['artifact']['id']and value['artifactDigest']==pin['artifact']['digest']
        and all(value[k]==pin[k]for k in('inventorySha256','manifestSha256'))
        and value['tokenRevoked']is True and value['privateInput']is False and value['releaseReady']is False,'Actual reader completion refused')
    sha(value['stageReceiptSha256'])
    write_new(PUBLIC/'reports/raw-reader.json',value)


def raw_source(pin,roster,identifier):
    result=decode(read(PUBLIC/'reports/raw-reader.json',8192))
    need(result.get('admission')==identifier and result.get('sourceCommit')==pin['sourceCommit']and result.get('tokenRevoked')is True
        and result.get('artifactId')==pin['artifact']['id']and result.get('artifactDigest')==pin['artifact']['digest']
        and all(result.get(k)==pin[k]for k in('inventorySha256','manifestSha256')),'Original reader result differs')
    ref={'file':str(recipe.INPUT/'stage-receipt.json'),'sha256':sha(result['stageReceiptSha256'])}
    receipt,inventory=recipe.stage_input(ref)
    need(all(receipt[k]==pin[k]for k in('purpose','privateRepository','sourceCommit','sourceRef','producer','artifact','inventorySha256','manifestSha256')),
        'Staged authenticated source differs')
    source_raw=recipe.ref_bytes(receipt['source']['manifest'])
    need(digest(source_raw)==roster['sourceJsonSha256']and digest(canonical(inventory))==roster['sourceInventorySha256']
        and len(inventory['files'])==roster['sourceFiles'],'Reviewed raw source inventory differs')
    total=0
    for name,h in inventory['files'].items():
        data=read(recipe.SOURCE/name,64*1024*1024);need(digest(data)==h,'Reviewed raw source bytes changed');total+=len(data)
    need(total==roster['sourceBytes']and receipt['candidate']['sha256']==roster['candidateSha256'],'Reviewed source/candidate differs')
    candidate=decode(recipe.ref_bytes(receipt['candidate']))
    need(candidate.get('published')is False,'Preparation candidate must remain draft')
    return ref


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*_):raise RuntimeError('Fixed vendor refused')


def rustup():
    need(not RUSTUP.exists()and not RUSTUP.is_symlink(),'Fresh fixed rustup required')
    # Parent ownership and immutability are checked before writing; never chmod
    # a bootstrap runtime ancestor or run a downloaded shell installer.
    for parent in RUSTUP.parents:
        info=parent.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'Protected vendor parent required')
    opener=build_opener(ProxyHandler({}),NoRedirect());end=time.monotonic()+90;parts=[];count=0
    with opener.open(Request(RUSTUP_URL,headers={'Accept-Encoding':'identity'}),timeout=15)as response:
        need(response.status==200 and response.geturl()==RUSTUP_URL,'Fixed vendor response refused')
        while True:
            need(time.monotonic()<end,'Fixed vendor deadline expired')
            part=response.read1(min(65536,RUSTUP_BYTES+1-count))
            if not part:break
            count+=len(part);need(count<=RUSTUP_BYTES,'Fixed vendor size refused');parts.append(part)
    raw=b''.join(parts)
    need(len(raw)==RUSTUP_BYTES and digest(raw)==RUSTUP_SHA and raw[:6]==b'\x7fELF\x02\x01'
        and raw[18:20]==b'\x3e\x00','Exact fixed AMD64 rustup bytes required')
    fd=os.open(RUSTUP,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
    with os.fdopen(fd,'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
    need(read(RUSTUP)==raw and RUSTUP.stat().st_mode&0o777==0o500,'Fixed vendor readback differs')
    return {'file':str(RUSTUP),'sha256':RUSTUP_SHA}


def tools(report):
    ref=report['inventories']['runtime'];need(ref['file']==str(PUBLIC/'reports/runtime-inventory.json'),'Bootstrap runtime path refused')
    raw=read(Path(ref['file']),16*1024*1024);need(digest(raw)==ref['sha256'],'Bootstrap runtime inventory differs')
    runtime=decode(raw,16*1024*1024);result={}
    for path in(PYTHON,NODE,NPM):
        expected=runtime['files'].get(str(path));sha(expected)
        need(digest(read(path,128*1024*1024))==expected,'Managed fixed tool differs')
    for name,path in(('node',NODE),('npm',NPM)):
        expected=runtime['files'].get(str(path));sha(expected)
        result[name]={'file':str(path),'sha256':expected}
    need(report['node']['version']=='26.8.1'and report['node']['archiveSha256']=='3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d',
        'Original fixed Node vendor differs')
    return result


def bounded_metadata(ref,identifier,commit):
    exact(ref,{'file','sha256'});need(ref['file']==str(recipe.INPUT/'preparation.json'),'Fixed preparation proof required')
    raw=read(Path(ref['file']),16*1024*1024);need(digest(raw)==sha(ref['sha256']),'Actual preparation proof changed')
    proof=decode(raw,16*1024*1024)
    need(proof['runtimeAdmitted']is False and proof['releaseReady']is False,'Preparation cannot admit runtime')
    sha(proof['sourceCommit'],40)
    values={}
    for kind in('website','tools'):
        raw=recipe.ref_bytes(proof[kind]['manifest']);value=decode(raw,16*1024*1024)
        values[kind]={'files':len(value['files']),'inventorySha256':digest(raw)}
    return {'schema':1,'kind':'public-website-preparation-metadata','status':'prepared','stage':'metadata','code':'none',
        'admission':identifier,'controlSource':commit,'sourceCommit':proof['sourceCommit'],
        'preparationSha256':ref['sha256'],'source':values['website'],'runtime':values['tools'],
        'runtimeAdmitted':False,'privateEpoch':False,'fullJourney':False,'releaseReady':False,
        'wholeHostCredentialAbsenceProven':False}


def invoke(workspace,commit,identifier,env):
    global _STAGE
    _STAGE='public-source';context(commit,env)
    need(os.geteuid()==0 and Path(sys.executable).resolve(strict=True)==PYTHON,'Managed root preparation required')
    pin,roster,report,_=public_source(workspace,commit,identifier)
    _STAGE='raw-source';stage_ref=raw_source(pin,roster,identifier);refs=tools(report)
    _STAGE='rustup';refs['rustup']=rustup()
    _STAGE='preparation';ref=recipe.prepare(stage_ref,refs)
    _STAGE='metadata';return bounded_metadata(ref,identifier,commit)


class FixedParser(argparse.ArgumentParser):
    def error(self,*_):raise RuntimeError('Fixed arguments refused')


def main():
    global _STAGE
    _STAGE='arguments'
    try:
        parser=FixedParser(add_help=False);parser.add_argument('--workspace',required=True);parser.add_argument('--control-source',required=True)
        parser.add_argument('--admission-id',required=True);parser.add_argument('--mode',choices=('validate','reader','prepare'),default='prepare');args=parser.parse_args()
        env=dict(os.environ)
        if args.mode=='reader':
            # sudo may add its fixed identity bookkeeping; never forward it.
            keep=set(BASE_ENV)|CONTEXT|{'PRIVATE_ARTIFACT_READ_TOKEN','GITHUB_TOKEN'}
            env={k:v for k,v in env.items()if k in keep};env.update(BASE_ENV)
            read_raw(args.workspace,args.control_source,args.admission_id,env);value={'schema':1,'status':'reader-complete','releaseReady':False}
        elif args.mode=='validate':
            _STAGE='public-source'
            context(args.control_source,env);public_source(args.workspace,args.control_source,args.admission_id)
            value={'schema':1,'status':'source-roster-validated','releaseReady':False}
        else:value=invoke(args.workspace,args.control_source,args.admission_id,env)
        raw=canonical(value);need(len(raw)<=4096,'Bounded preparation metadata required')
    except BaseException:
        value={'schema':1,'kind':'public-website-preparation-metadata','status':'held','stage':_STAGE if _STAGE in _STAGES else'arguments',
            'code':'fixed-stage-refused','runtimeAdmitted':False,'privateEpoch':False,'fullJourney':False,'releaseReady':False,
            'wholeHostCredentialAbsenceProven':False}
        print(canonical(value).decode());return 1
    print(raw.decode());return 0

if __name__=='__main__':raise SystemExit(main())
