#!/usr/bin/env python3
"""Bounded authentic Actions transport. Signatures/provenance are verified separately."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import zipfile

REPO='zunderlabs/zunder-guard'
REPO_ID=1409357189
MAX_ZIP=128*1024*1024
MAX_FILE=128*1024*1024
MAX_TOTAL=256*1024*1024


def need(ok,message):
    if not ok:raise RuntimeError(message)


def timestamp(value):
    need(isinstance(value,str) and value.endswith('Z'),'Canonical UTC timestamp required.')
    return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()


def command(path):
    need(path.startswith('repos/'+REPO+'/actions/'),'Only canonical Actions transport permitted.')
    return ['/usr/bin/gh','api',path]


def stream(path, *, target=None, limit=2*1024*1024):
    environment=dict(PATH='/usr/bin:/bin',HOME=str(Path.home()),GH_TOKEN=os.environ['GH_TOKEN'],GH_PAGER='cat')
    child=subprocess.Popen(command(path),env=environment,stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True)
    total=0;digest=hashlib.sha256();body=bytearray();sink=None
    try:
        if target is not None:
            sink=target.open('xb');target.chmod(0o600)
        deadline=time.monotonic()+180
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            while selector.get_map():
                need(time.monotonic()<deadline,'Actions transport deadline.')
                for item,_ in selector.select(0.1):
                    block=os.read(item.fd,65536)
                    if not block:selector.unregister(item.fileobj);continue
                    total+=len(block);need(total<=limit,'Actions transport byte limit.')
                    digest.update(block)
                    if sink:sink.write(block)
                    else:body.extend(block)
        need(child.wait(timeout=max(0.01,deadline-time.monotonic()))==0,'Actions transport failed.')
        return (total,digest.hexdigest()) if sink else json.loads(body)
    finally:
        if sink:sink.close()
        if child.poll() is None:child.kill();child.wait(timeout=5)
        child.stdout.close()


def run_binding(run,tag,source,run_id,attempt):
    need(type(run_id) is int and run_id>0 and type(attempt) is int and attempt>0,'Run and attempt required.')
    need(run.get('id')==run_id and run.get('run_attempt')==attempt
         and run.get('head_sha')==source and run.get('head_branch')==tag
         and run.get('event')=='push' and run.get('path')=='.github/workflows/release.yml'
         and run.get('status')=='completed' and run.get('conclusion')=='success'
         and run.get('repository',{}).get('id')==REPO_ID
         and run.get('head_repository',{}).get('id')==REPO_ID,'Canonical successful release attempt differs.')
    return timestamp(run['run_started_at']),timestamp(run['updated_at'])


def artifact_binding(value, *, name, tag, source, run_id, window, jobs, job_name, attempt):
    need(value.get('name')==name and type(value.get('id')) is int and value['id']>0
         and value.get('expired') is False and type(value.get('size_in_bytes')) is int
         and 0<value['size_in_bytes']<=MAX_ZIP
         and re.fullmatch('sha256:[0-9a-f]{64}',value.get('digest','')),'Artifact metadata invalid.')
    scope=value.get('workflow_run',{})
    need(scope.get('id')==run_id and scope.get('head_sha')==source and scope.get('head_branch')==tag
         and scope.get('repository_id')==REPO_ID and scope.get('head_repository_id')==REPO_ID,'Artifact source/run scope differs.')
    created=timestamp(value['created_at']);updated=timestamp(value['updated_at'])
    need(window[0]<=created==updated<=window[1],'Artifact outside exact attempt window.')
    matched=[j for j in jobs if j.get('name')==job_name]
    need(len(matched)==1,'Exact artifact-producing job required.')
    job=matched[0]
    need(job.get('run_attempt')==attempt and job.get('run_id')==run_id
         and job.get('status')=='completed' and job.get('conclusion')=='success'
         and timestamp(job['started_at'])<=created<=timestamp(job['completed_at']),
         'Artifact not created by the selected successful attempt job.')
    return job['id']


def extract(path,destination, *, expected_names=None,max_total=MAX_TOTAL,max_members=64):
    names=[];total=0
    with zipfile.ZipFile(path) as archive:
        entries=archive.infolist();need(0<len(entries)<=min(64,max_members),'Artifact file count limit.')
        for item in entries:
            mode=item.external_attr>>16
            need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*',item.filename) and '..' not in item.filename
                 and item.filename.casefold() not in {n.casefold() for n in names}
                 and not item.is_dir() and item.create_system==3 and stat.S_ISREG(mode)
                 and not item.flag_bits&1 and item.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
                 and 0<item.file_size<=MAX_FILE,'Unsafe artifact member.')
            names.append(item.filename);total+=item.file_size
            need(total<=min(MAX_TOTAL,max_total),'Artifact expanded byte limit.')
        if expected_names is not None:need(set(names)==set(expected_names),'Unexpected provenance members.')
        for item in entries:
            target=destination/item.filename
            with archive.open(item) as source,target.open('xb') as out:
                target.chmod(0o600);written=0
                while block:=source.read(65536):
                    written+=len(block);need(written<=item.file_size,'Artifact size mismatch.');out.write(block)
                need(written==item.file_size,'Truncated artifact member.')
    return names


def stage(tag,source,run_id,attempt,output,receipt):
    need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag) and re.fullmatch('[0-9a-f]{40}',source), 'Release binding required.')
    need(output.is_absolute() and not output.exists() and receipt.is_absolute() and not receipt.exists(),'Fresh Actions staging paths required.')
    run=stream(f'repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}')
    window=run_binding(run,tag,source,run_id,attempt)
    listing=stream(f'repos/{REPO}/actions/runs/{run_id}/artifacts?per_page=100')
    jobs_listing=stream(f'repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    need(type(listing.get('total_count')) is int and listing['total_count']==len(listing['artifacts'])<=100
         and type(jobs_listing.get('total_count')) is int
         and jobs_listing['total_count']==len(jobs_listing['jobs'])<=100,'Actions inventory incomplete or oversized.')
    output.mkdir(mode=0o700);carrier=output.parent/'actions-carriers';carrier.mkdir(mode=0o700)
    selected=[];expanded=0;members=0
    for name,job_name in [('dist','package'),(f'zunder-guard-{tag}.intoto.jsonl','provenance / generator')]:
        matches=[a for a in listing['artifacts'] if a.get('name')==name]
        need(len(matches)==1,'Unique exact Actions artifact required.')
        value=matches[0]
        job_id=artifact_binding(value,name=name,tag=tag,source=source,run_id=run_id,window=window,
                                jobs=jobs_listing['jobs'],job_name=job_name,attempt=attempt)
        archive=carrier/(str(value['id'])+'.zip')
        count,digest=stream(f'repos/{REPO}/actions/artifacts/{value["id"]}/zip',target=archive,limit=MAX_ZIP)
        need(count==value['size_in_bytes'] and 'sha256:'+digest==value['digest'],'Actual downloaded ZIP differs from GitHub digest/size.')
        names=extract(archive,output,expected_names=None if name=='dist' else [name],
                      max_total=MAX_TOTAL-expanded,max_members=64-members)
        expanded+=sum((output/name).stat().st_size for name in names);members+=len(names)
        selected.append(dict(id=value['id'],name=name,job_id=job_id,zip_sha256=digest,bytes=count,files=names))
    # Timestamp and source are re-read after downloads; a concurrent rerun cannot silently change scope.
    run_binding(stream(f'repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}'),tag,source,run_id,attempt)
    run_binding(stream(f'repos/{REPO}/actions/runs/{run_id}'),tag,source,run_id,attempt)
    report=dict(schema=1,kind='authenticated-actions-release-transport',tag=tag,source=source,run_id=run_id,
                run_attempt=attempt,artifacts=selected,cryptographic_release_verification=False)
    with receipt.open('x') as out:json.dump(report,out,indent=2);out.write('\n')
    receipt.chmod(0o600)
    return report
