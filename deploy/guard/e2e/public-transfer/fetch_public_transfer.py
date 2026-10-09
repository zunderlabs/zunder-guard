#!/usr/bin/env python3
"""Fixed GitHub draft asset read using only the job's standard platform token."""
import hashlib, json, os, re, signal, ssl, stat, threading, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
POLICY_SHA = '2c5097b0b8aeaf536e735ca8b8d930b852817716b69868b79a6af6e8d5c8d1af'
HERE = Path(__file__).resolve().parent
API = 'https://api.github.com/repos/zunderlabs/zunder-guard'
LIMIT = 512 * 1024 * 1024
KEYS = {'schema','repository','tag','release_id','asset_id','asset_name','bytes','sha256',
        'manifest_sha256','source_commit','draft','public_subjects_only'}


def need(value):
    if not value: raise RuntimeError('Fixed public asset refused')


def policy(raw):
    value=json.loads(raw)
    need(type(value) is dict and set(value)==KEYS and value['schema']==1
         and value['repository']=='zunderlabs/zunder-guard'
         and value['tag']=='public-runtime-transfer-20261009-r1'
         and value['asset_name']=='linux-public-transfer-20261009-r1.tar'
         and value['draft'] is True and value['public_subjects_only'] is True)
    for k in ('release_id','asset_id','bytes'):
        need(type(value[k]) is int and value[k]>0)
    need(value['bytes']<=LIMIT)
    for k in ('sha256','manifest_sha256'): need(re.fullmatch('[0-9a-f]{64}',value[k]) is not None)
    need(re.fullmatch('[0-9a-f]{40}',value['source_commit']) is not None)
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def opener():
    # Explicit empty proxy map excludes ambient proxy credentials and arbitrary destinations.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
                                       urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def request(url, token, binary=False):
    headers={'Accept':'application/octet-stream' if binary else 'application/vnd.github+json',
             'User-Agent':'zunder-public-runtime-transfer','X-GitHub-Api-Version':'2022-11-28'}
    if token is not None: headers['Authorization']='Bearer '+token
    return urllib.request.Request(url,headers=headers)


class Budget:
    """One original monotonic budget plus an independent blocking-call alarm."""
    def __init__(self,seconds=180):
        self.seconds=seconds
    def check(self): need(time.monotonic()<self.deadline)
    def timeout(self):
        self.check(); return min(15,self.deadline-time.monotonic())
    def __enter__(self):
        need(threading.current_thread() is threading.main_thread()
             and signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0) and self.seconds>0)
        self.deadline=time.monotonic()+self.seconds
        self.previous=signal.getsignal(signal.SIGALRM)
        def expired(_signum,_frame): raise RuntimeError('Fixed public transfer budget expired')
        signal.signal(signal.SIGALRM,expired)
        signal.setitimer(signal.ITIMER_REAL,self.seconds)
        return self
    def __exit__(self,_type,_value,_traceback):
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,self.previous)


def chunks(response,budget,limit):
    total=0
    while True:
        budget.check()
        # HTTPResponse.read1 returns one available chunk; the independent alarm
        # also interrupts header/SSL/socket operations trickling within timeout.
        raw=response.read1(min(65536,limit-total+1))
        budget.check(); need(type(raw) is bytes)
        if not raw: return
        total+=len(raw); need(total<=limit)
        yield raw


def json_read(client,url,token,budget):
    budget.check()
    with client.open(request(url,token),timeout=budget.timeout()) as result:
        budget.check(); need(result.status==200)
        raw=b''.join(chunks(result,budget,1024*1024))
    budget.check(); value=json.loads(raw); budget.check(); return value


def metadata(release,asset,p):
    need(release['id']==p['release_id'] and release['draft'] is True
         and release['tag_name']==p['tag'] and release['target_commitish']==p['source_commit'])
    need(asset['id']==p['asset_id'] and asset['name']==p['asset_name'] and asset['size']==p['bytes']
         and asset['state']=='uploaded' and asset['url']==API+'/releases/assets/'+str(p['asset_id']))
    need(type(release['assets']) is list and len(release['assets'])==1)
    sole=release['assets'][0]
    need(sole['id']==p['asset_id'] and sole['name']==p['asset_name'] and sole['size']==p['bytes']
         and sole['state']=='uploaded' and sole['url']==asset['url']
         and sole.get('digest')==asset.get('digest'))
    if asset.get('digest') is not None: need(asset['digest']=='sha256:'+p['sha256'])


def blob_url(url):
    u=urllib.parse.urlsplit(url)
    need(u.scheme=='https' and u.hostname=='release-assets.githubusercontent.com'
         and u.port in (None,443) and u.username is None and u.password is None
         and u.path.startswith('/github-production-release-asset/') and not u.fragment)
    return url


def fetch(p,token,target):
    need(not target.exists() and not target.is_symlink())
    with Budget() as budget:
        client=opener()
        release=json_read(client,API+'/releases/'+str(p['release_id']),token,budget)
        asset=json_read(client,API+'/releases/assets/'+str(p['asset_id']),token,budget)
        metadata(release,asset,p); budget.check()
        try:
            response=client.open(request(asset['url'],token,True),timeout=budget.timeout())
        except urllib.error.HTTPError as error:
            budget.check(); need(error.code==302 and error.headers.get('Location') is not None)
            url=blob_url(error.headers['Location']); error.close()
            # Never forward GitHub Authorization to the signed blob URL.
            response=client.open(request(url,None,True),timeout=budget.timeout())
        with response:
            budget.check(); need(response.status==200)
            if response.headers.get('Content-Length') is not None:
                need(int(response.headers['Content-Length'])==p['bytes'])
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            count=0; h=hashlib.sha256()
            with os.fdopen(fd,'wb') as output:
                for block in chunks(response,budget,p['bytes']):
                    count+=len(block); h.update(block); output.write(block)
                budget.check(); need(count==p['bytes'] and h.hexdigest()==p['sha256'])
                output.flush(); os.fsync(output.fileno()); budget.check()
        need(stat.S_ISREG(target.lstat().st_mode) and target.lstat().st_nlink==1); budget.check()
        return {'schema':1,'kind':'actual-fixed-github-draft-public-transfer','release_id':p['release_id'],
                'asset_id':p['asset_id'],'bytes':count,'sha256':h.hexdigest(),'manifest_sha256':p['manifest_sha256'],
                'platform_token_used':True,'user_aws_credentials':False,'venue_credentials':False,
                'runtime_execution':False,'package_installation':False,'release_acceptance':False}


def main():
    need(os.geteuid()!=0 and POLICY_SHA is not None)
    raw=(HERE/'actual-transfer-policy.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest()==POLICY_SHA); p=policy(raw)
    token=os.environ.pop('GITHUB_TOKEN',None)
    need(type(token) is str and 10<=len(token)<=4096 and '\n' not in token and '\r' not in token)
    print(json.dumps(fetch(p,token,HERE/p['asset_name']),sort_keys=True))


if __name__=='__main__':
    try: main()
    except BaseException:
        print('Fixed GitHub public transfer incomplete; retain original output for reconciliation')
        raise SystemExit(2)
