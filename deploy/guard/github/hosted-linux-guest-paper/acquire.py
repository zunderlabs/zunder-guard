"""Exact original public signed subjects. No network, token or candidate execution."""
import hashlib,json,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
def need(ok,message):
    if not ok:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def regular(path,expected=None,limit=134217728):
    before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022 and before.st_size<=limit,'regular public input refused')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after),'public input changed')
    if expected:need(len(raw)==expected['bytes']and sha(raw)==expected['sha256'],'candidate subject differs')
    return raw
def candidate():
    row=json.loads(regular(HERE/'candidate.json'))
    need(row['tag']=='v1.0.5'and row['source']=='0f64fa0f822fb2e9fffc414883ca843bd4e992a7'and row['release_run']==38022247487 and row['manifest_sha256']=='029c13981f216cf297f1c539e968c6e6dbe001d61ee4ee1f6496fea993ac06ad','fixed candidate differs')
    need(1<=len(row['files'])<=32 and all(re.fullmatch(r'[A-Za-z0-9_.-]+',name)and name not in('.','..')for name in row['files']),'subject names refused')
    return row
def verify(directory):
    row=candidate()
    for name,expected in row['files'].items():regular(directory/name,expected)
    sums={}
    for line in (directory/'SHA256SUMS').read_text().splitlines():
        match=re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_.-]+)',line)
        need(match is not None and match[2]not in sums,'signed checksum shape refused');sums[match[2]]=match[1]
    need(set(sums)==set(row['provenance_subjects']),'all provenance subjects required')
    for name,digest in sums.items():need(row['files'][name]['sha256']==digest,'signed subject identity differs')
    return row
if __name__=='__main__':
    try:
        if sys.argv[1:]==['--subjects']:
            for name in candidate()['provenance_subjects']:print(name)
        else:
            need(len(sys.argv)==2,'one public artifact directory required');verify(Path(sys.argv[1]));print('All original signed subjects match pinned bytes.')
    except BaseException:raise SystemExit('Public candidate admission refused')
