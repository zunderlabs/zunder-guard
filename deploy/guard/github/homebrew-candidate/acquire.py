"""Public draft assets only. Exact hashes come from the verified candidate bank."""
import hashlib,json,os,platform,subprocess,sys
from pathlib import Path

def need(ok,message):
 if not ok:raise RuntimeError(message)

def route():
 systems={'Darwin':'darwin','Linux':'linux'};arches={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64'}
 need(platform.system()in systems and platform.machine()in arches,'Unsupported native runner')
 return systems[platform.system()]+'-'+arches[platform.machine()]

def verify(directory,candidate,selected):
 names=['SHA256SUMS','SHA256SUMS.sigstore.json','zunder-guard.rb','zunder-guard-v1.0.4.intoto.jsonl',selected]
 for name in names:
  p=directory/name;s=p.lstat();row=candidate['files'][name]
  need(p.is_file()and not p.is_symlink()and s.st_nlink==1 and s.st_size==row['bytes']
       and hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256'],'Exact verified public candidate bytes differ')
 return names

def main():
 need(len(sys.argv)==2,'One exact public artifact output path required')
 candidate=json.loads(Path(__file__).with_name('candidate.json').read_bytes())
 need(candidate['tag']=='v1.0.4'and candidate['source']=='ddb3ce0b86cdfd094cfffd60dd8ea8073f20d844'
      and candidate['manifest_sha256']=='59d94ded377d7834d7472c4ddede38154af8514a7cc76c27ac1c87db5305c09c','Fixed reviewed candidate required')
 output=Path(sys.argv[1]);need(output.is_dir()and not output.is_symlink(),'Owned downloaded artifact directory required')
 selected='zunder-guard-v1.0.4-'+route()+'.tar.gz'
 for name,row in candidate['files'].items():
  p=output/name;info=p.lstat()
  need(p.is_file()and not p.is_symlink()and info.st_uid==os.getuid()and info.st_nlink==1
       and info.st_size==row['bytes']and hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256'],
       'Exact original signed artifact subject differs')
 verify(output,candidate,selected)
 print(json.dumps({'schema':1,'kind':'exact-signed-build-artifact-acquisition','route':route(),
      'candidateSource':candidate['source'],'manifestSha256':candidate['manifest_sha256'],'privateInput':False},sort_keys=True))

if __name__=='__main__':
 try:main()
 except BaseException:sys.exit('Public candidate acquisition refused')
