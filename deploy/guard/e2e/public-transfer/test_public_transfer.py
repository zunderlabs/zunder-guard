import hashlib, importlib.util, io, json, os, signal, tarfile, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name):
 spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py')); value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
b=module('transfer_bundle'); f=module('fetch_public_transfer')

class Transfer(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name).resolve()
  self.data=b'public fixture only'; self.row={'path':'nested/public.txt','bytes':len(self.data),'sha256':b.sha(self.data)}
  self.public=json.dumps({'schema':1,'files':[self.row]}).encode(); self.patch=patch.object(b,'PUBLIC_SHA',b.sha(self.public)); self.patch.start()
 def tearDown(self): self.patch.stop(); self.temp.cleanup()
 def archive(self,rows=None):
  target=self.root/'fixture.tar'
  with tarfile.open(target,'w',format=tarfile.USTAR_FORMAT) as tar:
   tar.addfile(b.header(b.MAP_NAME,len(self.public)),io.BytesIO(self.public))
   for info,data in rows if rows is not None else [(b.header(self.row['path'],len(self.data)),self.data)]: tar.addfile(info,io.BytesIO(data) if data is not None else None)
  return target
 def run_unpack(self,target): return b.unpack(target,self.root/'result',b.hash_file(target),target.stat().st_size,self.public)
 def test_roundtrip(self):
  result=self.run_unpack(self.archive()); self.assertFalse(result['release_acceptance']); self.assertEqual((self.root/'result'/self.row['path']).read_bytes(),self.data)
 def test_exact_sha_before_parsing(self):
  p=self.archive()
  with self.assertRaises(RuntimeError): b.unpack(p,self.root/'result','0'*64,p.stat().st_size,self.public)
  self.assertFalse((self.root/'result').exists())
 def test_symlink_archive(self):
  p=self.archive(); q=self.root/'link';q.symlink_to(p)
  with self.assertRaises(RuntimeError): self.run_unpack(q)
 def test_duplicate(self):
  info=b.header(self.row['path'],len(self.data));p=self.archive([(info,self.data),(info,self.data)])
  with self.assertRaises(RuntimeError): self.run_unpack(p)
 def test_tar_symlink(self):
  info=b.header(self.row['path'],0);info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd'
  with self.assertRaises(RuntimeError): self.run_unpack(self.archive([(info,None)]))
 def test_unknown_and_traversal(self):
  for name in ('unexpected','../outside'):
   with self.subTest(name=name):
    p=self.archive([(b.header(name,len(self.data)),self.data)])
    with self.assertRaises(RuntimeError): self.run_unpack(p)
    if (self.root/'result').exists(): (self.root/'result').rmdir()
 def test_subject_content(self):
  with self.assertRaises(RuntimeError): self.run_unpack(self.archive([(b.header(self.row['path'],len(self.data)),b'x'*len(self.data))]))
 def test_missing_subject(self):
  with self.assertRaises(RuntimeError): self.run_unpack(self.archive([]))
 def test_prefix_collision(self):
  with self.assertRaises(RuntimeError): b.file_rows({'schema':1,'files':[dict(self.row,path='a'),dict(self.row,path='a/b')]})
 def test_zero_bytes(self):
  self.row=dict(self.row,bytes=0,sha256=b.sha(b''));self.public=json.dumps({'schema':1,'files':[self.row]}).encode()
  with patch.object(b,'PUBLIC_SHA',b.sha(self.public)): self.assertEqual(self.run_unpack(self.archive([(b.header(self.row['path'],0),b'')]))['files'],1)
 def test_assemble_exact_explicit_subjects(self):
  source=self.root/'source';source.write_bytes(self.data)
  local=json.dumps({'schema':1,'files':[dict(self.row,source_path=str(source))]}).encode()
  (self.root/'local-input-map.json').write_bytes(local);(self.root/'public-file-map.json').write_bytes(self.public)
  with patch.object(b,'HERE',self.root),patch.object(b,'LOCAL_SHA',b.sha(local)):
   result=b.assemble(self.root/'fixture.tar'); self.assertEqual(result['files'],1)
   self.assertEqual(self.run_unpack(self.root/'fixture.tar')['files'],1)
 def test_source_hardlink_refusal(self):
  source=self.root/'source'; source.write_bytes(self.data); os.link(source,self.root/'second')
  with self.assertRaises(RuntimeError): b.pinned_source(dict(self.row,source_path=str(source)))

class Fetch(unittest.TestCase):
 def value(self):
  return {'schema':1,'repository':'zunderlabs/zunder-guard','tag':'public-runtime-transfer-20261009-r1',
          'release_id':123,'asset_id':456,'asset_name':'linux-public-transfer-20261009-r1.tar','bytes':10240,
          'sha256':'a'*64,'manifest_sha256':'b'*64,'source_commit':'c'*40,'draft':True,'public_subjects_only':True}
 def test_fixed_policy(self): self.assertEqual(f.policy(json.dumps(self.value())),self.value())
 def test_bound_policy_exact_digest(self):
  raw=(HERE/'actual-transfer-policy.json').read_bytes()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),f.POLICY_SHA)
  p=f.policy(raw)
  self.assertEqual(p['release_id'],408349093); self.assertEqual(p['asset_id'],626199359)
  self.assertEqual(p['bytes'],405309440)
  self.assertEqual(p['sha256'],'1ce0ce0755c090975cd4eb09e11b39de4e793d01ba15f706331d48ce130576bb')
 def test_wrong_fields(self):
  for key,value in [('repository','outside/owner'),('tag','v1.0.3'),('asset_name','another'),('draft',False),('release_id',True),('bytes',f.LIMIT+1)]:
   with self.subTest(key=key):
    p=self.value();p[key]=value
    with self.assertRaises(RuntimeError): f.policy(json.dumps(p))
 def test_blob_host_auth_boundary(self):
  valid='https://release-assets.githubusercontent.com/github-production-release-asset/123/data?sig=public'
  self.assertEqual(f.blob_url(valid),valid)
  for url in ('http://release-assets.githubusercontent.com/github-production-release-asset/a','https://evil.test/a','https://x@release-assets.githubusercontent.com/github-production-release-asset/a','https://release-assets.githubusercontent.com:444/github-production-release-asset/a','https://release-assets.githubusercontent.com/another/a'):
   with self.subTest(url=url):
    with self.assertRaises(RuntimeError):f.blob_url(url)
  self.assertNotIn('Authorization',f.request(valid,None,True).headers)
 def test_metadata_requires_owned_draft(self):
  p=self.value();a={'id':456,'name':p['asset_name'],'size':p['bytes'],'state':'uploaded','url':f.API+'/releases/assets/456','digest':'sha256:'+p['sha256']}
  r={'id':123,'draft':True,'tag_name':p['tag'],'target_commitish':p['source_commit'],'assets':[a]}
  f.metadata(r,a,p)
  for changed in ({'draft':False},{'target_commitish':'0'*40},{'assets':[]}):
   with self.assertRaises(RuntimeError):f.metadata(dict(r,**changed),a,p)
 def metadata_inputs(self):
  p=self.value();a={'id':456,'name':p['asset_name'],'size':p['bytes'],'state':'uploaded','url':f.API+'/releases/assets/456','digest':'sha256:'+p['sha256']}
  r={'id':123,'draft':True,'tag_name':p['tag'],'target_commitish':p['source_commit'],'assets':[a]}
  return r,a,p
 def test_reject_extra_and_duplicate_assets(self):
  r,a,p=self.metadata_inputs()
  for extra in (dict(a,id=789,name='unreviewed'),dict(a)):
   with self.subTest(extra=extra):
    with self.assertRaises(RuntimeError):f.metadata(dict(r,assets=[a,extra]),a,p)
 def test_sole_asset_metadata_consistent(self):
  r,a,p=self.metadata_inputs()
  for key,value in [('id',789),('name','unexpected'),('size',1),('state','new'),('url','https://evil.test/asset'),('digest','sha256:'+'0'*64)]:
   with self.subTest(key=key):
    with self.assertRaises(RuntimeError):f.metadata(dict(r,assets=[dict(a,**{key:value})]),a,p)
 def test_available_chunks_not_buffered_read(self):
  class Response:
   def __init__(self):self.blocks=iter([b'a',b'b',b''])
   def read(self,_size):raise AssertionError('Buffered read must not run')
   def read1(self,_size):return next(self.blocks)
  with f.Budget(1) as budget:self.assertEqual(b''.join(f.chunks(Response(),budget,2)),b'ab')
 def test_chunk_byte_limit(self):
  class Response:
   def read1(self,_size):return b'abc'
  with f.Budget(1) as budget:
   with self.assertRaises(RuntimeError):list(f.chunks(Response(),budget,2))
 def test_late_eof_refuses(self):
  class Response:
   def read1(self,_size):self.clock=2;return b''
  response=Response();response.clock=0
  with patch.object(f.time,'monotonic',lambda:response.clock):
   with f.Budget(1) as budget:
    with self.assertRaises(RuntimeError):list(f.chunks(response,budget,2))
 def test_trickle_deadline_never_renews(self):
  class Response:
   def read1(self,_size):self.clock+=0.4;return b'a'
  response=Response();response.clock=0
  with patch.object(f.time,'monotonic',lambda:response.clock):
   with f.Budget(1) as budget:
    with self.assertRaises(RuntimeError):list(f.chunks(response,budget,100))
    self.assertEqual(budget.deadline,1)
 def test_original_alarm_interrupts_blocking_read(self):
  class Response:
   def read1(self,_size):time.sleep(1);return b''
  previous=signal.getsignal(signal.SIGALRM);started=time.monotonic()
  with self.assertRaises(RuntimeError):
   with f.Budget(0.04) as budget:list(f.chunks(Response(),budget,2))
  self.assertLess(time.monotonic()-started,0.5)
  self.assertEqual(signal.getitimer(signal.ITIMER_REAL),(0.0,0.0))
  self.assertEqual(signal.getsignal(signal.SIGALRM),previous)
 def test_timeout_uses_remaining_original_budget(self):
  clock=[0]
  with patch.object(f.time,'monotonic',lambda:clock[0]):
   with f.Budget(30) as budget:
    self.assertEqual(budget.timeout(),15);clock[0]=28;self.assertEqual(budget.timeout(),2)
    clock[0]=30
    with self.assertRaises(RuntimeError):budget.timeout()
 def test_existing_alarm_refuses_without_overwrite(self):
  with patch.object(f.signal,'getitimer',return_value=(5.0,0.0)),patch.object(f.signal,'signal') as change:
   with self.assertRaises(RuntimeError):
    with f.Budget():self.fail('Existing watchdog must refuse')
   change.assert_not_called()

if __name__=='__main__': unittest.main()
