#!/usr/bin/env python3
"""Offline transport/parser tests; never substitutes for cryptographic verification."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parent
def load(name):
    s=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
a=load('actions-artifacts');c=load('staged-subjects')
TAG='v1.0.1';SOURCE='a'*40


class Tests(unittest.TestCase):
    def run_value(self):
        return dict(id=42,run_attempt=2,head_sha=SOURCE,head_branch=TAG,event='push',path='.github/workflows/release.yml',status='completed',conclusion='success',repository={'id':a.REPO_ID},head_repository={'id':a.REPO_ID},run_started_at='2026-10-08T19:00:00Z',updated_at='2026-10-08T19:30:00Z')
    def artifact(self):
        return dict(name='dist',id=7,expired=False,size_in_bytes=100,digest='sha256:'+'b'*64,
          created_at='2026-10-08T19:20:00Z',updated_at='2026-10-08T19:20:00Z',workflow_run=dict(id=42,head_sha=SOURCE,head_branch=TAG,repository_id=a.REPO_ID,head_repository_id=a.REPO_ID))
    def job(self):
        return dict(name='package',id=9,run_id=42,run_attempt=2,status='completed',conclusion='success',started_at='2026-10-08T19:19:00Z',completed_at='2026-10-08T19:21:00Z')
    def binding(self,value=None,jobs=None):
        return a.artifact_binding(value or self.artifact(),name='dist',tag=TAG,source=SOURCE,run_id=42,
          window=a.run_binding(self.run_value(),TAG,SOURCE,42,2),jobs=[self.job()] if jobs is None else jobs,job_name='package',attempt=2)
    def test_exact_attempt_and_producing_job(self):self.assertEqual(self.binding(),9)
    def test_bad_run_scope_or_attempt(self):
        for name,value in [('id',41),('run_attempt',1),('head_sha','c'*40),('head_branch','v1.0.0'),('event','pull_request'),('status','in_progress'),('conclusion','failure'),('path','evil.yml'),('repository',{'id':1}),('head_repository',{'id':1})]:
            run=self.run_value();run[name]=value
            with self.subTest(name=name),self.assertRaises(RuntimeError):a.run_binding(run,TAG,SOURCE,42,2)
    def test_old_attempt_or_wrong_job_cannot_receive_credit(self):
        for name,value in [('run_attempt',1),('run_id',43),('name','evil'),('status','in_progress'),('conclusion','failure'),('started_at','2026-10-08T19:21:00Z'),('completed_at','2026-10-08T19:19:00Z')]:
            job=self.job();job[name]=value
            with self.subTest(name=name),self.assertRaises(RuntimeError):self.binding(jobs=[job])
        with self.assertRaises(RuntimeError):self.binding(jobs=[self.job(),self.job()])
    def test_invalid_or_changed_artifact_metadata(self):
        for name,value in [('name','dist2'),('id',True),('expired',True),('size_in_bytes',a.MAX_ZIP+1),('digest','bad'),('created_at','2026-10-08T18:00:00Z'),('updated_at','2026-10-08T19:20:01Z')]:
            artifact=self.artifact();artifact[name]=value
            with self.subTest(name=name),self.assertRaises(RuntimeError):self.binding(artifact)
        artifact=self.artifact();artifact['workflow_run']['head_sha']='0'*40
        with self.assertRaises(RuntimeError):self.binding(artifact)
    def zip_fixture(self,root,entries):
        path=root/'carrier.zip'
        with zipfile.ZipFile(path,'w') as archive:
            for name,data,mode,compression in entries:
                item=zipfile.ZipInfo(name);item.create_system=3;item.external_attr=mode<<16;item.compress_type=compression
                archive.writestr(item,data)
        return path
    def test_regular_flat_extraction(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root=Path(temp);out=root/'out';out.mkdir()
            path=self.zip_fixture(root,[('file.txt',b'public',0o100644,zipfile.ZIP_DEFLATED)])
            self.assertEqual(a.extract(path,out),['file.txt']);self.assertEqual((out/'file.txt').read_bytes(),b'public')
            self.assertEqual(stat.S_IMODE((out/'file.txt').stat().st_mode),0o600)
    def test_slip_symlink_special_directory_and_unsupported_compression_refused(self):
        for name,mode,compression in [('../escape',0o100644,0),('/escape',0o100644,0),('a/b',0o100644,0),('a..b',0o100644,0),('file',0o120777,0),('file',0o010600,0),('dir/',0o040700,0),('file',0o100644,zipfile.ZIP_BZIP2)]:
            with self.subTest(name=name,mode=mode),tempfile.TemporaryDirectory(dir=ROOT) as temp:
                root=Path(temp);out=root/'out';out.mkdir();path=self.zip_fixture(root,[(name,b'x',mode,compression)])
                with self.assertRaises(RuntimeError):a.extract(path,out)
                self.assertFalse(list(out.iterdir()))
    def test_case_duplicate_and_member_count_refused(self):
        for names in (['a','A'],[str(i) for i in range(65)]):
            with tempfile.TemporaryDirectory(dir=ROOT) as temp:
                root=Path(temp);out=root/'out';out.mkdir();path=self.zip_fixture(root,[(n,b'x',0o100644,0) for n in names])
                with self.assertRaises(RuntimeError):a.extract(path,out)
    def test_size_and_exact_provenance_bounds(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root=Path(temp);out=root/'out';out.mkdir();path=self.zip_fixture(root,[('file',b'abcd',0o100644,0)])
            with patch.object(a,'MAX_FILE',3),self.assertRaises(RuntimeError):a.extract(path,out)
            with patch.object(a,'MAX_TOTAL',3),self.assertRaises(RuntimeError):a.extract(path,out)
            with self.assertRaises(RuntimeError):a.extract(path,out,expected_names=['expected.jsonl'])
    def staged(self,root):
        staged=root/'staged';out=root/'out';staged.mkdir(mode=0o700);out.mkdir(mode=0o700)
        files={'file.txt':b'public','SHA256SUMS':(hashlib.sha256(b'public').hexdigest()+'  file.txt\n').encode(),'SHA256SUMS.sigstore.json':b'fixture bundle',f'zunder-guard-{TAG}.intoto.jsonl':b'fixture provenance'}
        for name,data in files.items():(staged/name).write_bytes(data);(staged/name).chmod(0o600)
        return staged,out
    def test_seed_and_subjects_do_not_create_verified_marker(self):
        with tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve())) as temp:
            staged,out=self.staged(Path(temp));c.copy('seed',staged,out,TAG);c.copy('subjects',staged,out,TAG)
            self.assertEqual({p.name for p in out.iterdir()},{p.name for p in staged.iterdir()})
            self.assertFalse((out/'.verified-release-source.json').exists())
    def test_staged_extra_symlink_hardlink_and_wrong_hash_refused(self):
        for mutation in ('extra','symlink','hardlink','hash'):
            with tempfile.TemporaryDirectory(dir=str(Path('/tmp').resolve())) as temp:
                staged,out=self.staged(Path(temp));file=staged/'file.txt'
                if mutation=='extra':(staged/'extra').write_text('extra')
                if mutation=='symlink':file.unlink();file.symlink_to('/etc/passwd')
                if mutation=='hardlink':os.link(file,Path(temp)/'other')
                if mutation=='hash':file.write_bytes(b'changed')
                with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):c.copy('subjects',staged,out,TAG)
    def test_crypto_core_is_still_mandatory(self):
        text=(ROOT/'verify-release-assets.sh').read_text()
        for command in ('cosign verify-blob','sha256sum -c SHA256SUMS','slsa-verifier verify-artifact','cosign verify "$REF"','slsa-verifier verify-image'):
            self.assertIn(command,text)
        self.assertLess(text.index('cosign verify-blob'),text.index('staged-subjects.py" subjects'))

    def test_source_ci_sigstore_checksum_slsa_and_oci_core_unchanged(self):
        text=(ROOT/'verify-release-assets.sh').read_text()
        core=(text[text.index('COMMIT=$(gh api'):text.index('mkdir -p "$OUT"')]
              +text[text.index('IDENTITY='):text.index('# Download only signed software subjects.')]
              +text[text.index('sha256sum -c SHA256SUMS'):])
        self.assertEqual(hashlib.sha256(core.encode()).hexdigest(),
                         'e53e8bb71122044f586b147479fbf83e9a940061a278b920a5a5fa98ef469b56')


if __name__=='__main__':os.umask(0o077);unittest.main()
