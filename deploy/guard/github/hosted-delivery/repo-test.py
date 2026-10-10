#!/usr/bin/env python3
"""Inert controller regression tests. No GitHub/cloud calls or payload execution."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repo_control', HERE / 'repo-control.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, data, mode, kind in entries:
            item = tarfile.TarInfo(name)
            item.mode, item.type = mode, kind
            if kind == tarfile.REGTYPE:
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
            else:
                archive.addfile(item)
    return output.getvalue()


def snapshot_entries():
    return [('Cargo.toml', b'[workspace.package]\nversion="1.0.4"\n', 0o644, tarfile.REGTYPE)] + [
        (name, b'public product text\n', 0o644, tarfile.REGTYPE)
        for name in ['Cargo.lock', 'LICENSE', 'NOTICE', 'README.md', 'THIRD_PARTY_LICENSES.md']]


class HandoffTests(unittest.TestCase):
    def test_regular_snapshot_preserves_executable_without_execution(self):
        entries = snapshot_entries() + [('install.sh', b'echo inert\n', 0o755, tarfile.REGTYPE)]
        with tempfile.TemporaryDirectory() as tmp:
            result = m.unpack_snapshot(tar_bytes(entries), Path(tmp) / 'tree')
            self.assertTrue((result / 'install.sh').stat().st_mode & 0o100)

    def test_archive_path_link_duplicate_setid_refused(self):
        cases = [('.. /x', tarfile.SYMTYPE, 0o644), ('../escape', tarfile.REGTYPE, 0o644),
                 ('.git/config', tarfile.REGTYPE, 0o644), ('file', tarfile.SYMTYPE, 0o644),
                 ('file', tarfile.FIFOTYPE, 0o644), ('file', tarfile.REGTYPE, 0o4755),
                 ('README.md', tarfile.REGTYPE, 0o644)]
        for name, kind, mode in cases:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    m.unpack_snapshot(tar_bytes(snapshot_entries() + [(name, b'inert', mode, kind)]), Path(tmp) / 'tree')

    def test_missing_licence_closure_and_private_crate_refused(self):
        for entries in [snapshot_entries()[:-1], snapshot_entries() + [('Cargo.lock', b'name = "zunder-engine"\n', 0o644, tarfile.REGTYPE)]]:
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                m.unpack_snapshot(tar_bytes(entries), Path(tmp) / 'tree')

    def test_scan_matches_existing_export_policy_when_private_source_available(self):
        original = HERE.parents[1] / 'export' / 'export.py'
        if not original.is_file():
            self.skipTest('Original private policy absent from public controller; frozen equivalence proved before export')
        spec = importlib.util.spec_from_file_location('original_policy', original)
        source = importlib.util.module_from_spec(spec); spec.loader.exec_module(source)
        for name in ['SECRET_PATTERNS', 'DEVELOPMENT_PATTERNS', 'WARN_PATTERNS']:
            self.assertEqual([(a,b.pattern,b.flags) for a,b in getattr(source,name)],
                             [(a,b.pattern,b.flags) for a,b in getattr(m.scanner,name)])
        self.assertEqual(source.PUBLIC_FILE_HEX, m.scanner.PUBLIC_FILE_HEX)
        self.assertEqual(source.PUBLIC_CRATES, m.scanner.PUBLIC_CRATES)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'example.txt').write_text('Product text\n')
            self.assertEqual(source.scan(root), m.scanner.scan(root))

    def test_schema_copy_matches_website_source_when_present(self):
        original=HERE.parents[3]/'web/release-pin.ts'
        if not original.is_file():
            self.skipTest('Private website schema not present in public repository')
        self.assertEqual(original.read_bytes(),(HERE/'repo-release-schema.ts').read_bytes())

    def test_exact_ci_refuses_skipped_steps_rerun_stale_source_and_blob(self):
        ci={'workflowId':7,'workflowPath':'.github/workflows/ci.yml','workflowBlob':'b'*40,'runId':12,'runAttempt':2,'jobName':'fmt · clippy · test · deny'}
        value={'admission':{'sourceCommit':'a'*40,'privateRepository':{'id':123,'fullName':m.PRIVATE}},'sourceCi':ci}
        run={'id':12,'run_attempt':2,'repository':{'id':123,'full_name':m.PRIVATE},'head_repository':{'id':123},
             'head_sha':'a'*40,'head_branch':'main','path':ci['workflowPath'],'workflow_id':7,'event':'push','status':'completed','conclusion':'success'}
        job={'name':ci['jobName'],'status':'completed','conclusion':'success','steps':[{'name':name,'status':'completed','conclusion':'success'} for name in ['fmt','clippy','test','deny']]}
        class Reader:
            def __init__(self,change):self.change=change
            def read(self,endpoint):
                if '/actions/workflows/' in endpoint:return {'id':7,'path':ci['workflowPath'],'state':'active'}
                if '/contents/' in endpoint:return {'type':'file','sha':self.change.get('blob','b'*40)}
                if endpoint.endswith('/jobs?per_page=100'):
                    altered=copy.deepcopy(job)
                    if self.change.get('skip'):altered['steps'][-1]['conclusion']='skipped'
                    return {'total_count':1,'jobs':[altered]}
                if endpoint.endswith('/commits/main'):return {'sha':self.change.get('main','a'*40)}
                return dict(run,**self.change.get('run',{}))
        m.source_ci(value,Reader({}))
        for change in [{'blob':'f'*40},{'main':'f'*40},{'skip':True},{'run':{'run_attempt':3}},{'run':{'event':'workflow_dispatch'}},{'run':{'conclusion':'failure'}}]:
            with self.subTest(change=change),self.assertRaises(ValueError):m.source_ci(value,Reader(change))

    def test_source_record_requires_complete_ci_not_dispatch_claim(self):
        with self.assertRaises(ValueError):
            m.record({'schema':1,'id':'one','mode':'source','version':'1.0.4','admission':{}},'one')

    def test_writer_refuses_other_repos_and_main_force_operations(self):
        with self.assertRaises(ValueError): m.Writer('inert','other/repo')
        writer = m.Writer('inert',m.PRIVATE)
        with self.assertRaises(ValueError): writer.request('PATCH','/repos/'+m.PRIVATE+'/git/refs/heads/main',{})
        with self.assertRaises(ValueError): writer.request('POST','/repos/'+m.PUBLIC+'/pulls',{})

    def test_private_pin_never_imported_and_special_pin_refused(self):
        class Reader:
            def read(self, endpoint):
                return {'truncated':False,'tree':[{'path':m.PIN_PATH,'mode':'120000','type':'blob','sha':'a'*40}]}
        with self.assertRaises(ValueError): m.read_pin(Reader(),'a'*40)
        self.assertNotIn('import(', (HERE/'repo-compare-pin.ts').read_text())
        self.assertIn("'./repo-release-schema.ts'", (HERE/'repo-compare-pin.ts').read_text())

    def test_pin_downgrade_identity_channel_and_unpublished_transition(self):
        # Real public TS schema and comparison run against inert JSON, not mocked checks.
        code = (HERE/'repo-release-schema.ts').read_text()
        self.assertIn('export function parseReleasePin',code)
        version='1.0.4'; base='https://github.com/'+m.PUBLIC; url=base+'/releases/download/v'+version
        pin={'schema':1,'version':version,'sourceCommit':'a'*40,'published':True,'publishedAt':'2026-10-10T00:00:00Z','releaseId':7,
             'releaseUrl':base+'/releases/tag/v'+version,'assetsUrl':url,
             'signedAssetManifest':{'url':url+'/SHA256SUMS','sha256':'b'*64,'sigstoreBundleUrl':url+'/SHA256SUMS.sigstore.json','provenanceUrl':url+'/zunder-guard-v'+version+'.intoto.jsonl'},
             'image':{'reference':'ghcr.io/'+m.PUBLIC+'@sha256:'+'c'*64,'descriptorAsset':'zunder-guard-v'+version+'.image.txt'},
             'assets':{'zunder-guard-v'+version+'.image.txt':{'url':url+'/zunder-guard-v'+version+'.image.txt','sha256':'d'*64},'i':{'url':url+'/i','sha256':'e'*64}},
             'channels':{'unixInstallerUrl':'https://zunderlabs.com/i','windowsInstallerUrl':None,'awsTemplateUrl':None,'homebrewReady':False}}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); previous=root/'old.json'; nxt=root/'next.json'; previous.write_text(json.dumps(pin))
            def check(value):
                nxt.write_text(json.dumps(value))
                return subprocess.run(['node',str(HERE/'repo-compare-pin.ts'),str(nxt),str(previous)],capture_output=True,check=False).returncode
            self.assertEqual(check(pin),0)
            for change in [{'sourceCommit':'f'*40},{'releaseId':8},{'channels':dict(pin['channels'],unixInstallerUrl=None)}]:
                self.assertNotEqual(check(dict(pin,**change)),0)
            newer=copy.deepcopy(pin)
            old=json.dumps(pin).replace('1.0.4','1.0.3');previous.write_text(old)
            self.assertEqual(check(newer),0)
            previous.write_text(json.dumps(pin));older=json.loads(old)
            self.assertNotEqual(check(older),0)

    def test_publish_changes_only_site_data_and_never_updates_main(self):
        data=b'{"inert":true}\n'; digest=m.git_blob(data); base='a'*40
        class Writer:
            repository=m.PRIVATE
            def __init__(self): self.calls=[]
            def request(self,method,endpoint,value=None):
                self.calls.append((method,endpoint,value))
                if '/matching-refs/' in endpoint:return []
                if method=='GET' and '/git/commits/' in endpoint:return {'tree':{'sha':'b'*40}}
                if method=='GET' and '/git/trees/' in endpoint:return {'truncated':False,'tree':[{'path':'unchanged-private-code.ts','type':'blob','mode':'100644','sha':'c'*40}]}
                if endpoint.endswith('/git/blobs'):return {'sha':digest}
                if endpoint.endswith('/git/trees'):return {'sha':'d'*40}
                if endpoint.endswith('/git/commits'):return {'sha':'e'*40}
                if endpoint.endswith('/commits/main'):return {'sha':base}
                if endpoint.endswith('/git/refs'):return {'ref':value['ref']}
                if endpoint.endswith('/pulls'):return {'number':1}
                raise AssertionError(endpoint)
        writer=Writer()
        result=m.publish_tree(writer,{m.PIN_PATH:(data,'100644')},base,'guard/site-'+base+'-1.0.4-abcdef123456','inert','inert')
        self.assertEqual(result,{'prNumber':1,'created':True})
        edits=next(value['tree'] for method,endpoint,value in writer.calls if method=='POST' and endpoint.endswith('/git/trees'))
        self.assertEqual([x['path'] for x in edits],[m.PIN_PATH])
        self.assertTrue(all(method in {'GET','POST'} for method,_,_ in writer.calls))
        refs=next(value['ref'] for method,endpoint,value in writer.calls if method=='POST' and endpoint.endswith('/git/refs'))
        self.assertTrue(refs.startswith('refs/heads/guard/site-'))

    def test_existing_modified_or_closed_proposal_fails_before_reads_or_writes(self):
        branch='guard/site-'+'a'*40+'-1.0.4'
        for state,head in [('open','f'*40),('closed','a'*40),('closed','f'*40)]:
            class Writer:
                repository=m.PRIVATE
                def __init__(self):self.calls=[]
                def request(self,method,endpoint,value=None):
                    self.calls.append((method,endpoint,value))
                    if '/matching-refs/' in endpoint:
                        return [{'ref':'refs/heads/'+branch,'object':{'sha':head}}]
                    if '/pulls?' in endpoint:
                        return [{'number':99,'state':state,'head':{'sha':head},'base':{'ref':'other-base'}}]
                    raise AssertionError('No destination state may be accepted after existing branch: '+endpoint)
            writer=Writer()
            with self.subTest(state=state,head=head),self.assertRaisesRegex(ValueError,'explicit.*reconciliation'):
                m.publish_tree(writer,{m.PIN_PATH:(b'inert','100644')},'a'*40,branch,'inert','inert')
            self.assertEqual(len(writer.calls),1)
            self.assertEqual(writer.calls[0][0],'GET')

    def test_main_race_stops_before_branch_creation(self):
        class Writer:
            repository=m.PRIVATE
            def __init__(self):self.writes=[]
            def request(self,method,endpoint,value=None):
                if method=='POST':self.writes.append(endpoint)
                if '/matching-refs/' in endpoint:return []
                if '/git/commits/' in endpoint and method=='GET':return {'tree':{'sha':'b'*40}}
                if '/git/trees/' in endpoint and method=='GET':return {'truncated':False,'tree':[]}
                if endpoint.endswith('/git/blobs'):return {'sha':m.git_blob(b'x')}
                if endpoint.endswith('/git/trees'):return {'sha':'d'*40}
                if endpoint.endswith('/git/commits'):return {'sha':'e'*40}
                if endpoint.endswith('/commits/main'):return {'sha':'f'*40}
                raise AssertionError(endpoint)
        writer=Writer()
        with self.assertRaises(ValueError):m.publish_tree(writer,{m.PIN_PATH:(b'x','100644')},'a'*40,'guard/site-'+'a'*40+'-1.0.4','inert','inert')
        self.assertFalse(any(x.endswith('/git/refs') or x.endswith('/pulls') for x in writer.writes))


if __name__=='__main__':unittest.main()
