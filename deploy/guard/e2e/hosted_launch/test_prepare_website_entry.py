"""Inert invoker fixtures: no network, compiler, reader, bootstrap or provider."""
import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from . import prepare_website_entry as p


class Invoker(unittest.TestCase):
    def env(self):return {**p.BASE_ENV,'GITHUB_REPOSITORY':p.REPOSITORY,'GITHUB_REF':'refs/heads/main',
        'GITHUB_REF_TYPE':'branch','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_SHA':'a'*40}
    def roster(self):
        pin={'sourceCommit':'b'*40};raw=b'exact admitted raw record'
        roster={'schema':1,'id':'fixture','rawAdmissionSha256':p.digest(raw),'sourceCommit':'b'*40,
            'sourceJsonSha256':'c'*64,'sourceInventorySha256':'d'*64,'sourceFiles':2,'sourceBytes':3,'candidateSha256':'e'*64}
        return raw,pin,roster
    def test_exact_clean_context_and_no_credential_environment(self):
        env=self.env();p.context('a'*40,env)
        for key,value in [('GITHUB_TOKEN','hidden'),('AWS_REGION','hidden'),('NODE_OPTIONS','hidden'),('APP_PRIVATE_KEY','hidden'),('UNKNOWN','hidden'),('GITHUB_REF','refs/pull/1/merge'),('GITHUB_SHA','b'*40)]:
            with self.subTest(key=key),self.assertRaises(RuntimeError):p.context('a'*40,{**env,key:value})
        p.context('a'*40,{**env,'PRIVATE_ARTIFACT_READ_TOKEN':'test-only','GITHUB_TOKEN':'test-only'},reader=True)
    def test_source_roster_no_unknown_field_bool_count_or_wrong_pin(self):
        raw,pin,roster=self.roster();p.validate_roster(raw,pin,roster,'fixture')
        for key,value in [('extra',True),('schema',True),('id','different'),('rawAdmissionSha256','f'*64),('sourceCommit','f'*40),('sourceFiles',True),('sourceBytes',0),('candidateSha256','latest')]:
            with self.subTest(key=key),self.assertRaises(RuntimeError):p.validate_roster(raw,pin,{**roster,key:value},'fixture')
    def test_no_saved_stage_json_authorizes_raw_source(self):
        pin={'sourceCommit':'b'*40,'purpose':'original-guard-website-build-input','privateRepository':{'id':1,'fullName':'zunderlabs/zunder'},
            'sourceRef':'refs/heads/main','producer':{},'artifact':{'id':2,'digest':'sha256:'+'a'*64},'inventorySha256':'c'*64,'manifestSha256':'d'*64}
        result={'admission':'fixture',**{k:pin[k]for k in('sourceCommit','inventorySha256','manifestSha256')},'artifactId':2,'artifactDigest':pin['artifact']['digest'],
            'tokenRevoked':True,'stageReceiptSha256':'e'*64}
        inventory={'schema':1,'files':{'file.rs':p.digest(b'actual')}}
        receipt={**pin,'source':{'manifest':{'file':'/protected/source.json','sha256':p.digest(p.canonical(inventory))}},
            'candidate':{'sha256':'f'*64},'rawManifest':{}}
        _,_,roster=self.roster();roster.update(sourceJsonSha256=p.digest(p.canonical(inventory)),sourceInventorySha256=p.digest(p.canonical(inventory)),sourceFiles=1,sourceBytes=6,candidateSha256='f'*64)
        with patch.object(p,'read',side_effect=lambda path,*_:p.canonical(result)if path.name=='raw-reader.json'else b'actual'),\
             patch.object(p.recipe,'stage_input',return_value=(receipt,inventory)),\
             patch.object(p.recipe,'ref_bytes',side_effect=lambda ref:p.canonical(inventory)if ref is receipt['source']['manifest']else p.canonical({'published':False})):
            p.raw_source(pin,roster,'fixture')
            for mutation in ({'sourceInventorySha256':'0'*64},{'sourceJsonSha256':'0'*64},{'sourceBytes':7},{'candidateSha256':'0'*64}):
                with self.assertRaises(RuntimeError):p.raw_source(pin,{**roster,**mutation},'fixture')
            with patch.object(p.recipe,'ref_bytes',side_effect=lambda ref:p.canonical(inventory)if ref is receipt['source']['manifest']else p.canonical({'published':True})),self.assertRaises(RuntimeError):p.raw_source(pin,roster,'fixture')
    def test_source_checks_actual_clean_git_bootstrap_tree_and_committed_roster(self):
        text=Path(p.__file__).read_text();body=text[text.index('def public_source'):text.index('def validate_roster')]
        for value in ("['rev-parse','HEAD']","['status','--porcelain']","['archive','--format=tar',commit]",'source_map==tree(SOURCE)',"['show',commit+':'+name]",'read(SOURCE/name','module.load_pin(pin,identifier)','validate_roster(pin_raw,pin,roster,identifier)'):
            self.assertIn(value,body)
    def test_original_bootstrap_and_actual_git_and_protected_committed_bytes_join(self):
        workspace=Path('/fixture-workspace');commit='a'*40
        pin_raw,pin,roster=self.roster();pin_raw=p.canonical(pin);roster['rawAdmissionSha256']=p.digest(pin_raw)
        records={p.RAW+'fixture.json':pin_raw,p.RAW+'fixture.source.json':p.canonical(roster)}
        inventory={'schema':1,'files':{name:p.digest(raw)for name,raw in records.items()}}
        inv_raw=p.canonical(inventory)
        report={'schema':1,'kind':'actual-free-hosted-ordinary-preparation','controlSource':commit,
            'source':{'commit':commit,'archiveSha256':p.digest(b'actual Git archive'),'controllerRoot':str(p.SOURCE),
                'genuineCheckout':str(p.CHECKOUT),'gitDatabaseInSourceInventory':False},
            'inventories':{'source':{'file':str(p.PUBLIC/'reports/source-inventory.json'),'sha256':p.digest(inv_raw)}},
            **{k:False for k in('privateInput','providerRolesAssumed','venueOrders','nativeAcceptance','fullJourney','releaseReady')}}
        def git(_workspace,args,*_):
            if args==['rev-parse','HEAD']:return(commit+'\n').encode()
            if args==['status','--porcelain']:return b''
            if args==['archive','--format=tar',commit]:return b'actual Git archive'
            if args[0]=='show':return records[args[1].split(':',1)[1]]
            self.fail('Unexpected command')
        def read(path,*_):
            if path.name=='preparation.json':return p.canonical(report)
            if path.name=='source-inventory.json':return inv_raw
            return records[str(path.relative_to(p.SOURCE))]
        module=SimpleNamespace(load_pin=lambda *_:None)
        spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _:None))
        with patch.object(Path,'resolve',return_value=workspace),patch.object(p,'git',side_effect=git),\
            patch.object(p,'read',side_effect=read),patch.object(p,'tree',return_value=inventory),\
            patch.object(p.importlib.util,'spec_from_file_location',return_value=spec),\
            patch.object(p.importlib.util,'module_from_spec',return_value=module):
            actual=p.public_source(workspace,commit,'fixture');self.assertEqual(actual[:2],(pin,roster))
            for changed in('controlSource','fullJourney'):
                with patch.dict(report,{changed:'changed'}),self.assertRaises(RuntimeError):p.public_source(workspace,commit,'fixture')
            with patch.object(p,'tree',return_value={'schema':1,'files':{}}),self.assertRaises(RuntimeError):p.public_source(workspace,commit,'fixture')
            with patch.object(p,'git',side_effect=lambda w,args,*_:b'changed'if args[0]=='archive'else git(w,args)),self.assertRaises(RuntimeError):p.public_source(workspace,commit,'fixture')
            with patch.object(p,'read',side_effect=lambda path,*_:b'changed'if path.name=='fixture.source.json'else read(path)),self.assertRaises(RuntimeError):p.public_source(workspace,commit,'fixture')
    def test_fixed_vendor_constants_and_no_redirect(self):
        self.assertEqual(p.RUSTUP_BYTES,21113232);self.assertEqual(p.RUSTUP_SHA,'dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71')
        self.assertIn('/1.29.1/x86_64-unknown-linux-gnu/',p.RUSTUP_URL)
        self.assertEqual(str(p.RUSTUP),'/opt/zunder-hosted-ordinary/runtime/node/bin/rustup')
        with self.assertRaises(RuntimeError):p.NoRedirect().redirect_request(None)
    def test_vendor_failure_never_creates_or_executes_file(self):
        # Context-manager fixture is a harmless response only, never a network.
        class Response:
            status=302
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def geturl(self):return p.RUSTUP_URL
        opener=SimpleNamespace(open=lambda *_args,**_kw:Response())
        info=SimpleNamespace(st_mode=0o040700,st_uid=0)
        with patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),\
            patch.object(Path,'lstat',return_value=info),patch.object(p,'build_opener',return_value=opener),\
            patch.object(p.os,'open')as create,self.assertRaises(RuntimeError):p.rustup()
        create.assert_not_called()
    def test_vendor_wrong_bytes_header_size_digest_never_written(self):
        class Response:
            status=200
            def __init__(self,raw):self.input=io.BytesIO(raw)
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def geturl(self):return p.RUSTUP_URL
            def read1(self,size):return self.input.read(size)
        expected=b'\x7fELF\x02\x01'+b'0'*12+b'\x3e\x00'+b'fixture'
        info=SimpleNamespace(st_mode=0o040700,st_uid=0)
        for raw in (b'',expected[:-1],expected+b'!',b'\x00'+expected[1:],expected[:18]+b'\x00\x00'+expected[20:]):
            opener=SimpleNamespace(open=lambda *_args,**_kw:Response(raw))
            with self.subTest(raw=raw),patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),\
                patch.object(Path,'lstat',return_value=info),patch.object(p,'build_opener',return_value=opener),\
                patch.object(p,'RUSTUP_BYTES',len(expected)),patch.object(p,'RUSTUP_SHA',p.digest(expected)),\
                patch.object(p.os,'open')as create,self.assertRaises(RuntimeError):p.rustup()
            create.assert_not_called()
    def test_managed_tools_reread_python_node_npm_and_original_digest(self):
        rows={str(path):p.digest(str(path).encode())for path in(p.PYTHON,p.NODE,p.NPM)}
        raw=p.canonical({'files':rows})
        report={'inventories':{'runtime':{'file':str(p.PUBLIC/'reports/runtime-inventory.json'),'sha256':p.digest(raw)}},
            'node':{'version':'26.8.1','archiveSha256':'3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d'}}
        def read(path,*_):return raw if path.name=='runtime-inventory.json'else str(path).encode()
        with patch.object(p,'read',side_effect=read)as observed:
            self.assertEqual(set(p.tools(report)),{'node','npm'})
            self.assertEqual({str(call.args[0])for call in observed.call_args_list if call.args[0].name!='runtime-inventory.json'},set(rows))
        for changed in(p.PYTHON,p.NODE,p.NPM):
            with patch.object(p,'read',side_effect=lambda path,*_:b'changed'if path==changed else read(path)),self.assertRaises(RuntimeError):p.tools(report)
    def test_reader_uses_scoped_env_no_token_argv_and_requires_original_completion(self):
        pin={'purpose':'fixed','sourceCommit':'b'*40,'artifact':{'id':2,'digest':'sha256:'+'c'*64},'inventorySha256':'d'*64,'manifestSha256':'e'*64}
        value={'schema':1,'admission':'fixture','purpose':'fixed','sourceCommit':'b'*40,'artifactId':2,'artifactDigest':pin['artifact']['digest'],
            'inventorySha256':'d'*64,'manifestSha256':'e'*64,'tokenRevoked':True,'stageReceiptSha256':'f'*64,'privateInput':False,'releaseReady':False}
        env={**self.env(),'PRIVATE_ARTIFACT_READ_TOKEN':'private-test-only','GITHUB_TOKEN':'public-test-only'}
        observations=[]
        def run(argv,**kw):
            observations.append((argv,dict(kw['env']),kw['env']))
            return SimpleNamespace(returncode=0,stdout=p.canonical(value))
        with patch.object(p,'public_source',return_value=(pin,{}, {}, None)),patch.object(p,'tools'),\
            patch.object(p.os,'geteuid',return_value=0),patch.object(Path,'resolve',return_value=p.PYTHON),\
            patch.object(p.subprocess,'run',side_effect=run),patch.object(p,'write_new')as write:
            p.read_raw('/unused','a'*40,'fixture',env);write.assert_called_once()
            argv,scoped,cleared=observations[0]
            self.assertNotIn('private-test-only',' '.join(argv));self.assertNotIn('public-test-only',' '.join(argv))
            self.assertEqual(scoped,env);self.assertEqual(cleared,{})
            for name,mutation in(('tokenRevoked',False),('sourceCommit','0'*40),('schema',True),('releaseReady',True)):
                with patch.dict(value,{name:mutation}),self.assertRaises(RuntimeError):p.read_raw('/unused','a'*40,'fixture',env)
    def test_metadata_is_bounded_counts_and_digests_not_private_inventory(self):
        inventories={'website':{'schema':1,'files':{'private/customer.ts':'c'*64}},'tools':{'schema':1,'files':{'private/tool.js':'d'*64}}}
        proof={'runtimeAdmitted':False,'releaseReady':False,'sourceCommit':'b'*40,
            **{kind:{'manifest':{'file':'/private/'+kind,'sha256':p.digest(p.canonical(value))}}for kind,value in inventories.items()}}
        raw=p.canonical(proof);ref={'file':str(p.recipe.INPUT/'preparation.json'),'sha256':p.digest(raw)}
        with patch.object(p,'read',return_value=raw),patch.object(p.recipe,'ref_bytes',side_effect=lambda ref:p.canonical(inventories[Path(ref['file']).name])):
            result=p.bounded_metadata(ref,'fixture','a'*40)
            self.assertNotIn('customer',p.canonical(result).decode());self.assertNotIn('/private/',p.canonical(result).decode())
            self.assertEqual(result['source']['files'],1);self.assertFalse(result['runtimeAdmitted'])
            with self.assertRaises(RuntimeError):p.bounded_metadata({**ref,'sha256':'0'*64},'fixture','a'*40)
    def test_prepare_order_and_no_live_call_on_import(self):
        text=Path(p.__file__).read_text();body=text[text.index('def invoke'):text.index('def main')]
        self.assertLess(body.index('public_source('),body.index('raw_source('));self.assertLess(body.index('raw_source('),body.index('rustup()'))
        self.assertLess(body.index('rustup()'),body.index('recipe.prepare(stage_ref,refs)'))
        tree=ast.parse(text)
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.ClassDef,ast.If)):continue
            self.assertFalse(any(isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr in('run','open','prepare')for n in ast.walk(node)))
    def test_failure_metadata_never_prints_exception_paths_payload_credentials(self):
        argv=['entry','--workspace','/unused','--control-source','a'*40,'--admission-id','fixture']
        with patch.object(p.sys,'argv',argv),patch.object(p,'invoke',side_effect=RuntimeError('/private/source hidden-secret')),\
            patch('sys.stdout',new_callable=io.StringIO)as output:
            self.assertEqual(p.main(),1)
        value=json.loads(output.getvalue());self.assertEqual(value['status'],'held');self.assertNotIn('hidden',output.getvalue())
        self.assertFalse(value['wholeHostCredentialAbsenceProven']);self.assertFalse(value['releaseReady'])
    def test_argument_errors_are_fixed_and_never_echo_unknown_input(self):
        with patch.object(p.sys,'argv',['entry','--unknown-hidden-secret']),patch('sys.stdout',new_callable=io.StringIO)as output,\
            patch('sys.stderr',new_callable=io.StringIO)as error:
            self.assertEqual(p.main(),1)
        self.assertEqual(error.getvalue(),'');self.assertNotIn('hidden-secret',output.getvalue());self.assertEqual(json.loads(output.getvalue())['stage'],'arguments')
    def test_workflow_permissions_and_token_isolation(self):
        workflow=Path(__file__).resolve().parents[4]/'.github/workflows/hosted-website-build-preparation.yml'
        text=workflow.read_text();self.assertIn('ubuntu-24.04',text);self.assertIn('environment: website-staging',text)
        self.assertIn('ref: ${{ github.workflow_sha }}',text);self.assertIn('persist-credentials: false',text)
        self.assertIn('repositories: zunder',text);self.assertIn('permission-actions: read',text);self.assertIn('permission-contents: read',text)
        for refused in ('id-token:','packages:','HOSTED_OPS','CLOUDFLARE_API_TOKEN','AWS_','upload-artifact@latest'):self.assertNotIn(refused,text)
        body=text[text.index('- name: Prepare admitted website'):];self.assertNotIn('PRIVATE_ARTIFACT_READ_TOKEN',body);self.assertNotIn('GITHUB_TOKEN',body)
        self.assertIn('website-preparation-metadata.json',body);self.assertNotIn('/*.json',body)

if __name__=='__main__':unittest.main()
