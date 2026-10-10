"""Pure/mocked preparation fixtures; no local vendor/native/provider execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
REPO=Path(__file__).resolve().parents[5]
SUPPORT=REPO/'deploy/guard/e2e'
if not (SUPPORT/'hosted_launch/inventory.py').is_file():
    SUPPORT=REPO.parent/'dependencies/deploy/guard/e2e'
sys.path.insert(0,str(SUPPORT));sys.path.insert(0,str(HERE))
import runtime_maps as maps
import prepare_runtime as getter
from hosted_launch.contracts import digest,canonical


def record(path,raw=b'fixture'):
    return {'path':str(path),'bytes':len(raw),'sha256':digest(raw),'uid':0,'mode':0o100444,
            'dev':8,'ino':10,'nlink':1}


def elf(dynamic):
    raw=bytearray(120);raw[:6]=b'\x7fELF\x02\x01'
    struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1)
    struct.pack_into('<I',raw,64,2 if dynamic else 1)
    return bytes(raw)


class InventoryFixtures(unittest.TestCase):
    def test_complete_tree_retains_every_member(self):
        rows={'a.py':digest(b'a'),'nested/b.py':digest(b'b')}
        def actual(path):return record(path,b'a' if str(path).endswith('/a.py') else b'b')
        with patch.object(maps,'tree',return_value={'schema':1,'files':rows}),patch.object(maps,'entry',side_effect=actual):
            o=maps.Observation();self.assertEqual(o.complete_tree('/opt/fixed'),{'schema':1,'files':rows})
            self.assertEqual(len(o.closure('actual-fixed-linux-runtime-closure')['entries']),2)
            self.assertEqual(set(o.entries),{'/opt/fixed/a.py','/opt/fixed/nested/b.py'})

    def test_tree_omission_or_member_mutation_refuses(self):
        with patch.object(maps,'tree',return_value={'schema':1,'files':{'a.py':digest(b'old')}}),patch.object(maps,'entry',side_effect=record):
            with self.assertRaises(RuntimeError):maps.Observation().complete_tree('/opt/fixed')

    def test_complete_stdlib_not_trimmed_to_256(self):
        with patch.object(maps,'entry',side_effect=record):
            o=maps.Observation()
            for i in range(257):o.add('/opt/fixed/'+str(i)+'.py')
            self.assertEqual(len(o.closure('actual-fixed-linux-runtime-closure')['entries']),257)
            with self.assertRaises(RuntimeError):o.closure('actual-fixed-linux-trust-closure')

    def test_runtime_total_and_member_limits_refuse(self):
        with patch.object(maps,'entry',side_effect=lambda p:{**record(p),'bytes':maps.MAX_TOTAL+1}):
            with self.assertRaises(RuntimeError):maps.Observation().add('/opt/fixed/a')
        o=maps.Observation();o.entries={str(i):record(str(i)) for i in range(20001)}
        with self.assertRaises(RuntimeError):o.closure('actual-fixed-linux-runtime-closure')

    def test_repeated_member_changes_refuse(self):
        with patch.object(maps,'entry',side_effect=[record('/opt/a'),record('/opt/a',b'changed')]):
            o=maps.Observation();o.add('/opt/a')
            with self.assertRaises(RuntimeError):o.add('/opt/a')

    def test_recheck_detects_original_identity_and_alias_change(self):
        o=maps.Observation();o.entries['/opt/a']=record('/opt/a');o.aliases['/usr/bin/awk']='/usr/bin/mawk'
        with patch.object(maps,'entry',side_effect=lambda p:{**record(p),'ino':11}):
            with self.assertRaises(RuntimeError):o.recheck()
        with patch.object(maps,'entry',side_effect=record),patch.object(Path,'resolve',return_value=Path('/usr/bin/other')):
            with self.assertRaises(RuntimeError):o.recheck()

    def test_entry_preserves_protected_read_and_original_identity(self):
        fake=SimpleNamespace(st_dev=8,st_ino=10,st_uid=0,st_mode=0o100444,st_nlink=1,st_size=7,st_mtime_ns=1,st_ctime_ns=1)
        with patch.object(Path,'lstat',return_value=fake),patch.object(maps,'read',return_value=b'fixture') as read:
            e=maps.entry('/opt/a');read.assert_called_once_with(Path('/opt/a'),maps.MAX_FILE)
            self.assertEqual(e,record('/opt/a'))
        changed=SimpleNamespace(**{**vars(fake),'st_ino':11})
        with patch.object(Path,'lstat',side_effect=[fake,changed]),patch.object(maps,'read',return_value=b'fixture'):
            with self.assertRaises(RuntimeError):maps.entry('/opt/a')

    def test_lexical_system_alias_is_retained_not_guessed(self):
        with patch.object(Path,'resolve',return_value=Path('/usr/bin/mawk')),patch.object(maps,'entry',side_effect=record):
            o=maps.Observation();self.assertEqual(o.resolve('/usr/bin/awk'),'/usr/bin/mawk')
            self.assertEqual(o.closure('actual-fixed-linux-runtime-closure')['aliases'],[{'path':'/usr/bin/awk','target':'/usr/bin/mawk'}])

    def test_ldd_known_dynamic_paths(self):
        raw=b'linux-vdso.so.1 (0x123)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x124)\n/lib64/ld-linux-x86-64.so.2 (0x125)\n'
        self.assertEqual(maps.parse_dependencies(raw,0),['/lib/x86_64-linux-gnu/libc.so.6','/lib64/ld-linux-x86-64.so.2'])

    def test_ldd_missing_unowned_unknown_and_oversize_refuse(self):
        for raw,code in [(b'libx => not found\n',0),(b'libx => /tmp/attacker.so (0x123)\n',0),
                         (b'unknown diagnostic',1),(b'x'*65537,0),(b'',2)]:
            with self.assertRaises(RuntimeError):maps.parse_dependencies(raw,code)

    def test_static_and_dynamic_elf_are_distinguished_without_execution(self):
        self.assertFalse(maps.dynamic_elf(elf(False)));self.assertTrue(maps.dynamic_elf(elf(True)))
        for raw in (b'notELF',elf(True)[:70]):
            with self.assertRaises(RuntimeError):maps.dynamic_elf(raw)

    def test_ldd_failure_cannot_hide_dynamic_runtime(self):
        o=maps.Observation()
        with patch.object(o,'resolve',side_effect=lambda p:p),patch.object(maps.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'')),patch.object(maps,'read',return_value=elf(True)):
            with self.assertRaises(RuntimeError):maps.native_closure(o,['/usr/bin/fixed'])
        with patch.object(o,'resolve',side_effect=lambda p:p),patch.object(maps.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'')),patch.object(maps,'read',return_value=elf(False)):
            self.assertEqual(maps.native_closure(o,['/usr/bin/fixed']),['/usr/bin/fixed'])

    def test_mapped_observation_refuses_deleted_unowned_and_omitted(self):
        self.assertEqual(maps.mapped_paths('1-2 r-xp 0 00:00 1 /opt/zunder-public-reboot-acquisition/runtime/node'),['/opt/zunder-public-reboot-acquisition/runtime/node'])
        for raw in ('1-2 r-xp 0 00:00 1 /usr/lib/libx.so (deleted)','1-2 r-xp 0 00:00 1 /opt/hostedtoolcache/node','', '1-2 r-xp 0 00:00 1 /tmp/key'):
            with self.assertRaises(RuntimeError):maps.mapped_paths(raw)

    def test_tuf_empty_fallback_unknown_or_duplicate_target_refuses(self):
        for files in ({},{'fulcio.crt':digest(b'cert')},{'trusted_root.json':digest(b'a'),'x/trusted_root.json':digest(b'b')}):
            with patch.object(maps,'tree',return_value={'schema':1,'files':files}):
                with self.assertRaises(RuntimeError):maps.trusted_root_observation('/opt/fixed')

    def test_actual_tuf_target_observation_stays_unadmitted(self):
        value={'mediaType':'application/vnd.dev.sigstore.trustedroot+json;version=0.1','certificateAuthorities':[{}],'tlogs':[{}]}
        raw=canonical(value)
        with patch.object(maps,'tree',return_value={'schema':1,'files':{'targets/trusted_root.json':digest(raw)}}),patch.object(maps,'read',return_value=raw):
            v=maps.trusted_root_observation('/opt/fixed');self.assertFalse(v['trustAdmitted']);self.assertEqual(v['trustedRootTargetSha256'],digest(raw))
        with patch.object(maps,'tree',return_value={'schema':1,'files':{'targets/trusted_root.json':digest(raw)}}),patch.object(maps,'read',return_value=b'{}'):
            with self.assertRaises(RuntimeError):maps.trusted_root_observation('/opt/fixed')


    def test_diagnostic_retains_only_hash_and_clears_after_success(self):
        fake=SimpleNamespace(st_dev=8,st_ino=10,st_uid=0,st_mode=0o100444,st_nlink=1,st_size=7,st_mtime_ns=1,st_ctime_ns=1)
        with patch.object(Path,'lstat',return_value=fake),patch.object(maps,'read',side_effect=RuntimeError('SECRET /private/path')):
            with self.assertRaises(RuntimeError):maps.entry('/opt/fixed/a')
        self.assertEqual(maps.CONTEXT,{'operation':'protected-member','memberSha256':digest(b'/opt/fixed/a')})
        with patch.object(Path,'lstat',return_value=fake),patch.object(maps,'read',return_value=b'fixture'):
            maps.entry('/opt/fixed/a')
        self.assertIsNone(maps.CONTEXT)

    def test_zero_byte_members_retained_with_exact_empty_hash(self):
        fake=SimpleNamespace(st_dev=8,st_ino=10,st_uid=0,st_mode=0o100444,st_nlink=1,st_size=0,st_mtime_ns=1,st_ctime_ns=1)
        with patch.object(Path,'lstat',return_value=fake),patch.object(maps,'read',return_value=b''):
            result=maps.entry('/opt/stdlib/empty.py')
        self.assertEqual(result['bytes'],0);self.assertEqual(result['sha256'],digest(b''))


class GetterFixtures(unittest.TestCase):
    def test_fixed_clean_environment_has_no_secret_proxy_or_factory(self):
        env=maps.clean_environment()
        self.assertEqual(env['TUF_ROOT'],'/opt/zunder-public-reboot-acquisition/trust/cache/sigstore')
        self.assertEqual(env['OPENSSL_CONF'],'/opt/zunder-public-reboot-acquisition/trust/openssl.cnf')
        for name in ('GH_TOKEN','GITHUB_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN','AWS_PROFILE','AWS_ACCESS_KEY_ID','BASH_ENV','NODE_OPTIONS','PYTHONPATH','LD_PRELOAD','HTTPS_PROXY','TUF_MIRROR','TUF_ROOT_JSON'):
            self.assertNotIn(name,env);self.assertNotIn(name,getter.initial_environment())

    def test_only_fixed_finite_archive_destinations_and_aliases(self):
        self.assertEqual(getter.destination('deploy/guard/e2e/actions-artifacts.py'),getter.SOURCE/'actions-artifacts.py')
        self.assertIsNone(getter.destination('web/site/src/pages/[...slug].astro'))
        for name in ('../escape','/absolute','some/../escape','some//escape'):
            with self.assertRaises(RuntimeError):getter.destination(name)

    def test_vendor_versions_size_and_sha_are_literal(self):
        self.assertEqual(getter.VENDORS['cosign'][1:],(141178250,'4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71'))
        self.assertEqual(getter.VENDORS['slsa-verifier'][1:],(33291668,'946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339'))
        with self.assertRaises(RuntimeError):getter.download_vendor('caller-url')

    def test_vendor_redirect_refuses_http_userinfo_other_host_fragment(self):
        for url in ('http://release-assets.githubusercontent.com/a','https://evil.example/a','https://user@release-assets.githubusercontent.com/a','https://release-assets.githubusercontent.com/a#bad'):
            with self.assertRaises(RuntimeError):getter.VendorRedirect().redirect_request(None,None,302,'',{},url)

    def download(self,raw,size,expected):
        response=io.BytesIO(raw);response.status=200
        opener=SimpleNamespace(open=lambda *a,**kw:response)
        with patch.object(getter,'VENDORS',{'cosign':('https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64',size,expected)}),patch.object(getter,'build_opener',return_value=opener),patch.object(getter,'exclusive') as output:
            v=getter.download_vendor('cosign');return v,output

    def test_vendor_good_bytes_copied_only_after_exact_hash(self):
        v,output=self.download(b'fixed',5,digest(b'fixed'))
        self.assertFalse(v['upstreamSignatureIndependentlyVerified']);output.assert_called_once_with(getter.ROOT/'bin/cosign',b'fixed',0o700)

    def test_vendor_truncated_oversize_and_bad_hash_never_execute_or_copy(self):
        for raw,size,expected in ((b'four',5,digest(b'fixed')),(b'oversize',5,digest(b'fixed')),(b'other',5,digest(b'fixed'))):
            with self.assertRaises(RuntimeError):self.download(raw,size,expected)

    def test_error_privacy_is_closed_even_with_unknown_stage(self):
        original=getter.STAGE
        try:
            getter.STAGE='/private/secret/path'
            output=io.StringIO()
            with patch.object(Path,'is_dir',return_value=False),contextlib.redirect_stdout(output):
                getter.failure(RuntimeError('SECRET_TOKEN /private/key'))
            value=json.loads(output.getvalue());self.assertEqual(value['stage'],'unknown')
            self.assertFalse(value['privateInput']);self.assertFalse(value['runtimeAdmitted']);self.assertFalse(value['releaseReady'])
            self.assertNotIn('SECRET',output.getvalue());self.assertNotIn('/private',output.getvalue())
        finally:getter.STAGE=original

    def test_fixed_workflow_contains_no_reader_oidc_provider_candidate_or_toolcache(self):
        path=REPO/'.github/workflows/hosted-linux-acquisition-runtime-preparation.yml'
        text=path.read_text();self.assertIn('contents: read',text);self.assertIn('runs-on: ubuntu-24.04',text)
        self.assertIn('persist-credentials: false',text);self.assertIn('sudo /usr/bin/env -i',text)
        for forbidden in ('id-token:','secrets.','create-github-app-token','aws-actions','setup-node','GH_TOKEN:','GITHUB_TOKEN:','verifyOriginalPaperCandidate','verify-image','verify-artifact'):
            self.assertNotIn(forbidden,text)


    def source_fixture(self,mutate=False):
        packet={};dependencies=REPO.parent/'dependencies'
        if not dependencies.is_dir():dependencies=REPO
        for name in getter.DEPENDENCIES:packet[name]=(dependencies/name).read_bytes()
        for name,(target,_) in getter.VERIFIERS.items():
            file=REPO/name
            if not file.is_file():file=REPO.parent/'evidence/source-verifiers'/target
            packet[name]=file.read_bytes()
        for name in ('prepare_runtime.py','runtime_maps.py'):
            packet[getter.PUBLIC_ENTRY+name]=(HERE/name).read_bytes()
        if mutate:packet[next(iter(getter.DEPENDENCIES))]=b'changed source'
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as archive:
            for name,data in packet.items():
                member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o644;archive.addfile(member,io.BytesIO(data))
        return raw.getvalue()

    def test_fixed_root_source_copies_before_protected_reexec(self):
        archive=self.source_fixture();commit='a'*40
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();workspace=root/'checkout';workspace.mkdir()
            overrides={'ROOT':root/'owned','SOURCE':root/'owned/source','MATERIAL':root/'material','REPORTS':root/'reports','WORK':root/'work'}
            with patch.multiple(getter,**overrides),patch.object(getter,'command',side_effect=[(commit+'\n').encode(),b'',archive]),patch.object(getter,'protected_ancestors'),patch.object(getter,'protect_simple') as protect,patch.object(getter,'checked_reexec',side_effect=lambda executable,args,env,expected:getter.os.execve(executable,args,env)),patch.object(getter.os,'execve') as execute:
                getter.stage_source(str(workspace),commit)
                protect.assert_called_once_with(root/'owned/source')
                execute.assert_called_once()
                self.assertEqual(execute.call_args.args[0],'/usr/bin/python3.12')
                self.assertIn(str(root/'owned/source/preparation/prepare_runtime.py'),execute.call_args.args[1])
                self.assertEqual(json.loads((root/'owned/source/original-source.json').read_bytes())['commit'],commit)

    def test_source_dependency_mismatch_never_reexecutes(self):
        archive=self.source_fixture(True);commit='a'*40
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();workspace=root/'checkout';workspace.mkdir()
            overrides={'ROOT':root/'owned','SOURCE':root/'owned/source','MATERIAL':root/'material','REPORTS':root/'reports','WORK':root/'work'}
            with patch.multiple(getter,**overrides),patch.object(getter,'command',side_effect=[(commit+'\n').encode(),b'',archive]),patch.object(getter,'protected_ancestors'),patch.object(getter,'protect_simple'),patch.object(getter,'checked_reexec',side_effect=lambda executable,args,env,expected:getter.os.execve(executable,args,env)),patch.object(getter.os,'execve') as execute:
                with self.assertRaises(RuntimeError):getter.stage_source(str(workspace),commit)
                execute.assert_not_called()



class RepairFixtures(unittest.TestCase):
    def test_r1_exact_writable_ancestor_refuses_before_any_source_mutation(self):
        archive=GetterFixtures().source_fixture();commit='a'*40
        with tempfile.TemporaryDirectory()as td:
            base=Path(td).resolve();parent=base/'unprotected';parent.mkdir(mode=0o777);parent.chmod(0o777)
            workspace=base/'checkout';workspace.mkdir();original=Path.lstat
            def stat_path(path):
                actual=original(path)
                return SimpleNamespace(st_uid=0,st_mode=actual.st_mode)
            overrides={'ROOT':parent/'owned','SOURCE':parent/'owned/source','MATERIAL':parent/'material','REPORTS':parent/'reports','WORK':parent/'work'}
            with patch.multiple(getter,**overrides),patch.object(Path,'lstat',stat_path),patch.object(getter,'command',side_effect=[(commit+'\n').encode(),b'',archive])as command,patch.object(getter,'protect_simple')as protect,patch.object(getter.os,'execve')as execute:
                with self.assertRaises(RuntimeError):getter.stage_source(str(workspace),commit)
                command.assert_not_called();protect.assert_not_called();execute.assert_not_called()
                self.assertFalse((parent/'owned').exists());self.assertFalse((parent/'reports').exists())

    def test_canonical_symlink_or_nonroot_existing_ancestor_refuses(self):
        with tempfile.TemporaryDirectory()as td:
            base=Path(td).resolve();target=base/'target';target.mkdir();alias=base/'alias';alias.symlink_to(target,target_is_directory=True)
            with self.assertRaises(RuntimeError):getter.protected_ancestors(alias/'new')
        fake=SimpleNamespace(st_uid=1000,st_mode=0o40755)
        with patch.object(Path,'resolve',side_effect=lambda *args,**kw:Path('/opt/fixed')),patch.object(Path,'lstat',return_value=fake):
            with self.assertRaises(RuntimeError):getter.protected_ancestors('/opt/fixed')

    def test_checked_reexec_retains_original_source_and_refuses_hash_or_identity_change(self):
        raw=b'original';source=SimpleNamespace(st_dev=8,st_ino=10,st_uid=0,st_mode=0o100444,st_nlink=1,st_size=len(raw),st_mtime_ns=1,st_ctime_ns=1)
        binary=SimpleNamespace(st_uid=0,st_mode=0o100555,st_nlink=1)
        for variant in ('good','hash','identity'):
            named=SimpleNamespace(**{**vars(source),'st_ino':11})if variant=='identity'else source
            with patch.object(getter,'guard_fixed_paths')as guard,patch.object(getter,'protected_ancestors'),patch.object(getter.os,'open',return_value=42)as opened,patch.object(getter.os,'fstat',return_value=source),patch.object(getter.os,'read',return_value=raw),patch.object(Path,'lstat',side_effect=[named,binary]),patch.object(getter.os,'close')as close,patch.object(getter.os,'execve')as execute:
                execute.side_effect=lambda *args:self.assertEqual(close.call_count,0)
                if variant=='good':getter.checked_reexec('/usr/bin/python3.12',['fixed'],{},digest(raw));execute.assert_called_once()
                else:
                    with self.assertRaises(RuntimeError):getter.checked_reexec('/usr/bin/python3.12',['fixed'],{},digest(b'wrong')if variant=='hash'else digest(raw))
                    execute.assert_not_called()
                guard.assert_called_once();self.assertEqual(opened.call_args.args[1],getter.os.O_RDONLY|getter.os.O_NOFOLLOW);close.assert_called_once_with(42)

    def test_r1_provider_and_mapped_transitive_dependencies_enter_final_recursive_closure(self):
        import hosted_launch.inventory as inventory
        provider='/usr/lib/x86_64-linux-gnu/ossl-modules/provider.so';dependency='/usr/lib/x86_64-linux-gnu/libproviderdep.so.1';mapped='/usr/lib/x86_64-linux-gnu/libmapped.so.1';mappeddep='/usr/lib/x86_64-linux-gnu/libmappeddep.so.1';observed=[];calls=[]
        class Observation:
            def __init__(self):self.entries={};observed.append(self)
            def resolve(self,path):
                path=str(path);self.entries[path]=record(path,b'');return path
            def complete_tree(self,root):return {'schema':1,'files':{}}
            def recheck(self):calls.append('recheck')
            def closure(self,kind):return {'schema':1,'kind':kind,'platform':'linux','arch':'x64','entries':list(self.entries.values()),'aliases':[]}
        def native_closure(observation,seeds):
            calls.append(('native-seeds',list(seeds)))
            for seed in seeds:
                observation.resolve(seed)
                if seed==provider:observation.resolve(dependency)
                if seed==mapped:observation.resolve(mappeddep)
            return list(seeds)
        fake=SimpleNamespace(Observation=Observation,native_closure=native_closure,SYSTEM_CONFIG=(),mapped_paths=lambda _:[mapped],trusted_root_observation=lambda _:{'trustAdmitted':False},clean_environment=maps.clean_environment)
        output=io.StringIO()
        with patch.object(getter,'support',return_value=fake),patch.object(getter.sys,'executable',str(getter.ROOT/'bin/python3')),patch.object(getter.sys,'prefix',str(getter.ROOT)),patch.object(Path,'glob',return_value=[]),patch.object(Path,'rglob',return_value=[Path(provider)]),patch.object(Path,'is_dir',return_value=True),patch.object(Path,'is_file',return_value=True),patch.object(Path,'read_text',return_value=''),patch.object(Path,'mkdir'),patch.object(getter,'command',return_value=b''),patch.object(inventory,'write_new',return_value={'sha256':'0'*64}),patch.object(inventory,'tree',return_value={'schema':1,'files':{}}),contextlib.redirect_stdout(output):
            getter.inventories('a'*40)
        runtime=observed[0]
        self.assertIn(provider,runtime.entries);self.assertIn(dependency,runtime.entries);self.assertIn(mappeddep,runtime.entries)
        seeds=next(row[1]for row in calls if isinstance(row,tuple));self.assertIn(provider,seeds);self.assertIn(mapped,seeds)
        summary=json.loads(output.getvalue());self.assertFalse(summary['runtimeAdmitted']);self.assertFalse(summary['releaseReady']);self.assertFalse(summary['privateInput'])

    def test_r1_current_public_reviewed_bootstrap_and_contracts_match_compiled_pins(self):
        expected={'bootstrap.py':'0f8ce0bb4aea0708af0a2fafac27875b084d42b9485f98d428a0acdd47cc6dfc','contracts.py':'243a91e7abaa84511a9fc087d9af2ef9ff74bea6f9c679d2b48b70c9be81dc6b'}
        for name,sha in expected.items():
            self.assertEqual(getter.DEPENDENCIES['deploy/guard/e2e/hosted_launch/'+name],sha)
            self.assertEqual(digest((SUPPORT/'hosted_launch'/name).read_bytes()),sha)
        # The positive archive/reexec test above uses exactly these current reviewed bytes.

if __name__=='__main__':unittest.main()
