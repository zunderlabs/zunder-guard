"""Inert source fixtures only: no candidate, tool install, service, VM or device."""
import importlib.util,json,os,stat,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch,Mock
HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location('inert_'+name,HERE/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
host=load('host');guest=load('guest');tools=load('prepare_tools');acquire=load('acquire')
class PublicClock:
    end=10**12
    def check(self):pass
class Peer:
    def __init__(self,chunks):self.chunks=list(chunks);self.sent=[]
    def settimeout(self,value):pass
    def recv(self,size):return self.chunks.pop(0)if self.chunks else b''
    def sendall(self,value):self.sent.append(value)
    def __enter__(self):return self
    def __exit__(self,*args):return False
class Fixtures(unittest.TestCase):
    def test_fixed_frame_canonical(self):
        row={'body':{},'kind':'fixture'};frames=host.Frames(Peer([host.canonical(row)+b'\n']),PublicClock());self.assertEqual(frames.read(1),row)
    def test_fixed_frame_noncanonical_and_duplicate_refused(self):
        for raw in(b'{ "a": 1 }\n',b'{"a":1,"a":1}\n'):
            with self.subTest(raw=raw),self.assertRaises(RuntimeError):host.Frames(Peer([raw]),PublicClock()).read(1)
    def test_QMP_vendor_frame_permitted_only_explicitly(self):
        self.assertEqual(host.Frames(Peer([b'{ "QMP": { "version": {} } }\r\n']),PublicClock(),False).read(1),{'QMP':{'version':{}}})
    def test_frame_EOF_and_size_refused(self):
        for chunks in([b''],[b'x'*65537]):
            with self.subTest(chunks=len(chunks[0])),self.assertRaises(RuntimeError):host.Frames(Peer(chunks),PublicClock()).read(1)
    def test_frame_deadline_not_renewed(self):
        frames=host.Frames(Peer([b'{}\n']),types.SimpleNamespace(end=0,check=lambda:None))
        with self.assertRaises(RuntimeError):frames.read(1)
    def test_clock_original_monotonic_expiry_despite_rollback(self):
        with patch.object(host.time,'monotonic',side_effect=[10,2331]),patch.object(host.time,'time_ns',return_value=100000000000):
            clock=host.Clock()
            with self.assertRaises(RuntimeError):clock.check()
    def test_clock_forward_wall_expiry(self):
        with patch.object(host.time,'monotonic',return_value=10),patch.object(host.time,'time_ns',side_effect=[100000000000,2421000000000]):
            clock=host.Clock()
            with self.assertRaises(RuntimeError):clock.check()
    def test_cloud_has_no_package_or_ssh_key_generation(self):
        row=host.cloud_config({'challenge':'a'*64});self.assertEqual(row['packages'],[]);self.assertFalse(row['package_update']);self.assertFalse(row['package_upgrade']);self.assertEqual(row['ssh_genkeytypes'],[]);self.assertEqual(row['users'],[])
        self.assertEqual(row['mounts'][0][3],'ro,nodev,nosuid,noexec');self.assertIn('After=cloud-final.service',row['write_files'][1]['content'])
        self.assertIn(['/usr/bin/systemctl','--no-block','start','zunder-public-guest-observer.service'],row['runcmd'])
    def test_qemu_has_actual_kvm_only_and_fixed_resource_bound(self):
        argv=host.qemu_argv(Path('/fixture'),{'kernel':{'name':'kernel'},'initrd':{'name':'initrd'}},{'qemu-system-x86_64':{'file':'/usr/bin/qemu-system-x86_64'}},'a'*64)
        self.assertEqual(argv[argv.index('-accel')+1],'kvm');self.assertEqual(argv[argv.index('-m')+1],'4096');self.assertEqual(argv[argv.index('-smp')+1],'2');self.assertNotIn('tcg',' '.join(argv));self.assertNotIn('hostfwd',' '.join(argv));self.assertIn('/fixture/kernel',argv);self.assertIn('/fixture/initrd',argv)
    def test_runtime_parse_and_invalid_values(self):
        self.assertEqual(host.timespan_seconds('38min 40s'),2320)
        for text in('infinity','1.5s','1s 2s','-1s','1ms',''):
            with self.subTest(text=text),self.assertRaises(RuntimeError):host.timespan_seconds(text)
    def test_original_runtime_cgroup_limits_are_actual_required_readbacks(self):
        owner=host.OwnedGuest(Path('/fixture'),{},PublicClock(),'a'*64,['/usr/bin/qemu-system-x86_64','fixture']);owner.pid=77;owner.ticks=123;owner.runtime_max=2320
        fields={'ActiveState':'active','MainPID':'77','ControlGroup':'/system.slice/'+owner.unit,'RuntimeMaxUSec':'38min 40s','LimitCORE':'0','KillMode':'control-group','NoNewPrivileges':'yes'}
        owner.fields=lambda:fields
        reads={'/proc/77/cmdline':b'/usr/bin/qemu-system-x86_64\0fixture\0','/sys/fs/cgroup/system.slice/'+owner.unit+'/memory.max':'5368709120','/sys/fs/cgroup/system.slice/'+owner.unit+'/pids.max':'64','/sys/fs/cgroup/system.slice/'+owner.unit+'/cpu.max':'200000 100000'}
        class PublicPath:
            def __init__(self,path):self.path=str(path)
            def __truediv__(self,name):return PublicPath(self.path+'/'+name)
            def __eq__(self,other):return self.path==other.path
            def resolve(self):return PublicPath('/usr/bin/qemu-system-x86_64')
            def read_bytes(self):return reads[self.path]
            def read_text(self):return reads[self.path]
        with patch.object(host,'Path',PublicPath),patch.object(host,'birth',return_value=123):
            owner.assert_live()
            for name,bad in(('memory.max','5368709121'),('pids.max','65'),('cpu.max','200001 100000')):
                key='/sys/fs/cgroup/system.slice/'+owner.unit+'/'+name;original=reads[key];reads[key]=bad
                with self.subTest(name=name),self.assertRaises(RuntimeError):owner.assert_live()
                reads[key]=original
            fields['RuntimeMaxUSec']='40min'
            with self.assertRaises(RuntimeError):owner.assert_live()
    def test_original_pid_birth_cannot_be_adopted(self):
        owner=host.OwnedGuest(Path('/fixture'),{},PublicClock(),'a'*64,['/usr/bin/qemu-system-x86_64']);owner.pid=77;owner.ticks=123;owner.fields=lambda:{'ActiveState':'active','MainPID':'77'}
        with patch.object(host,'birth',return_value=124),self.assertRaises(RuntimeError):owner.assert_live()
    def test_QMP_actual_KVM_disabled_refuses_without_fallback(self):
        for enabled in(True,False):
            peer=Peer([b'{ "QMP": {} }\r\n',b'{ "return": {} }\r\n',json.dumps({'return':{'enabled':enabled,'present':True}}).encode()+b'\r\n']);observed=Mock()
            owner=types.SimpleNamespace(clock=PublicClock(),connect=lambda name,timeout:peer,assert_live=observed)
            if enabled:host.qmp_kvm(owner);observed.assert_called_once()
            else:
                with self.assertRaises(RuntimeError):host.qmp_kvm(owner)
                observed.assert_not_called()
            self.assertEqual(len(peer.sent),2)
    def test_foreign_unit_cleanup_refuses_before_stop(self):
        owner=host.OwnedGuest(Path('/fixture'),{},PublicClock(),'a'*64,['/usr/bin/qemu-system-x86_64']);owner.started=True;owner.fields=lambda cleanup=False:{'LoadState':'loaded','ExecStart':'/foreign'}
        with patch.object(host,'command')as command,self.assertRaises(RuntimeError):owner.close()
        command.assert_not_called()
    def test_unstarted_owner_cleanup_has_no_effect(self):
        owner=host.OwnedGuest(Path('/fixture'),{},PublicClock(),'a'*64,['/usr/bin/qemu-system-x86_64'])
        with patch.object(host,'command')as command:self.assertTrue(owner.close())
        command.assert_not_called()
    def test_public_observation_exact_epoch_and_sequence(self):
        plan={'challenge':'a'*64,'controlSource':'b'*40,'candidateSource':'c'*40,'candidateManifestSha256':'d'*64}
        row={'schema':1,'kind':'actual-public-guest-hello',**plan,'sequence':0,'bootId':'11111111-1111-1111-1111-111111111111','body':{}}
        self.assertEqual(host.validate_observation(row,plan,row['kind'],0),{})
        for key,value in(('challenge','e'*64),('sequence',True),('candidateSource','e'*40),('extra',1)):
            bad={**row,key:value}
            with self.subTest(key=key),self.assertRaises(RuntimeError):host.validate_observation(bad,plan,row['kind'],0)
    def test_checksums_no_duplicate_or_traversal(self):
        raw=('a'*64+' *image\n').encode();self.assertEqual(host.checksum_members(raw),{'image':'a'*64})
        for bad in(raw+raw,('a'*64+' *../image\n').encode(),('a'*64+'  image\n').encode()):
            with self.assertRaises(RuntimeError):host.checksum_members(bad)
    def test_actual_source_pin_fixture_and_change_refusal(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)
            for name in host.SOURCE_FILES:(root/name).write_bytes(b'fixture');(root/name).chmod(0o600)
            file=root/'host.py';manifest=root/'source-manifest.json';manifest.write_bytes(host.canonical({'schema':1,'files':{name:host.sha(b'fixture')for name in host.SOURCE_FILES}}));manifest.chmod(0o600)
            with patch.object(host,'HERE',root):self.assertEqual(host.source_admission()[1]['schema'],1)
            file.write_bytes(b'changed')
            with patch.object(host,'HERE',root),self.assertRaises(RuntimeError):host.source_admission()
    def test_public_file_symlink_hardlink_shared_mode_refused(self):
        with tempfile.TemporaryDirectory()as temp:
            file=Path(temp)/'file';file.write_bytes(b'x');file.chmod(0o600);alias=Path(temp)/'alias';alias.symlink_to(file)
            with self.assertRaises(RuntimeError):host.regular(alias)
            alias.unlink();os.link(file,alias)
            with self.assertRaises(RuntimeError):host.regular(file)
            alias.unlink();file.chmod(0o666)
            with self.assertRaises(RuntimeError):host.regular(file)
    def test_guest_operation_order_rejects_without_command(self):
        with patch.object(guest,'command')as command:
            for operation,args in((guest.exercise,({},'boot',{'phase':'pending-install'})),(guest.after_reboot,({},'boot',{'phase':'awaiting-reboot','beforeBoot':'boot'})),(guest.remove,({}, {'phase':'fresh'}))):
                with self.assertRaises(RuntimeError):operation(*args)
        command.assert_not_called()
    def test_static_state_and_journal_prefix(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);files={'guard.toml':b'publicfixture','risk-paper.jsonl':b'first\n','kill':b'stop\n'}
            for name,raw in files.items():(root/name).write_bytes(raw);(root/name).chmod(0o600)
            with patch.object(guest,'HOME',root),patch.object(guest.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=os.getuid())):
                original=guest.snapshot();(root/'risk-paper.jsonl').write_bytes(b'first\nsecond\n');guest.preserved(original)
                (root/'kill').write_bytes(b'stop\nextra')
                with self.assertRaises(RuntimeError):guest.preserved(original)
    def test_missing_unit_after_removal_requires_no_pid_and_listener(self):
        fake_socket=Mock();fake_socket.__enter__=Mock(return_value=fake_socket);fake_socket.__exit__=Mock(return_value=False);fake_socket.connect_ex.return_value=111
        with patch.object(guest,'command',return_value=b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n'),patch.object(guest.socket,'socket',return_value=fake_socket):guest.stopped(allow_missing=True)
        with patch.object(guest,'command',return_value=b'LoadState=not-found\nActiveState=inactive\nMainPID=12\n'),patch.object(guest.socket,'socket',return_value=fake_socket),self.assertRaises(RuntimeError):guest.stopped(allow_missing=True)
        fake_socket.connect_ex.return_value=0
        with patch.object(guest,'command',return_value=b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n'),patch.object(guest.socket,'socket',return_value=fake_socket),self.assertRaises(RuntimeError):guest.stopped(allow_missing=True)
    def test_vendor_release_exact_three_original_hashes(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);(root/'lists').mkdir();row={'inrelease':{}}
            for name in('noble','noble-updates','noble-security'):
                raw=name.encode();path=root/'lists'/('snapshot_dists_'+name+'_InRelease');path.write_bytes(raw);path.chmod(0o600);row['inrelease'][name]=tools.sha(raw)
            tools.verify_lists(root,row);path.write_bytes(b'different')
            with self.assertRaises(RuntimeError):tools.verify_lists(root,row)
    def test_vendor_apt_sources_isolated_no_insecure_fallback(self):
        argv=tools.options(Path('/fixture'));joined=' '.join(argv)
        self.assertIn('Dir::Etc::sourceparts=-',joined);self.assertIn('Dir::Etc::parts=-',joined);self.assertIn('APT::Get::AllowUnauthenticated=false',joined);self.assertNotIn('=true',joined)
    def test_vendor_child_timeout_kills_group_before_reap(self):
        child=types.SimpleNamespace(pid=123,returncode=0,wait=Mock());order=[];child.wait.side_effect=lambda timeout:order.append('wait')
        with patch.object(tools.subprocess,'Popen',return_value=child),patch.object(tools.os,'waitid',return_value=None,create=True),patch.multiple(tools.os,P_PID=1,WEXITED=4,WNOHANG=1,WNOWAIT=0x1000000,create=True),patch.object(tools.time,'monotonic',side_effect=[0,2]),patch.object(tools.os,'killpg',side_effect=lambda pid,sig:order.append('kill')),self.assertRaises(RuntimeError):tools.run_fixed(['/fixture/apt-get'],1)
        self.assertEqual(order,['kill','wait'])
    def test_all_signed_subject_inventory_is_closed(self):
        row=acquire.candidate();self.assertEqual(len(row['files']),27);self.assertEqual(len(row['provenance_subjects']),24);self.assertEqual(set(row['files'])-set(row['provenance_subjects']),{'SHA256SUMS','SHA256SUMS.sigstore.json','zunder-guard-v1.0.4.intoto.jsonl'})
if __name__=='__main__':unittest.main()
