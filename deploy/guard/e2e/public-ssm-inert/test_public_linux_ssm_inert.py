"""Inert author validation: no real download, compiler, SDK, seccomp or Go execution."""
import io
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import public_linux_ssm_inert as candidate


def archive(path, rows):
    with tarfile.open(path,'w:gz') as out:
        for name,kind,data in rows:
            info=tarfile.TarInfo(name);info.type=kind;info.mode=0o755
            info.size=len(data) if kind==tarfile.REGTYPE else 0
            out.addfile(info,io.BytesIO(data) if info.isfile() else None)


class Tests(unittest.TestCase):
    def test_exact_candidate_files_and_all_inert_test_names(self):
        root=Path(__file__).parent/'candidate'
        for name,sha in candidate.FILES.items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),sha)
        import re
        raw=(root/'native_ssm_fd_test.go').read_text()
        self.assertEqual(tuple(re.findall(r'^func (Test\w+)\(',raw,re.M)),candidate.TESTS)
        self.assertNotIn('func TestMain(',raw)
        self.assertNotIn('net.Dial(',raw)
        self.assertNotIn('http.Get(',raw)

    def test_primary_linux_compiler_row(self):
        self.assertEqual(candidate.GO['size'],70590635)
        self.assertEqual(candidate.GO['sha256'],'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5')
        self.assertEqual(candidate.GO['host'],'dl.google.com')
        self.assertNotIn('darwin',candidate.GO['path'])

    def test_safe_regular_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive(root/'a.tar.gz',[('prefix/',tarfile.DIRTYPE,b''),('prefix/bin/tool',tarfile.REGTYPE,b'public')])
            receipt=candidate.safe_extract(root/'a.tar.gz',root/'out','prefix',candidate.OriginalBudget(),executable=True)
            self.assertEqual((root/'out/bin/tool').read_bytes(),b'public')
            self.assertEqual(receipt['files'],1)
            self.assertEqual(receipt['logical_bytes'],6)
            self.assertEqual((root/'out/bin/tool').stat().st_mode&0o777,0o700)

    def test_archive_refuses_traversal_links_devices_duplicates(self):
        cases=[ [('prefix/../outside',tarfile.REGTYPE,b'x')], [('/prefix/x',tarfile.REGTYPE,b'x')],
               [('prefix/link',tarfile.SYMTYPE,b'')], [('prefix/link',tarfile.LNKTYPE,b'')],
               [('prefix/dev',tarfile.CHRTYPE,b'')], [('prefix/a',tarfile.REGTYPE,b'x'),('prefix/a',tarfile.REGTYPE,b'y')],
               [('wrong/a',tarfile.REGTYPE,b'x')], [('prefix\\a',tarfile.REGTYPE,b'x')]]
        for rows in cases:
            with self.subTest(rows=rows),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);archive(root/'a.tar.gz',rows)
                with self.assertRaises(RuntimeError):candidate.safe_extract(root/'a.tar.gz',root/'out','prefix',candidate.OriginalBudget())

    def test_archive_caps_are_original(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive(root/'a.tar.gz',[('prefix/a',tarfile.REGTYPE,b'xx')])
            with self.assertRaises(RuntimeError):candidate.safe_extract(root/'a.tar.gz',root/'out','prefix',candidate.OriginalBudget(),max_bytes=1)
        with patch.object(candidate.time,'time',return_value=100),patch.object(candidate.time,'monotonic',return_value=100):
            b=candidate.OriginalBudget(1)
        with patch.object(candidate.time,'time',return_value=101),patch.object(candidate.time,'monotonic',return_value=100):
            with self.assertRaises(RuntimeError):b.remaining()
        with patch.object(candidate.time,'time',return_value=100),patch.object(candidate.time,'monotonic',return_value=101):
            with self.assertRaises(RuntimeError):b.remaining()

    def test_socket_seccomp_public_instruction_simulation(self):
        def result(arch,syscall):
            acc=0;index=0;rows=candidate.seccomp_rows()
            while True:
                code,jt,jf,k=rows[index]
                if code==0x20:acc=arch if k==4 else syscall
                elif code==0x15:index+=jt if acc==k else jf
                elif code==0x45:index+=jt if acc&k else jf
                elif code==0x06:return k
                else:self.fail('Unknown BPF opcode')
                index+=1
        for syscall in (41,53):self.assertEqual(result(0xc000003e,syscall),0x0005000d)
        self.assertEqual(result(0xc000003e,1),0x7fff0000)
        self.assertEqual(result(0x40000003,41),0x80000000)
        self.assertEqual(result(0xc000003e,41|0x40000000),0x80000000)

    def assert_no_live_child(self, pid):
        try:
            os.kill(pid,0)
        except ProcessLookupError:
            return
        # A non-running orphan zombie can await the host init reaper briefly.
        # run_owned itself requires the whole original group to disappear.
        state=subprocess.run(['/bin/ps','-o','stat=','-p',str(pid)],capture_output=True,text=True,check=False).stdout.strip()
        self.assertTrue(not state or state.startswith('Z'), 'Owned descendant survived command return')

    def run_exited_parent_fixture(self, exitcode, *, sleeper=False):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);log=root/'public.log';pid=None
            script="""import os,sys,time
pid=os.fork()
if pid==0:
    os.close(0);os.close(1);os.close(2)
    time.sleep(10)
    os._exit(0)
print(pid,flush=True)
if sys.argv[2]=='sleep':time.sleep(10)
os._exit(int(sys.argv[1]))
"""
            budget=candidate.OriginalBudget(5)
            started,until,end=budget.started_ms,budget.until_ms,budget.end
            try:
                words=[sys.executable,'-I','-B','-c',script,str(exitcode),'sleep' if sleeper else 'exit']
                if exitcode or sleeper:
                    with self.assertRaises(RuntimeError):
                        candidate.run_owned(words,{'PATH':'/usr/bin:/bin'},root,log,budget,maximum=.3 if sleeper else 2)
                else:
                    output=candidate.run_owned(words,{'PATH':'/usr/bin:/bin'},root,log,budget,maximum=2)
                    self.assertEqual(output,log.read_bytes())
                pid=int(log.read_bytes().strip())
                self.assert_no_live_child(pid)
                self.assertEqual((budget.started_ms,budget.until_ms,budget.end),(started,until,end))
            finally:
                # Only this public fixture's known still-live descendant on a
                # regression; never discover or signal unrelated processes.
                if pid is None and log.exists():
                    raw=log.read_bytes().strip()
                    if raw.isdigit():pid=int(raw)
                if pid is not None:
                    try:os.kill(pid,0)
                    except ProcessLookupError:pass
                    else:
                        state=subprocess.run(['/bin/ps','-o','stat=','-p',str(pid)],capture_output=True,text=True,check=False).stdout.strip()
                        if state and not state.startswith('Z'):os.kill(pid,signal.SIGKILL)

    def test_exited_successful_parent_never_leaves_owned_descendant(self):
        self.run_exited_parent_fixture(0)

    def test_exited_failed_parent_never_leaves_owned_descendant(self):
        self.run_exited_parent_fixture(7)

    def test_original_command_deadline_kills_owned_group(self):
        self.run_exited_parent_fixture(0,sleeper=True)

    def test_download_does_not_follow_redirects(self):
        class Response:
            status=302
            def getheader(self,name):return None
        class Connection:
            def __init__(self,*a,**kw):pass
            def request(self,*a,**kw):pass
            def getresponse(self):return Response()
            def close(self):pass
        with tempfile.TemporaryDirectory() as temp,patch.object(candidate.http.client,'HTTPSConnection',Connection):
            with self.assertRaises(RuntimeError):candidate.fixed_download(candidate.SDK,Path(temp)/'refused',candidate.OriginalBudget())


if __name__=='__main__':unittest.main()
