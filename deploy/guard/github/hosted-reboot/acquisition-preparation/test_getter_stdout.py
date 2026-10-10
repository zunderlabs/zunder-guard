"""Pure inert record/file/workflow tests; the getter is never invoked."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('getter_stdout',HERE/'getter_stdout.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
REPO=HERE.parents[4]
WORKFLOW=REPO/'.github/workflows/hosted-linux-acquisition-branch-preparation.yml'
TEST_LINE='          /usr/bin/python3.12 -I -B deploy/guard/github/hosted-reboot/acquisition-preparation/test_getter_stdout.py\n'
FALLBACK='          if [[ ! -e "$RUNNER_TEMP/acquisition-preparation-inventories/summary.json" && ! -e "$RUNNER_TEMP/acquisition-preparation-inventories/failure.json" ]]; then\n            /usr/bin/python3.12 -I -B deploy/guard/github/hosted-reboot/acquisition-preparation/getter_stdout.py > "$RUNNER_TEMP/acquisition-preparation-inventories/getter-stdout.json"\n          fi\n'


def record(stage='source',diagnostic=False):
    value={'schema':1,'kind':'linux-acquisition-preparation-incomplete','stage':stage,
        'reason':'guard-refused','privateInput':False,'runtimeAdmitted':False,'releaseReady':False}
    if diagnostic:value['diagnostic']={'operation':'protected-member','memberSha256':'a'*64}
    return value


def raw(value):return g.canonical(value)+b'\n'


class GetterStdoutTests(unittest.TestCase):
    def test_closed_stages_reasons_and_late_diagnostics(self):
        for stage in g.STAGES:
            for reason in ('guard-refused','operation-failed'):
                value=record(stage);value['reason']=reason
                self.assertEqual(g.validate_capture(raw(value)),value)
        for stage in g.DIAGNOSTIC_STAGES:
            for operation in ('protected-member','complete-tree'):
                value=record(stage,True);value['diagnostic']['operation']=operation
                self.assertEqual(g.validate_capture(raw(value)),value)

    def test_no_authority_flag_numeric_or_true(self):
        for flag in ('privateInput','runtimeAdmitted','releaseReady'):
            for value in (True,0,1,None,'false',[],{}):
                data=record();data[flag]=value
                with self.assertRaises(ValueError):g.validate_capture(raw(data))
        for value in (True,1.0,'1',None):
            data=record();data['schema']=value
            with self.assertRaises(ValueError):g.validate_capture(raw(data))

    def test_exact_members_and_failure_only(self):
        for key in record():
            data=record();del data[key]
            with self.assertRaises(ValueError):g.validate_capture(raw(data))
        for key in ('exception','path','payload','sourceAdmitted','controlSource'):
            data=record();data[key]='sensitive-example'
            with self.assertRaises(ValueError):g.validate_capture(raw(data))
        for key,value in (('stage','anything'),('stage',[]),('reason','exception-text'),('kind','actual-no-secret-linux-acquisition-preparation')):
            data=record();data[key]=value
            with self.assertRaises(ValueError):g.validate_capture(raw(data))

    def test_canonical_single_ascii_record(self):
        data=raw(record())
        for value in (data[:-1],data+b'\n',data+b'garbage',b' '+data,data+data,
                      json.dumps(record(),indent=2).encode()+b'\n',b'{"schema":1,"schema":1}\n',
                      data.replace(b'"schema":1',b'"schema":NaN'),b'\xff',b'x'*4097,b'',data.decode()):
            with self.assertRaises((ValueError,TypeError)):g.validate_capture(value)

    def test_diagnostic_members_and_stage_exact(self):
        for stage in g.STAGES-g.DIAGNOSTIC_STAGES:
            with self.assertRaises(ValueError):g.validate_capture(raw(record(stage,True)))
        for diagnostic in ({},None,[],{'operation':'unknown','memberSha256':'a'*64},
                           {'operation':'protected-member','memberSha256':'A'*64},
                           {'operation':'protected-member','memberSha256':'a'*63},
                           {'operation':'protected-member','memberSha256':'a'*64,'path':'sensitive-example'}):
            data=record('reports');data['diagnostic']=diagnostic
            with self.assertRaises(ValueError):g.validate_capture(raw(data))
        duplicate=raw(record('reports',True)).replace(b'"operation":"protected-member"',b'"operation":"protected-member","operation":"protected-member"')
        with self.assertRaises(ValueError):g.validate_capture(duplicate)

    def test_original_getter_stage_and_context_grammar(self):
        source=(HERE/'prepare_runtime.py').read_text();tree=ast.parse(source)
        node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name)and t.id=='STAGES'for t in n.targets))
        original=set(ast.literal_eval(node.value.args[0]));self.assertEqual(g.STAGES,original|{'unknown'})
        self.assertIn("'reason':reason,'privateInput':False,'runtimeAdmitted':False,'releaseReady':False",source)
        self.assertIn("CONTEXT={'operation':operation,'memberSha256':digest(name.encode())}",(HERE/'runtime_maps.py').read_text())

    def test_regular_fixed_capture(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as directory:
            path=Path(directory)/g.CAPTURE;path.write_bytes(raw(record()));path.chmod(0o600)
            self.assertEqual(g.export_capture(directory),record())
            self.assertFalse((Path(directory)/g.OUTPUT).exists())

    def test_missing_and_refused_are_closed_private(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as directory:
            self.assertEqual(g.export_capture(directory),g.refused('capture-unavailable'))
            path=Path(directory)/g.CAPTURE
            for content in (b'sensitive-example /private/path secret',b'x'*4097,b'[[]]\n',b'['*2000+b']'*2000):
                path.write_bytes(content);path.chmod(0o600)
                value=g.export_capture(directory);self.assertEqual(value,g.refused('capture-refused'))
                output=g.canonical(value);self.assertNotIn(b'sensitive-example',output);self.assertNotIn(b'/private',output)
                self.assertTrue(all(value[name]is False for name in g.FLAGS))

    def test_symlink_hardlink_fifo_permissions_refuse(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as directory:
            root=Path(directory);path=root/g.CAPTURE;other=root/'other';other.write_bytes(raw(record()))
            path.symlink_to(other);self.assertEqual(g.export_capture(directory),g.refused('capture-refused'));path.unlink()
            os.link(other,path);self.assertEqual(g.export_capture(directory),g.refused('capture-refused'));path.unlink()
            os.mkfifo(path);self.assertEqual(g.export_capture(directory),g.refused('capture-refused'));path.unlink()
            path.write_bytes(raw(record()));path.chmod(0o666);self.assertEqual(g.export_capture(directory),g.refused('capture-refused'))
            with patch.object(g.os,'geteuid',return_value=os.geteuid()+1):
                self.assertEqual(g.export_capture(directory),g.refused('capture-refused'))

    def test_changed_capture_and_replaced_name_refuse_close(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as directory:
            path=Path(directory)/g.CAPTURE;path.write_bytes(raw(record()));path.chmod(0o600)
            read=os.read;close=os.close
            def mutation(fd,size):
                data=read(fd,size);path.write_bytes(raw(record('arguments')));return data
            with patch.object(g.os,'read',side_effect=mutation),patch.object(g.os,'close',wraps=close)as closed:
                self.assertEqual(g.export_capture(directory),g.refused('capture-refused'));closed.assert_called_once()
            path.write_bytes(raw(record()))
            def replacement(fd,size):
                data=read(fd,size);path.unlink();path.write_bytes(data);return data
            with patch.object(g.os,'read',side_effect=replacement):
                self.assertEqual(g.export_capture(directory),g.refused('capture-refused'))

    def test_relative_noncanonical_loop_and_argument_paths_refuse(self):
        self.assertEqual(g.export_capture('.'),g.refused('capture-refused'))
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as directory:
            link=Path(directory)/'link';link.symlink_to(directory)
            self.assertEqual(g.export_capture(str(link)),g.refused('capture-refused'))
            with patch.object(g.Path,'resolve',side_effect=RuntimeError('sensitive-example')):
                self.assertEqual(g.export_capture(directory),g.refused('capture-refused'))

    def test_cli_fixed_capture_and_no_argument_echo(self):
        import io
        class Stdout:
            def __init__(self):self.buffer=io.BytesIO()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as directory:
            path=Path(directory)/g.CAPTURE;path.write_bytes(raw(record()));path.chmod(0o600)
            for args,env,expected in ((['getter_stdout.py'],{'RUNNER_TEMP':directory},record()),
                                     (['getter_stdout.py','sensitive-example'],{'RUNNER_TEMP':directory},g.refused('capture-refused')),
                                     (['getter_stdout.py'],{},g.refused('capture-refused'))):
                stdout=Stdout()
                with patch.object(g.sys,'argv',args),patch.object(g.sys,'stdout',stdout),patch.dict(g.os.environ,env,clear=True):
                    self.assertEqual(g.main(),0)
                self.assertEqual(stdout.buffer.getvalue(),raw(expected))
                self.assertNotIn(b'sensitive-example',stdout.buffer.getvalue())

    def test_exact_workflow_inverse_and_precedence(self):
        source=WORKFLOW.read_text();self.assertEqual(source.count(TEST_LINE),1);self.assertEqual(source.count(FALLBACK),1)
        old=source.replace(TEST_LINE,'').replace(FALLBACK,'')
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(),'adc58315bac911c6ae8158281a6642780de1b082a9f2f745b2fc5915d03cac17')
        self.assertLess(source.index('for name in summary failure'),source.index(FALLBACK))
        self.assertLess(source.index(FALLBACK),source.index('branch_observation.py "$OBSERVED_SOURCE"'))
        self.assertNotIn('sudo ',FALLBACK);self.assertNotIn('cat ',FALLBACK)
        for summary in (False,True):
            for failure in (False,True):
                self.assertEqual(not summary and not failure,not(summary or failure))

    def test_all_existing_getter_maps_support_and_tools_unchanged(self):
        pins={
            HERE/'prepare_runtime.py':'2f4bfeb85b2f97725769cf1b44f3219fbdd25e879b8f39acfacb664257f7fef6',
            HERE/'runtime_maps.py':'cce8160f30b2aa86cab06342e20bb222aa5f0a796e64b9cb811ea11da51d97f2',
            HERE/'test_runtime_preparation.py':'ff8af8b455dee74c1b353de94fdd4982c4f649171f102cfbd3546b86ede9aa62',
            HERE/'branch_observation.py':'9a4a167dc081871cfcf5c02c8f8656c1f990cf9cc0907663425c1be6ee06074a',
            HERE.parent/'fixed-acquisition-stage.py':'539dbd0feaab3ad235a3fb5484b8f6f2ea1bf813cf5ed526868d94555523d421',
            REPO/'.github/workflows/hosted-linux-acquisition-runtime-preparation.yml':'36f72e9f8f50f2af9658371313427b7dc3266df40194229ee80b4be4f0498bcb'}
        for path,expected in pins.items():self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),expected)


if __name__=='__main__':unittest.main()
