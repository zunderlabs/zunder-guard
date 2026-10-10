"""Inert SOURCE traces and exact inverse; no getter/root/git execution."""
import ast
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('source_stage_getter',HERE/'prepare_runtime.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
spec=importlib.util.spec_from_file_location('source_stage_stdout',HERE/'getter_stdout.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
LABELS=('source-ancestors','source-checkout','source-head-clean','source-archive','source-fresh',
    'source-materialize','source-verify','source-manifest','source-protect','source-reexec')
ADDED_VOCAB="\n 'source-ancestors','source-checkout','source-head-clean','source-archive','source-fresh',\n 'source-materialize','source-verify','source-manifest','source-protect','source-reexec',\n "


class Refusal(Exception):pass


class SourceStages(unittest.TestCase):
    def trace(self,fail=None,head_ok=True,clean=True):
        events=[];commit='a'*40;workspace=Path('/fixed/inert/checkout')
        required=set(g.DEPENDENCIES)|set(g.VERIFIERS)|{g.PUBLIC_ENTRY+'prepare_runtime.py',g.PUBLIC_ENTRY+'runtime_maps.py'}
        blobs={name:name.encode()for name in required}
        hashes={blobs[name]:g.DEPENDENCIES.get(name)or(g.VERIFIERS[name][1]if name in g.VERIFIERS else 'b'*64)for name in required}
        source_blob=blobs[g.PUBLIC_ENTRY+'prepare_runtime.py']
        class Archive:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def __iter__(self):
                for name in sorted(required):
                    yield SimpleNamespace(name=name,size=len(blobs[name]),mode=0o644,isfile=lambda:True,isdir=lambda:False)
            def extractfile(self,member):return io.BytesIO(blobs[member.name])
        def event(name):
            events.append((name,g.STAGE))
            if name==fail:raise RuntimeError('sensitive-example /private/path')
        guards=0
        def guard():
            nonlocal guards
            guards+=1;event('ancestors-'+str(guards))
        def command(argv,**kwargs):
            if 'rev-parse'in argv:event('head');return(commit if head_ok else 'f'*40).encode()+b'\n'
            if 'status'in argv:event('clean');return b''if clean else b' M source-file\n'
            if 'archive'in argv:event('archive');return b'inert-tar'
            raise AssertionError('Unexpected mocked command')
        def exists(path):event('exists');return fail=='fresh'
        def resolve(path,**kwargs):event('checkout');return path
        def mkdir(path,**kwargs):event('mkdir')
        def exclusive(path,data,*args):event('manifest'if path.name=='original-source.json'else 'member')
        def protect(path):event('protect')
        def reexec(*args):event('reexec');raise Refusal()
        def digest(data):return hashes.get(data,'c'*64)
        patches=[patch.object(g,'guard_fixed_paths',side_effect=guard),patch.object(g,'command',side_effect=command),
            patch.object(Path,'resolve',resolve),patch.object(Path,'exists',exists),patch.object(Path,'mkdir',mkdir),
            patch.object(Path,'read_bytes',return_value=source_blob),patch.object(g,'exclusive',side_effect=exclusive),
            patch.object(g,'protect_simple',side_effect=protect),patch.object(g,'checked_reexec',side_effect=reexec),
            patch.object(g,'digest',side_effect=digest),patch.object(g.tarfile,'open',return_value=Archive())]
        if fail=='verify':patches.append(patch.object(g,'destination',return_value=None))
        with contextlib.ExitStack()as stack:
            for item in patches:stack.enter_context(item)
            try:g.stage_source(str(workspace),commit)
            except(RuntimeError,Refusal):pass
            else:raise AssertionError('Mocked reexec/refusal was required')
        return events,g.STAGE

    def test_exact_full_source_inverse_and_ast(self):
        source=(HERE/'prepare_runtime.py').read_text()
        inverse_spec=importlib.util.spec_from_file_location('ancestor_inverse',HERE/'test_source_ancestors.py')
        inverse_module=importlib.util.module_from_spec(inverse_spec);inverse_spec.loader.exec_module(inverse_module)
        source=inverse_module.normalize_source(source)
        self.assertEqual(source.count(ADDED_VOCAB),1)
        inverse=source.replace(ADDED_VOCAB,'')
        for label in LABELS:
            line="    STAGE='"+label+"'\n"
            self.assertEqual(inverse.count(line),2 if label=='source-ancestors'else 1)
            inverse=inverse.replace(line,'')
        expected='582c8b4a21c9b5c765afda960510334d65474d8d794226d81251c58fbe6901f1'
        self.assertEqual(hashlib.sha256(inverse.encode()).hexdigest(),expected)
        function=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='stage_source')
        original=next(n for n in ast.parse(inverse).body if isinstance(n,ast.FunctionDef)and n.name=='stage_source')
        function.body=[n for n in function.body if not(isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='STAGE'and isinstance(n.value,ast.Constant)and n.value.value in LABELS)]
        self.assertEqual(ast.dump(function),ast.dump(original))

    def test_each_existing_refusal_has_exact_closed_label(self):
        cases={'ancestors-1':'source-ancestors','checkout':'source-checkout','head':'source-head-clean',
            'clean':'source-head-clean','archive':'source-archive','fresh':'source-fresh','ancestors-2':'source-ancestors',
            'mkdir':'source-materialize','member':'source-materialize','verify':'source-verify',
            'manifest':'source-manifest','protect':'source-protect','reexec':'source-reexec'}
        for operation,expected in cases.items():
            with self.subTest(operation=operation):
                events,stage=self.trace(fail=operation);self.assertEqual(stage,expected)
                if operation not in ('verify','fresh'):self.assertEqual(events[-1],(operation,expected))

    def test_original_head_short_circuit_and_query_order(self):
        events,stage=self.trace(head_ok=False)
        self.assertEqual([name for name,label in events],['ancestors-1','checkout','head'])
        self.assertEqual(stage,'source-head-clean')
        events,stage=self.trace(clean=False)
        self.assertEqual([name for name,label in events],['ancestors-1','checkout','head','clean'])
        self.assertEqual(stage,'source-head-clean')
        events,stage=self.trace()
        names=[name for name,label in events]
        self.assertEqual(names[:9],['ancestors-1','checkout','head','clean','archive','exists','exists','exists','exists'])
        self.assertEqual(names[9:13],['ancestors-2','mkdir','mkdir','mkdir'])
        self.assertEqual(names[-3:],['manifest','protect','reexec'])
        self.assertEqual(stage,'source-reexec')

    def test_freshness_original_short_circuit_before_mkdir(self):
        events,stage=self.trace(fail='fresh');names=[name for name,label in events]
        self.assertEqual(names.count('exists'),1);self.assertNotIn('mkdir',names)
        self.assertEqual(stage,'source-fresh')

    def test_all_new_labels_emit_only_original_failure_fields(self):
        for stage in LABELS:
            with patch.object(g,'STAGE',stage),patch.object(Path,'is_dir',return_value=False),patch.object(g.sys,'stdout',new=io.StringIO())as out:
                g.failure(RuntimeError('sensitive-example /private/path'))
                raw=out.getvalue().encode();value=e.validate_capture(raw)
                self.assertEqual(value['stage'],stage);self.assertEqual(value['reason'],'guard-refused')
                self.assertNotIn(b'sensitive-example',raw);self.assertNotIn(b'/private/path',raw)
                self.assertEqual(set(value),{'schema','kind','stage','reason','privateInput','runtimeAdmitted','releaseReady'})
                self.assertTrue(all(value[name]is False for name in ('privateInput','runtimeAdmitted','releaseReady')))

    def test_no_new_path_payload_or_capability_vocabulary(self):
        self.assertTrue(set(LABELS)<=g.STAGES)
        self.assertEqual(e.STAGES,g.STAGES|{'unknown'})
        value={'schema':1,'kind':'linux-acquisition-preparation-incomplete','stage':'source-head',
            'reason':'guard-refused','privateInput':False,'runtimeAdmitted':False,'releaseReady':False}
        with self.assertRaises(ValueError):e.validate_capture(e.canonical(value)+b'\n')
        for stage in LABELS:
            value['stage']=stage;value['diagnostic']={'operation':'protected-member','memberSha256':'a'*64}
            with self.assertRaises(ValueError):e.validate_capture(e.canonical(value)+b'\n')


if __name__=='__main__':unittest.main()
