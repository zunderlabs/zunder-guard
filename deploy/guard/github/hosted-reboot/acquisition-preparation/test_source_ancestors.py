"""Pure ancestor facts from mocked original queries; no root getter execution."""
import ast
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ancestor_getter',HERE/'prepare_runtime.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
spec=importlib.util.spec_from_file_location('ancestor_stdout',HERE/'getter_stdout.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)


OLD_CANONICAL="""    need(directory.is_absolute() and directory.resolve(strict=False)==directory,
         'Canonical fixed protected path required')
"""
NEW_CANONICAL="""    ancestor_context(directory,directory,'canonical','pending')
    canonical_ok=directory.is_absolute() and directory.resolve(strict=False)==directory
    ancestor_context(directory,directory,'canonical','observed','true' if canonical_ok else 'false')
    need(canonical_ok,
         'Canonical fixed protected path required')
"""
OLD_STAT="""        try:s=path.lstat()
        except FileNotFoundError:break
"""
NEW_STAT="""        ancestor_context(directory,path,'lstat','pending','true')
        try:s=path.lstat()
        except FileNotFoundError:
            ancestor_context(directory,path,'lstat','missing','true');break
        ancestor_context(directory,path,'lstat','observed','true',s)
"""
FAILURE_ADDITION="""    if STAGE=='source-ancestors' and SOURCE_ANCESTOR_CONTEXT is not None:
        value['ancestorObservation']=SOURCE_ANCESTOR_CONTEXT.copy()
"""


def normalize_source(source):
    start=source.index('SOURCE_ANCESTOR_CONTEXT = None\n');end=source.index('def protected_ancestors(directory):',start)
    source=source[:start]+source[end:]
    for new,old in ((NEW_CANONICAL,OLD_CANONICAL),(NEW_STAT,OLD_STAT),(FAILURE_ADDITION,'')):
        if source.count(new)!=1:raise ValueError('Finite diagnostic inverse mismatch')
        source=source.replace(new,old)
    return source


def facts(mode=0o40755,uid=0):return SimpleNamespace(st_mode=mode,st_uid=uid)


def failure_record():
    with patch.object(Path,'is_dir',return_value=False),patch.object(g.sys,'stdout',new=io.StringIO())as out:
        g.failure(RuntimeError('secret-example /private/path'))
    raw=out.getvalue().encode();value=e.validate_capture(raw)
    return raw,value


class AncestorFixtures(unittest.TestCase):
    def setUp(self):g.STAGE='source-ancestors';g.SOURCE_ANCESTOR_CONTEXT=None

    def test_whole_getter_exact_inverse_and_guard_ast(self):
        source=(HERE/'prepare_runtime.py').read_text();inverse=normalize_source(source)
        self.assertEqual(hashlib.sha256(inverse.encode()).hexdigest(),'2f4bfeb85b2f97725769cf1b44f3219fbdd25e879b8f39acfacb664257f7fef6')
        original=next(n for n in ast.parse(inverse).body if isinstance(n,ast.FunctionDef)and n.name=='protected_ancestors')
        transformed=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='protected_ancestors')
        transformed.body=[n for n in transformed.body if not(isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='ancestor_context')]
        expression=next(n for n in transformed.body if isinstance(n,ast.Assign)and n.targets[0].id=='canonical_ok')
        transformed.body.remove(expression)
        for n in ast.walk(transformed):
            if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'and isinstance(n.args[0],ast.Name)and n.args[0].id=='canonical_ok':n.args[0]=expression.value
        for n in ast.walk(transformed):
            if isinstance(n,ast.For):
                n.body=[x for x in n.body if not(isinstance(x,ast.Expr)and isinstance(x.value,ast.Call)and isinstance(x.value.func,ast.Name)and x.value.func.id=='ancestor_context')]
                for x in n.body:
                    if isinstance(x,ast.Try):x.handlers[0].body=[ast.Break()]
        self.assertEqual(ast.dump(transformed),ast.dump(original))

    def test_actual_same_stat_observations_type_uid_mode_refusal(self):
        for invalid in (facts(0o40777),facts(uid=1001),facts(0o100644),facts(0o120777),facts(0o20666)):
            seen=[]
            def lstat(path):seen.append(str(path));return facts()if path==Path('/')else invalid
            with patch.object(Path,'resolve',lambda p,**k:p),patch.object(Path,'lstat',lstat):
                with self.assertRaises(RuntimeError):g.protected_ancestors(g.ROOT)
            self.assertEqual(seen,['/','/opt'])
            raw,value=failure_record();observation=value['ancestorObservation']
            self.assertEqual(observation['ancestor'],'opt');self.assertEqual(observation['uid'],invalid.st_uid)
            self.assertEqual(observation['mode'],invalid.st_mode);self.assertEqual(observation['query'],'lstat')
            self.assertNotIn(b'/opt',raw);self.assertNotIn(b'secret-example',raw)

    def test_all_exact_fixed_targets_query_order_no_extra_stats(self):
        targets={g.ROOT:['/','/opt',str(g.ROOT)],g.SOURCE:['/','/opt',str(g.ROOT),str(g.SOURCE)],
                 g.MATERIAL:['/','/opt',str(g.MATERIAL)],g.REPORTS:['/','/run',str(g.REPORTS)],g.WORK:['/','/run',str(g.WORK)]}
        for target,expected in targets.items():
            calls=[]
            def resolve(path,**kwargs):calls.append(('resolve',str(path)));return path
            def lstat(path):calls.append(('lstat',str(path)));return facts()
            with patch.object(Path,'resolve',resolve),patch.object(Path,'lstat',lstat):g.protected_ancestors(target)
            self.assertEqual(calls,[('resolve',str(target))]+[('lstat',p)for p in expected])
            e.validate_ancestor(g.SOURCE_ANCESTOR_CONTEXT)

    def test_canonical_false_no_lstat_and_query_exception_unknown(self):
        with patch.object(Path,'resolve',return_value=Path('/fixed-other')),patch.object(Path,'lstat')as query:
            with self.assertRaises(RuntimeError):g.protected_ancestors(g.ROOT)
            query.assert_not_called()
        self.assertEqual(g.SOURCE_ANCESTOR_CONTEXT['canonical'],'false')
        self.assertEqual(g.SOURCE_ANCESTOR_CONTEXT['result'],'observed');failure_record()
        with patch.object(Path,'resolve',side_effect=OSError('secret-example')):
            with self.assertRaises(OSError):g.protected_ancestors(g.ROOT)
        self.assertEqual(g.SOURCE_ANCESTOR_CONTEXT['canonical'],'unknown')
        self.assertEqual(g.SOURCE_ANCESTOR_CONTEXT['result'],'pending');failure_record()

    def test_missing_break_and_exception_never_reuse_previous_facts(self):
        for error in (FileNotFoundError('secret-example'),OSError('secret-example')):
            with patch.object(Path,'resolve',lambda p,**k:p),patch.object(Path,'lstat',side_effect=[facts(),error])as query:
                if isinstance(error,FileNotFoundError):g.protected_ancestors(g.ROOT)
                else:
                    with self.assertRaises(OSError):g.protected_ancestors(g.ROOT)
                self.assertEqual(query.call_count,2)
            current=g.SOURCE_ANCESTOR_CONTEXT
            self.assertEqual(current['ancestor'],'opt');self.assertIsNone(current['uid']);self.assertIsNone(current['mode'])
            self.assertEqual(current['result'],'missing'if isinstance(error,FileNotFoundError)else 'pending');failure_record()

    def test_unknown_context_path_and_outside_phase_clear(self):
        g.ancestor_context(g.ROOT,Path('/'),'lstat','observed','true',facts());self.assertIsNotNone(g.SOURCE_ANCESTOR_CONTEXT)
        g.ancestor_context(Path('/unknown'),Path('/'),'lstat','observed','true',facts());self.assertIsNone(g.SOURCE_ANCESTOR_CONTEXT)
        g.ancestor_context(g.ROOT,Path('/unknown'),'lstat','pending','true');self.assertIsNone(g.SOURCE_ANCESTOR_CONTEXT)
        g.ancestor_context(g.ROOT,Path('/'),'lstat','observed','true',facts());g.STAGE='source-checkout'
        raw,value=failure_record();self.assertNotIn('ancestorObservation',value)
        g.ancestor_context(g.ROOT,Path('/'),'lstat','pending','true');self.assertIsNone(g.SOURCE_ANCESTOR_CONTEXT)

    def test_uid_mode_numeric_bounds_and_no_boolean_facts(self):
        for mode,uid in ((65536,0),(-1,0),(True,0),(0o40755,True),(0o40755,-1),(0o40755,4294967296)):
            g.ancestor_context(g.ROOT,Path('/opt'),'lstat','observed','true',facts(mode,uid))
            current=g.SOURCE_ANCESTOR_CONTEXT
            self.assertEqual(current['result'],'facts-refused');self.assertIsNone(current['uid']);self.assertIsNone(current['mode']);failure_record()
        for mode,uid in ((0,0),(65535,4294967295),(0o40755,0)):
            g.ancestor_context(g.ROOT,Path('/opt'),'lstat','observed','true',facts(mode,uid));e.validate_ancestor(g.SOURCE_ANCESTOR_CONTEXT)

    def test_hostile_json_closed_grammar_and_same_mode_type(self):
        g.ancestor_context(g.ROOT,Path('/opt'),'lstat','observed','true',facts())
        valid=g.SOURCE_ANCESTOR_CONTEXT.copy()
        changes={'kind':'arbitrary','target':'/opt','ancestor':'secret-example','query':'readlink','result':'pass',
                 'canonical':True,'uid':True,'mode':-1,'fileType':'regular','path':'/private/path'}
        for key,value in changes.items():
            record=valid.copy();record[key]=value
            with self.assertRaises(ValueError):e.validate_ancestor(record)
        for key in valid:
            record=valid.copy();del record[key]
            with self.assertRaises(ValueError):e.validate_ancestor(record)
        record=valid.copy();record.update(target='work',ancestor='opt')
        with self.assertRaises(ValueError):e.validate_ancestor(record)
        record=valid.copy();record.update(query='canonical')
        with self.assertRaises(ValueError):e.validate_ancestor(record)
        outer={'schema':1,'kind':'linux-acquisition-preparation-incomplete','stage':'source-checkout','reason':'guard-refused',
               'privateInput':False,'runtimeAdmitted':False,'releaseReady':False,'ancestorObservation':valid}
        with self.assertRaises(ValueError):e.validate_capture(e.canonical(outer)+b'\n')
        outer['stage']='source-ancestors';e.validate_capture(e.canonical(outer)+b'\n')
        outer['diagnostic']={'operation':'complete-tree','memberSha256':'a'*64}
        with self.assertRaises(ValueError):e.validate_capture(e.canonical(outer)+b'\n')


if __name__=='__main__':unittest.main()
