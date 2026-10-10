"""Inert inventory contexts only: no vendor/provider/runtime/private execution."""
import ast
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from . import bootstrap as p


class InventoryDiagnostic(unittest.TestCase):
    def setUp(self):
        self.stage = p._STAGE; self.context = p._INVENTORY_CONTEXT
        p._STAGE = 'inventories'; p.inventory_context()
        self.addCleanup(self.restore)
    def restore(self):
        p._STAGE = self.stage; p._INVENTORY_CONTEXT = self.context
    def diagnostic(self, error):return p.inventory_failure_diagnostic(p._INVENTORY_CONTEXT, error)
    def test_closed_errors_never_evaluate_text_or_export_paths_payloads_or_class_names(self):
        class SecretError(Exception):
            def __str__(self):raise AssertionError('Exception text must not be inspected')
        errors = [(FileNotFoundError, 'member-missing'), (PermissionError, 'permission-refused'),
                  (FileExistsError, 'already-exists'), (RuntimeError, 'guard-refused'),
                  (OSError, 'os-operation-failed'), (SecretError, 'operation-failed')]
        member = '/private/secret-name?payload=hidden\nsecret'
        for cls, reason in errors:
            p.inventory_context('tool-read', member=member, index=2, count=3)
            value = self.diagnostic(cls('hidden private payload'))
            self.assertEqual(value['reason'], reason)
            self.assertEqual(value['errorType'], 'other' if cls is SecretError else cls.__name__)
            self.assertEqual(value['memberSha256'], p.digest(member.encode()))
            self.assertEqual((value['index'], value['count']), (2, 3))
            self.assertNotIn('hidden', json.dumps(value)); self.assertNotIn('/private', json.dumps(value))
            self.assertNotIn('SecretError', json.dumps(value))
        value = self.diagnostic(p.subprocess.TimeoutExpired(['/private/command'], 5, output=b'private-output'))
        self.assertEqual(value['reason'], 'operation-timeout'); self.assertNotIn('private', json.dumps(value))
    def test_bounds_unknown_fields_and_context_clear_outside_inventory(self):
        for member in (None, '', 'x'*4097):
            p.inventory_context('native-ldd', member=member, index=True, count=100001)
            self.assertEqual(self.diagnostic(RuntimeError('secret')), {'operation':'native-ldd', 'errorType':'RuntimeError', 'reason':'guard-refused'})
        for context in ({'operation':'unlisted'}, {'operation':'source-tree','path':'hidden'},
                        {'operation':'tool-read','memberSha256':'not-hash'},
                        {'operation':'tool-read','index':True,'count':2}):
            with self.assertRaises(RuntimeError):p.inventory_failure_diagnostic(context, RuntimeError('secret'))
        self.assertIsNone(p.inventory_failure_diagnostic(None, RuntimeError('secret')))
        p.inventory_context('source-tree');p.inventory_context();self.assertIsNone(p._INVENTORY_CONTEXT)
        p.inventory_context('source-tree');p._STAGE='protect';p.inventory_context('tool-read',member='/secret')
        self.assertIsNone(p._INVENTORY_CONTEXT)
    def runtime(self, fail=None):
        tree_calls=[];read_calls=[];ldd_calls=[]
        def tree(root):
            tree_calls.append(str(root))
            if p._INVENTORY_CONTEXT['operation']==fail:raise PermissionError('/hidden/tree secret')
            return {'schema':1,'files':{'m.so':'a'*64,'doc.txt':'b'*64}}
        def read(path):
            read_calls.append(str(path))
            if p._INVENTORY_CONTEXT['operation']==fail:raise RuntimeError('/hidden/member secret')
            return b'fixed-bytes'
        def resolve(path,strict=False):
            if p._INVENTORY_CONTEXT['operation']==fail:raise FileNotFoundError('/hidden/resolve secret')
            return path
        def ldd(argv,**kwargs):
            ldd_calls.append(argv)
            if fail=='native-ldd':raise p.subprocess.TimeoutExpired(argv,5,output=b'private-ldd')
            return SimpleNamespace(stdout=b'libdep => /known/libdep.so (0x123)\n',returncode=0)
        def maps(path):
            self.assertEqual(str(path),'/proc/self/maps')
            if fail=='proc-maps-read':raise OSError('hidden maps')
            return '1-2 r-xp 0 00:00 1 /known/mapped.so'+(' (deleted)'if fail=='proc-map-member'else'')+'\n'
        with patch.object(p,'tree',side_effect=tree),patch.object(p,'read',side_effect=read),\
             patch.object(p.Path,'resolve',resolve),patch.object(p.Path,'read_text',maps),\
             patch.object(p.subprocess,'run',side_effect=ldd),patch.object(p,'TOOLS_PATHS',{'systemctl':'/usr/bin/systemctl'}):
            value=p.runtime_observation(Path('/fixed/node'),Path('/fixed/packages'))
        return value,tree_calls,read_calls,ldd_calls
    def test_runtime_positive_exact_original_calls_output_and_success_clear(self):
        value,trees,reads,ldd=self.runtime()
        roots={'python':str(p.ROOT/'runtime/python'),'node':'/fixed/node','packages':'/fixed/packages'}
        expected={str(Path(root)/name):digest for root in [*roots.values(),str(p.CHECKOUT)]for name,digest in [('m.so','a'*64),('doc.txt','b'*64)]}
        tools={'systemctl':'/usr/bin/systemctl','python':str(p.ROOT/'runtime/python/bin/python3.12'),'node':'/fixed/node/bin/node'}
        for name in ['/usr/bin/git',*tools.values(),'/known/libdep.so','/known/mapped.so']:expected[name]=p.digest(b'fixed-bytes')
        self.assertEqual(value,{'schema':1,'files':dict(sorted(expected.items())),'roots':roots,
            'tools':{name:{'file':file,'sha256':p.digest(b'fixed-bytes')}for name,file in tools.items()},
            'missingTools':['cosign','slsa-verifier','chromium'],'completePrivateRuntime':False,
            'observedNativeFiles':sorted(set(expected))})
        self.assertEqual(trees,[*roots.values(),str(p.CHECKOUT)])
        native=sorted({'/usr/bin/git',*tools.values(),*(str(Path(root)/'m.so')for root in [*roots.values(),str(p.CHECKOUT)])})
        self.assertEqual([argv for argv in ldd],[['/usr/bin/ldd',file]for file in native])
        self.assertEqual(reads,['/usr/bin/git',*tools.values(),*(['/known/libdep.so']*len(native)),'/known/mapped.so'])
        self.assertIsNone(p._INVENTORY_CONTEXT)
    def test_each_original_runtime_operation_failure_keeps_only_its_context(self):
        operations=['runtime-python-tree','runtime-node-tree','runtime-packages-tree','checkout-tree',
                    'git-resolve','git-read','tool-resolve','tool-read','native-ldd',
                    'native-dependency-resolve','native-dependency-read','proc-maps-read','proc-map-member']
        for operation in operations:
            with self.subTest(operation=operation):
                p.inventory_context()
                with self.assertRaises((RuntimeError,OSError,p.subprocess.TimeoutExpired)):self.runtime(operation)
                value=self.diagnostic(RuntimeError('/hidden secret'))
                self.assertEqual(value['operation'],operation)
                self.assertNotIn('/hidden',json.dumps(value));self.assertNotIn('secret',json.dumps(value))
                if operation.endswith('-tree')or operation=='proc-maps-read':self.assertNotIn('memberSha256',value)
    def prepare(self,fail=None):
        with tempfile.TemporaryDirectory()as td,ExitStack()as stack:
            root=Path(td)/'root';public=Path(td)/'public';selected=root/'runtime/website/source';writes=[];trees=[]
            for name,value in [('ROOT',root),('PUBLIC',public),('SOURCE',root/'source'),('CHECKOUT',root/'checkout'),('WEBSITE',selected)]:stack.enter_context(patch.object(p,name,value))
            stack.enter_context(patch.object(p.os,'geteuid',return_value=0));stack.enter_context(patch.object(p,'capabilities',return_value={}))
            stack.enter_context(patch.object(p,'preparation_ancestors'))  # inert fixture paths, never host admission
            stack.enter_context(patch.object(p,'source',return_value={}))
            def node(): (root/'runtime/node').mkdir(parents=True);return {}
            stack.enter_context(patch.object(p,'node',side_effect=node));stack.enter_context(patch.object(p,'website',return_value={}))
            stack.enter_context(patch.object(p,'command',return_value=b''));stack.enter_context(patch.object(p,'regularize_bin',return_value=[]))
            def python_runtime(): (root/'runtime/python/lib/python3.12').mkdir(parents=True);return []
            stack.enter_context(patch.object(p,'python_runtime',side_effect=python_runtime));stack.enter_context(patch.object(p,'protect'))
            stack.enter_context(patch.object(p,'runtime_observation',return_value={'schema':1,'files':{}}))
            def tree(path):
                trees.append(path)
                if p._INVENTORY_CONTEXT['operation']==fail:raise RuntimeError('hidden tree secret')
                return {'schema':1,'files':{'file':'a'*64}}
            def write(path,value,mode):
                writes.append((path,value,mode))
                if p._INVENTORY_CONTEXT['operation']==fail:raise OSError('hidden report secret')
                return {'file':str(path),'sha256':'c'*64}
            stack.enter_context(patch.object(p,'tree',side_effect=tree));stack.enter_context(patch.object(p,'write_new',side_effect=write))
            value=p.prepare('/inert-workspace','a'*40)
            return value,trees,writes
    def test_prepare_positive_same_reports_flags_and_context_clear(self):
        value,trees,writes=self.prepare()
        self.assertEqual(len(trees),3);self.assertEqual(len(writes),5)
        self.assertEqual([path.name for path,_,_ in writes],['source-inventory.json','website-inventory.json','runtime-inventory.json','python-packages-inventory.json','preparation.json'])
        result=writes[-1][1]
        for name in ('privateInput','providerRolesAssumed','venueOrders','nativeAcceptance','fullJourney','releaseReady'):self.assertIs(result[name],False)
        self.assertTrue(all(mode==0o444 for _,_,mode in writes));self.assertEqual(value['sha256'],'c'*64)
        self.assertIsNone(p._INVENTORY_CONTEXT)
    def test_source_website_packages_and_protected_report_failure_context(self):
        for operation in ('source-tree','website-tree','python-packages-tree','inventory-report-write','preparation-report-write'):
            with self.subTest(operation=operation):
                with self.assertRaises((RuntimeError,OSError)):self.prepare(operation)
                value=self.diagnostic(RuntimeError('hidden report payload'))
                self.assertEqual(value['operation'],operation);self.assertNotIn('hidden',json.dumps(value))
                if operation=='inventory-report-write':self.assertEqual((value['index'],value['count']),(0,4))
                else:self.assertNotIn('index',value)
    def test_main_inventory_failure_uses_closed_receipt_and_clears_before_write(self):
        with tempfile.TemporaryDirectory()as td:
            public=Path(td);(public/'reports').mkdir();writes=[]
            def fail(*_):p._STAGE='inventories';p.inventory_context('tool-read',member='/hidden/secret',index=0,count=3);raise PermissionError('private payload')
            def write(path,value,mode):self.assertIsNone(p._INVENTORY_CONTEXT);writes.append((path,value,mode))
            with patch.object(p,'PUBLIC',public),patch.object(p,'prepare',side_effect=fail),patch.object(p,'write_new',side_effect=write),\
                 patch.object(p.sys,'argv',['bootstrap','--workspace','/inert','--control-source','a'*40]):
                with self.assertRaises(SystemExit):p.main()
            self.assertEqual(len(writes),1);self.assertEqual(writes[0][0].name,'failure.json')
            self.assertEqual(writes[0][1]['diagnostic']['reason'],'permission-refused');self.assertNotIn('hidden',json.dumps(writes[0][1]));self.assertNotIn('payload',json.dumps(writes[0][1]))
    def test_main_outside_inventories_emits_no_stale_diagnostic(self):
        with tempfile.TemporaryDirectory()as td:
            public=Path(td);(public/'reports').mkdir();writes=[]
            def fail(*_):p.inventory_context('source-tree');p._STAGE='protect';raise RuntimeError('secret')
            with patch.object(p,'PUBLIC',public),patch.object(p,'prepare',side_effect=fail),patch.object(p,'write_new',side_effect=lambda path,value,mode:writes.append(value)),\
                 patch.object(p.sys,'argv',['bootstrap','--workspace','/inert','--control-source','a'*40]):
                with self.assertRaises(SystemExit):p.main()
            self.assertNotIn('diagnostic',writes[0]);self.assertIsNone(p._INVENTORY_CONTEXT)
    def test_context_helpers_never_touch_members_rescan_or_stringify_errors(self):
        source=ast.parse(Path(p.__file__).read_text())
        for name in ('inventory_context','inventory_failure_diagnostic'):
            function=next(n for n in source.body if isinstance(n,ast.FunctionDef)and n.name==name)
            calls=[ast.unparse(n.func)for n in ast.walk(function)if isinstance(n,ast.Call)]
            self.assertFalse(any(call in ('read','tree','write_new','str','repr','subprocess.run')or call.endswith(('.resolve','.stat','.lstat','.read_text','.rglob'))for call in calls))


class InventoryGuardReason(unittest.TestCase):
    def diagnostic(self,error):
        return p.inventory_failure_diagnostic({'operation':'source-tree'},error)
    def test_every_fixed_original_guard_maps_to_only_its_closed_code(self):
        for message,code in p._INVENTORY_GUARD_REASONS.items():
            with self.subTest(code=code):
                actual=self.diagnostic(RuntimeError(message))
                self.assertEqual(actual,{'operation':'source-tree','errorType':'RuntimeError','reason':'guard-refused','guardReason':code})
                self.assertNotIn(message,json.dumps(actual))
    def test_unknown_suffix_payload_and_malformed_arguments_stay_generic(self):
        known=next(iter(p._INVENTORY_GUARD_REASONS))
        errors=[RuntimeError(),RuntimeError(known,'private payload'),RuntimeError(None),RuntimeError(123),RuntimeError([known]),RuntimeError({known:'private payload'}),RuntimeError(known+' /private/payload'),RuntimeError('private sensitive payload')]
        class StrSubclass(str):
            def __hash__(self):raise AssertionError('Subclass hashing forbidden')
        errors.append(RuntimeError(StrSubclass(known)))
        for error in errors:
            self.assertEqual(self.diagnostic(error),{'operation':'source-tree','errorType':'RuntimeError','reason':'guard-refused'})
    def test_custom_runtime_error_args_and_string_callbacks_are_never_used(self):
        class CustomRuntimeError(RuntimeError):
            def __str__(self):raise AssertionError('No error stringification')
            def __repr__(self):raise AssertionError('No error representation')
            def __getattribute__(self,name):
                if name=='args':raise AssertionError('No custom args access')
                return super().__getattribute__(name)
        self.assertEqual(self.diagnostic(CustomRuntimeError('Root-owned non-writable ancestor required')),{'operation':'source-tree','errorType':'RuntimeError','reason':'guard-refused'})
        self.assertNotIn('guardReason',self.diagnostic(OSError('Root-owned non-writable ancestor required')))
    def test_guard_table_is_exact_original_inventory_and_delegated_member_literals(self):
        module=Path(p.__file__).with_name('inventory.py')
        tree=ast.parse(module.read_text())
        messages={n.args[1].value for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'and len(n.args)==2 and isinstance(n.args[1],ast.Constant)}
        messages.add('Safe complete source member required')
        self.assertEqual(set(p._INVENTORY_GUARD_REASONS),messages)
        self.assertEqual(len(p._INVENTORY_GUARD_REASONS),16)
        self.assertEqual(len(set(p._INVENTORY_GUARD_REASONS.values())),16)
    def test_all_original_bootstrap_ast_is_unchanged_except_exact_optional_guard_block(self):
        tree=ast.parse(Path(p.__file__).read_text())
        tree.body=[n for n in tree.body if not(isinstance(n,ast.FunctionDef)and n.name=='preparation_ancestors')]
        prepare=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='prepare')
        calls=[n for n in prepare.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='preparation_ancestors']
        self.assertEqual(len(calls),1);prepare.body.remove(calls[0])
        tree.body=[n for n in tree.body if not(isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='_INVENTORY_GUARD_REASONS')]
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='inventory_failure_diagnostic')
        candidates=[n for n in function.body if isinstance(n,ast.If)and ast.unparse(n.test)=='type(error) is RuntimeError']
        self.assertEqual(len(candidates),1)
        function.body.remove(candidates[0])
        self.assertEqual(hashlib.sha256(ast.dump(tree,include_attributes=False).encode()).hexdigest(),'d2dcacfb7e55062199fb1518c78176ace7fbeb4c1922a058e51e61f94de4303c')


if __name__=='__main__':unittest.main()
