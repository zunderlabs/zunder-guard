#!/usr/bin/env python3
"""Inert exporter fixtures; no bootstrap, package build or network."""
import hashlib
import ast
import importlib.util
import json
import os
import io
from pathlib import Path
import stat
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

selected = Path(__file__).with_name('export_bootstrap_probe.py')
spec = importlib.util.spec_from_file_location('bootstrap_probe_export', selected)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
SOURCE = 'a' * 40
HASH = 'b' * 64


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def failed(stage='node', diagnostic=None):
    value = {'schema': 1, 'kind': 'hosted-preparation-incomplete', 'stage': stage,
             'privateInput': False, 'releaseReady': False}
    if stage in ('python-runtime', 'inventories'):
        value['diagnostic'] = diagnostic
    return value


def prepared():
    return {'schema': 1, 'kind': 'actual-free-hosted-ordinary-preparation', 'controlSource': SOURCE,
        'startedAtNs': '1760000000000000000', 'completedAtNs': '1760000000000000001',
        'capabilities': {'noSwap': True, 'coreLimits': [0, 0], 'systemd': True, 'unifiedCgroup': True,
            'cgroupKill': True, 'memorySwapMax': True, 'ownedProbeAbsent': True,
            'bootId': '12345678-1234-1234-1234-123456789abc', 'machineIdSha256': HASH, 'heapLocking': False},
        'source': {'commit': SOURCE, 'archiveSha256': HASH, 'controllerRoot': p.ROOT + '/source',
            'genuineCheckout': p.ROOT + '/checkout', 'gitDatabaseInSourceInventory': False},
        'node': {'version': '26.8.1', 'url': 'https://nodejs.org/dist/v26.8.1/node-v26.8.1-linux-x64.tar.xz',
            'archiveSha256': '3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d',
            'archiveBytes': 100, 'aliases': ['bin/npx', 'bin/npm'],
            'trust': 'Previously verified official checksum signature; runtime still unadmitted'},
        'materialization': {'sourceLockSha256': HASH, 'focusedPackageSha256': HASH, 'focusedLockSha256': HASH,
            'omittedHistoricalGeneratedPrefix': 'artifacts/private-journey/',
            'omittedHistoricalReceipt': 'predecessor-manifest.json',
            'transformedFields': ['web/site/package.json', 'web/site/package-lock.json']},
        'removedNpmAliases': [{'path': '.bin/esbuild', 'target': 'esbuild/bin/esbuild'}],
        'regularizedPythonAliases': [{'path': 'sitecustomize.py', 'omitted': 'ambient startup customization'},
            {'path': 'config-3.12-x86_64-linux-gnu/libpython3.12.so',
             'target': '/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0'}],
        'inventories': {name: {'file': p.PUBLIC + '/reports/' + name + '-inventory.json', 'sha256': HASH}
            for name in p.INVENTORIES},
        **{name: False for name in ('privateInput', 'providerRolesAssumed', 'venueOrders',
            'nativeAcceptance', 'fullJourney', 'releaseReady')}, 'remaining': list(p.REMAINING)}


class Grammar(unittest.TestCase):
    def test_all_stages_are_closed_and_no_authority_is_added(self):
        for stage in p.STAGES:
            with self.subTest(stage=stage):
                out = p.diagnostic(SOURCE, 1, raw(failed(stage)), None)
                self.assertEqual(out['reportState'], 'failure')
                self.assertEqual(out['stage'], stage)
                self.assertEqual(out['bootstrapExit'], 1)
                for flag in p.FALSE_FLAGS:
                    self.assertIs(out[flag], False)

    def test_every_inventory_operation_class_pair_and_bounded_position(self):
        for operation in p.OPERATIONS:
            for cls, reason in p.INVENTORY_ERRORS.items():
                context = {'operation': operation, 'errorType': cls, 'reason': reason,
                    'memberSha256': HASH, 'index': 0, 'count': 4}
                out = p.diagnostic(SOURCE, 23, raw(failed('inventories', context)), None)
                self.assertEqual(out['diagnostic'], context)

    def test_python_members_and_paths_are_redacted_to_the_digest(self):
        for operation, member in [('check-root', 'stdlib'), ('create-root', 'stdlib'),
                ('copy-interpreter', 'python3.12'), ('enumerate', 'stdlib'), ('copy-member', 'stdlib/member.py')]:
            context = {'operation': operation, 'member': member,
                'memberSha256': hashlib.sha256(member.encode()).hexdigest(),
                'errorType': 'RuntimeError', 'reason': 'operation-failed'}
            out = p.diagnostic(SOURCE, 1, raw(failed('python-runtime', context)), None)
            self.assertNotIn('member', out['diagnostic'])
            self.assertNotIn(member.encode(), raw(out))
        context['member'] = None
        p.diagnostic(SOURCE, 1, raw(failed('python-runtime', context)), None)

    def test_all_python_reason_class_combinations(self):
        for cls in p.PYTHON_ERRORS:
            for reason in p.PYTHON_REASONS:
                context = {'operation': 'copy-member', 'member': None, 'memberSha256': HASH,
                    'errorType': cls, 'reason': reason}
                if cls == 'RuntimeError' or reason == 'operation-failed':
                    p.failure(failed('python-runtime', context))
                else:
                    with self.assertRaises(p.Refused):
                        p.failure(failed('python-runtime', context))

    def test_success_exports_only_counts_digests_and_fixed_flags(self):
        out = p.diagnostic(SOURCE, 0, None, raw(prepared()))
        self.assertEqual(out['reportState'], 'prepared')
        self.assertEqual(out['inventoryCount'], 4)
        self.assertEqual(out['removedNpmAliasCount'], 1)
        self.assertEqual(out['regularizedPythonAliasCount'], 2)
        self.assertEqual(out['reportSha256'], hashlib.sha256(raw(prepared())).hexdigest())
        self.assertNotIn(b'/opt/', raw(out))
        self.assertNotIn(b'/var/lib/', raw(out))
        self.assertNotIn(b'/run/', raw(out))
        self.assertNotIn(b'esbuild', raw(out))
        self.assertLess(len(raw(out)), 8192)
        for flag in p.FALSE_FLAGS:
            self.assertIs(out[flag], False)

    def test_success_requires_only_new_fixed_root_and_original_run_report_paths(self):
        self.assertEqual(p.ROOT, '/var/lib/zunder-hosted-ordinary')
        self.assertEqual(p.PUBLIC, '/run/zunder-hosted-ordinary')
        for root in ('/opt/zunder-hosted-ordinary', '/var/lib/foreign', '/var/lib/zunder-hosted-ordinary/..'):
            for key, suffix in (('controllerRoot', '/source'), ('genuineCheckout', '/checkout')):
                value=prepared();value['source'][key]=root+suffix
                with self.subTest(root=root,key=key), self.assertRaises(p.Refused):
                    p.preparation(value,SOURCE)
        value=prepared();value['inventories']['source']['file']=p.ROOT+'/reports/source-inventory.json'
        with self.assertRaises(p.Refused):p.preparation(value,SOURCE)

    def test_unknown_fields_at_every_nested_success_boundary_refuse(self):
        paths = [(), ('capabilities',), ('source',), ('node',), ('materialization',),
            ('inventories',), ('inventories', 'source'), ('removedNpmAliases', 0), ('regularizedPythonAliases', 0)]
        for path in paths:
            value = prepared()
            target = value
            for part in path:
                target = target[part]
            target['raw-private-error'] = 'must-never-export'
            with self.subTest(path=path), self.assertRaises(p.Refused):
                p.diagnostic(SOURCE, 0, None, raw(value))

    def test_false_authority_flags_and_fixed_vendor_paths_are_enforced(self):
        modifications = [('privateInput', True), ('releaseReady', True), ('controlSource', 'c' * 40),
            ('completedAtNs', '1'), ('schema', True)]
        for name, item in modifications:
            value = prepared()
            value[name] = item
            with self.subTest(name=name), self.assertRaises(p.Refused):
                p.preparation(value, SOURCE)
        for path, value in [(('node', 'archiveBytes'), True), (('node', 'url'), 'https://unlisted.invalid'),
                (('source', 'controllerRoot'), '/foreign/source'), (('capabilities', 'coreLimits'), [False, 0])]:
            item = prepared()
            item[path[0]][path[1]] = value
            with self.assertRaises(p.Refused):
                p.preparation(item, SOURCE)

    def test_unknown_failure_classes_contexts_and_members_refuse(self):
        context = {'operation': 'native-ldd', 'errorType': 'RuntimeError', 'reason': 'guard-refused'}
        for change in [{'operation': 'raw-error'}, {'errorType': 'SecretClass'}, {'reason': 'exception text'},
                {'member': '/private/path'}, {'index': True, 'count': 2}, {'index': 0},
                {'index': 2, 'count': 2}, {'index': 0, 'count': 100001}, {'memberSha256': 'A' * 64}]:
            with self.subTest(change=change), self.assertRaises(p.Refused):
                p.failure(failed('inventories', dict(context, **change)))
        value = failed('source')
        value['diagnostic'] = context
        with self.assertRaises(p.Refused):
            p.failure(value)
        value = failed('python-runtime')
        del value['diagnostic']
        with self.assertRaises(p.Refused):
            p.failure(value)

    def test_duplicate_fields_nonfinite_and_wrong_schema_refuse(self):
        for value in [b'{"schema":1,"schema":1}', b'{"x":NaN}', b'{"x":Infinity}', b'{}']:
            with self.assertRaises((p.Refused, KeyError)):
                p.diagnostic(SOURCE, 1, value, None)
        for value in [True, -1, 256, '1']:
            with self.assertRaises(p.Refused):
                p.diagnostic(SOURCE, value, None, None)

    def test_missing_conflicting_and_exit_inconsistency_remain_explicit(self):
        self.assertEqual(p.diagnostic(SOURCE, 1, None, None)['reportState'], 'missing')
        self.assertEqual(p.diagnostic(SOURCE, None, None, None)['bootstrapOutcome'], 'not-run')
        self.assertEqual(p.diagnostic(SOURCE, 0, raw(failed()), None)['reportState'], 'inconsistent')
        self.assertEqual(p.diagnostic(SOURCE, 1, None, raw(prepared()))['reportState'], 'inconsistent')
        with self.assertRaises(p.Refused):
            p.diagnostic(SOURCE, 1, raw(failed()), raw(prepared()))

    def test_bad_cli_emits_only_closed_refusal_and_never_reads_reports(self):
        output = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(p.sys, 'argv', ['probe', '--private-error=must-never-export']), \
                patch.object(p.sys, 'stdout', output), patch.object(p, 'reports') as read:
            self.assertEqual(p.main(), 1)
        read.assert_not_called()
        self.assertNotIn(b'must-never-export', output.buffer.getvalue())
        self.assertEqual(json.loads(output.buffer.getvalue())['reportState'], 'refused')


class Filesystem(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.owner = patch.object(p, 'OWNER', os.getuid())
        self.owner.start()
        self.addCleanup(self.owner.stop)

    def write(self, data=b'{}', mode=0o444):
        target = self.root / 'failure.json'
        target.write_bytes(data)
        target.chmod(mode)
        return target

    def test_fixed_regular_report_is_read_and_inventory_names_are_refused(self):
        self.write(raw(failed()))
        self.assertEqual(p.read_report(self.fd, 'failure.json'), raw(failed()))
        self.assertIsNone(p.read_report(self.fd, 'preparation.json'))
        for name in ('runtime-inventory.json', '../failure.json', '/private/path'):
            with self.assertRaises(p.Refused):
                p.read_report(self.fd, name)

    def test_source_producer_requested_0444_can_create_0400_under_restrictive_umask(self):
        # Same exclusive mode call as the source producer, on inert temporary bytes only.
        previous=os.umask(0o077)
        try:
            fd=os.open(self.root/'failure.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        finally:os.umask(previous)
        with os.fdopen(fd,'wb')as output:output.write(raw(failed()))
        self.assertEqual(stat.S_IMODE((self.root/'failure.json').stat().st_mode),0o400)
        with self.assertRaises(p.Refused)as refusal:p.read_report(self.fd,'failure.json')
        self.assertEqual(refusal.exception.guard,'report-mode-refused')

    def test_symlink_and_hardlink_are_refused(self):
        target = self.root / 'target'
        target.write_bytes(b'{}')
        target.chmod(0o444)
        (self.root / 'failure.json').symlink_to(target)
        with self.assertRaises((OSError, p.Refused)):
            p.read_report(self.fd, 'failure.json')
        (self.root / 'failure.json').unlink()
        os.link(target, self.root / 'failure.json')
        with self.assertRaises(p.Refused):
            p.read_report(self.fd, 'failure.json')

    def test_mode_size_directory_and_foreign_owner_are_refused(self):
        target = self.write()
        for mode in (0o644, 0o666, 0o400, 0o444 | stat.S_ISUID):
            target.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(p.Refused):
                p.read_report(self.fd, 'failure.json')
        target.unlink()
        self.write(b'x' * (p.LIMIT + 1))
        with self.assertRaises(p.Refused):
            p.read_report(self.fd, 'failure.json')
        target.unlink()
        target.mkdir()
        with self.assertRaises(p.Refused):
            p.read_report(self.fd, 'failure.json')
        target.rmdir()
        self.write()
        with patch.object(p, 'OWNER', os.getuid() + 10000), self.assertRaises(p.Refused):
            p.read_report(self.fd, 'failure.json')

    def test_mutation_between_read_and_identity_check_refuses(self):
        target = self.write(raw(failed()))
        original = os.read
        touched = False
        def read(fd, count):
            nonlocal touched
            result = original(fd, count)
            if not touched:
                target.chmod(0o644)
                target.write_bytes(raw(failed('source')))
                target.chmod(0o444)
                touched = True
            return result
        with patch.object(p.os, 'read', side_effect=read), self.assertRaises(p.Refused):
            p.read_report(self.fd, 'failure.json')

    def test_directory_and_fresh_root_identity_guards(self):
        info = os.fstat(self.fd)
        p.directory(info)
        fields = {name: getattr(info, name) for name in ('st_mode', 'st_uid')}
        for mode, owner in [(fields['st_mode'] | 0o020, os.getuid()),
                (fields['st_mode'], os.getuid() + 10000), (stat.S_IFREG | 0o444, os.getuid())]:
            with self.assertRaises(p.Refused):
                p.directory(SimpleNamespace(st_mode=mode, st_uid=owner))
        self.assertFalse(p.same(info, os.stat(self.root.parent)))

    def test_directory_components_refuse_symlink_without_following(self):
        real = self.root / 'real'
        real.mkdir()
        (self.root / 'link').symlink_to(real, target_is_directory=True)
        parts = tuple((self.root.resolve() / 'link').parts[1:])
        # Only ownership is modeled for an unprivileged fixture; actual no-follow opens run.
        with patch.object(p, 'REPORT_PARTS', parts), patch.object(p, 'directory'), \
                self.assertRaises(OSError):
            p.open_reports()


class GuardReasonAndShell(unittest.TestCase):
    def test_exact_closed_optional_inventory_guard_codes_only(self):
        base={'operation':'source-tree','errorType':'RuntimeError','reason':'guard-refused'}
        self.assertEqual(len(p.GUARD_REASONS),16)
        producer=ast.parse(Path(p.__file__).with_name('bootstrap.py').read_text())
        table=next(n.value for n in producer.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='_INVENTORY_GUARD_REASONS')
        self.assertEqual(p.GUARD_REASONS,frozenset(ast.literal_eval(table).values()))
        for code in p.GUARD_REASONS:
            context={**base,'guardReason':code}
            self.assertEqual(p.diagnostic(SOURCE,1,raw(failed('inventories',context)),None)['diagnostic'],context)
        for change in ({'guardReason':'private payload'},{'guardReason':'root-ancestor-refused suffix'},{'guardReason':True},{'guardReason':None},{'guardReason':['root-ancestor-refused']},{'guardReason':'root-ancestor-refused','errorType':'PermissionError','reason':'permission-refused'}):
            with self.subTest(change=change),self.assertRaises(p.Refused):p.failure(failed('inventories',{**base,**change}))
        self.assertEqual(p.failure(failed('inventories',base))['diagnostic'],base)
    def test_actual_workflow_shell_retains_numeric_exit_under_inherited_errexit(self):
        workflow=Path(__file__).resolve().parents[4]/'.github/workflows/hosted-ordinary-bootstrap-probe.yml'
        stage=workflow.read_text().split('      - name: Existing no-key bootstrap with retained failure\n',1)[1].split('      - name: Export only closed diagnostic metadata',1)[0]
        script=stage.split('        run: |\n',1)[1]
        script='\n'.join(line[10:]for line in script.splitlines())+'\n'
        command=next(line for line in script.splitlines()if line.startswith('if /usr/bin/sudo '))
        self.assertTrue(command.endswith('; then'))
        for exit_code in(0,1,23,137):
            with tempfile.TemporaryDirectory()as directory:
                output=Path(directory)/'output'
                inert=script.replace(command,"if /bin/bash -c 'exit "+str(exit_code)+"'; then")
                result=subprocess.run(['/bin/bash','--noprofile','--norc','-eo','pipefail','-c',inert],env={'PATH':'/usr/bin:/bin','GITHUB_OUTPUT':str(output)},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
                self.assertEqual(result.returncode,exit_code)
                self.assertEqual(output.read_text(),'exit_code='+str(exit_code)+'\n')
                self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')


class ValidatorRefusalDiagnostic(unittest.TestCase):
    def setUp(self):
        self.stage=p._VALIDATOR_STAGE
        self.addCleanup(lambda:setattr(p,'_VALIDATOR_STAGE',self.stage))
    def main(self,prepared_raw=None,failed_raw=None,*,error=None,stage=None,argv=None):
        def reports():
            if stage:p.validator_stage(stage)
            if error is not None:raise error
            return failed_raw,prepared_raw
        output=SimpleNamespace(buffer=io.BytesIO())
        with patch.object(p.sys,'argv',argv or ['probe','--control-source',SOURCE,'--bootstrap-exit','0']),\
             patch.object(p.sys,'platform','linux'),patch.object(p.os,'geteuid',return_value=0),\
             patch.object(p.sys,'stdout',output),patch.object(p,'reports',side_effect=reports):
            code=p.main()
        payload=output.buffer.getvalue();return code,json.loads(payload),payload
    def test_closed_stage_and_guard_enums_only(self):
        self.assertEqual(len(p.VALIDATOR_STAGES),20);self.assertEqual(len(p.VALIDATOR_GUARDS),9)
        for stage in p.VALIDATOR_STAGES:
            p.validator_stage(stage)
            for guard in p.VALIDATOR_GUARDS:
                self.assertEqual(p.refusal_diagnostic(p.Refused(guard)),{'stage':stage,'guard':guard})
        for stage in ('private-path/payload',None,1,True,[],{}):
            with self.assertRaises(p.Refused):p.validator_stage(stage)
        for guard in ('private payload',None,1,True,[],{}):
            self.assertEqual(p.refusal_diagnostic(p.Refused(guard))['guard'],'guard-refused')
    def test_exact_pinned_vendor_alias_order_and_all_other_lists_refused(self):
        value=prepared();p.preparation(value,SOURCE)
        for aliases in (['bin/npm','bin/npx'],[],['bin/npm'],['bin/npm','bin/npm'],['bin/npm','bin/npx','private'],None,{},'private'):
            value=prepared();value['node']['aliases']=aliases
            with self.assertRaises(p.Refused)as failure:p.preparation(value,SOURCE)
            self.assertEqual(p.refusal_diagnostic(failure.exception),{'stage':'preparation-node','guard':'node-alias-order-refused'})
    def test_expected_order_is_exact_source_producer_and_observed_vendor_order(self):
        # Parent read-only observation of SHA3e301118... official archive, not runtime proof.
        observed=[('bin/npx','../lib/node_modules/npm/bin/npx-cli.js'),
                  ('bin/npm','../lib/node_modules/npm/bin/npm-cli.js')]
        self.assertEqual([name for name,_ in observed],prepared()['node']['aliases'])
        source=ast.parse(Path(p.__file__).with_name('bootstrap.py').read_text())
        node=next(n for n in source.body if isinstance(n,ast.FunctionDef)and n.name=='node')
        expected=next(n.value for n in ast.walk(node)if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='expected')
        self.assertEqual(ast.literal_eval(expected),dict(observed))
        result=node.body[-1];self.assertIsInstance(result,ast.Return)
        value=next(value for key,value in zip(result.value.keys,result.value.values)if isinstance(key,ast.Constant)and key.value=='aliases')
        self.assertEqual(ast.unparse(value),'[a for a, _ in aliases]')
        self.assertNotIn('sorted(aliases)',ast.unparse(node))
        text=ast.unparse(node)
        self.assertIn('aliases.append((name,',text)
        self.assertIn('expected.get(name) == member.linkname',text)

    def test_real_exception_types_never_echo_text_and_subclasses_never_inspect_attributes(self):
        class Hostile(p.Refused):
            def __str__(self):raise AssertionError('No stringification')
            def __repr__(self):raise AssertionError('No representation')
            def __getattribute__(self,name):
                if name in ('args','guard'):raise AssertionError('No custom attributes')
                return super().__getattribute__(name)
        p.validator_stage('report-directory')
        pairs=[(FileNotFoundError('private'), 'missing-resource'),(PermissionError('private'),'permission-refused'),
               (OSError('private'),'os-operation-refused'),(json.JSONDecodeError('private','private',0),'metadata-decode-refused'),
               (KeyError('private'),'metadata-shape-refused'),(TypeError('private'),'metadata-shape-refused'),
               (ValueError('private'),'metadata-shape-refused'),(Hostile(),'other-refused'),(RuntimeError('private'),'other-refused')]
        for error,guard in pairs:
            row=p.refusal_diagnostic(error);self.assertEqual(row,{'stage':'report-directory','guard':guard})
            self.assertNotIn('private',json.dumps(row))
    def test_context_and_guard_mutation_cannot_export_arbitrary_value_or_callbacks(self):
        class Hostile(str):
            def __hash__(self):raise AssertionError('No subclass hashing')
            def __str__(self):raise AssertionError('No subclass string')
        p._VALIDATOR_STAGE=Hostile('private')
        error=p.Refused();error.guard=Hostile('private')
        self.assertEqual(p.refusal_diagnostic(error),{'stage':'arguments','guard':'guard-refused'})
    def test_bad_cli_resets_stage_and_never_reads_reports(self):
        p.validator_stage('preparation-node');output=SimpleNamespace(buffer=io.BytesIO())
        with patch.object(p.sys,'argv',['probe','--private=secret']),patch.object(p.sys,'stdout',output),patch.object(p,'reports')as reports:
            self.assertEqual(p.main(),1)
        reports.assert_not_called();row=json.loads(output.buffer.getvalue())
        self.assertEqual(row['validator'],{'stage':'arguments','guard':'guard-refused'})
        self.assertNotIn('secret',output.buffer.getvalue().decode())
    def test_fixed_main_reports_read_error_stage_without_raw_data(self):
        for stage in ('report-directory','failure-report-read','preparation-report-read','report-directory-readback'):
            code,row,payload=self.main(error=PermissionError('/private/raw payload'),stage=stage)
            self.assertEqual(code,1);self.assertEqual(row['reportState'],'refused')
            self.assertEqual(row['validator'],{'stage':stage,'guard':'permission-refused'})
            self.assertLess(len(payload),8192)
            for flag in p.FALSE_FLAGS:self.assertIs(row[flag],False)
            self.assertNotIn(b'private/raw',payload);self.assertNotIn(b'payload',payload)
    def test_nested_validation_boundaries_have_fixed_stages_without_fields_or_payloads(self):
        changes=[('preparation-schema',('extra',),'PRIVATE'),
                 ('preparation-capabilities',('capabilities','machineIdSha256'),'PRIVATE'),
                 ('preparation-source',('source','controllerRoot'),'/private/source'),
                 ('preparation-node',('node','aliases'),['bin/npm','bin/npx']),
                 ('preparation-materialization',('materialization','sourceLockSha256'),'PRIVATE'),
                 ('preparation-inventories',('inventories','source','file'),'/private/inventory'),
                 ('npm-aliases',('removedNpmAliases',),[{'path':'private unsafe','target':'x'}]),
                 ('python-aliases',('regularizedPythonAliases',),[{'path':'x','target':'private unsafe'}])]
        for stage,path,item in changes:
            value=prepared();target=value
            for name in path[:-1]:target=target[name]
            target[path[-1]]=item
            code,row,payload=self.main(raw(value));self.assertEqual(code,1)
            self.assertEqual(row['validator']['stage'],stage)
            self.assertNotIn(b'PRIVATE',payload);self.assertNotIn(b'/private',payload);self.assertNotIn(b'unsafe',payload)
    def test_json_and_conflicting_report_boundaries_remain_refused(self):
        for prepared_raw,failed_raw,stage,guard in ((b'{',None,'preparation-json','metadata-decode-refused'),
                (b'{"schema":1,"schema":1}',None,'preparation-json','guard-refused'),
                (None,b'{','failure-json','metadata-decode-refused'),
                (raw(prepared()),raw(failed()),'report-conflict','guard-refused')):
            code,row,_=self.main(prepared_raw,failed_raw)
            self.assertEqual(code,1);self.assertEqual(row['validator'],{'stage':stage,'guard':guard})
    def test_original_reports_adapter_selects_precise_read_boundary_and_closes_descriptors(self):
        info=SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_gid=0,st_mode=0o040700,st_nlink=1,st_size=1,st_mtime_ns=0,st_ctime_ns=0)
        for selected,stage in (('failure.json','failure-report-read'),('preparation.json','preparation-report-read')):
            def read(fd,name):
                if name==selected:raise p.Refused('report-mode-refused')
                return None
            with patch.object(p,'open_reports',return_value=3),patch.object(p.os,'fstat',return_value=info),\
                 patch.object(p,'read_report',side_effect=read),patch.object(p.os,'close')as close,self.assertRaises(p.Refused)as refusal:
                p.reports()
            self.assertEqual(p.refusal_diagnostic(refusal.exception),{'stage':stage,'guard':'report-mode-refused'})
            close.assert_called_once_with(3)
    def test_success_output_has_no_new_validator_or_authority_fields(self):
        expected=p.diagnostic(SOURCE,0,None,raw(prepared()))
        code,row,_=self.main(raw(prepared()))
        self.assertEqual(code,0);self.assertEqual(row,expected);self.assertNotIn('validator',row)
    def test_refusal_helpers_never_inspect_exception_text_or_add_report_reads(self):
        tree=ast.parse(Path(p.__file__).read_text())
        for name in ('validator_stage','refusal_diagnostic'):
            function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
            calls={ast.unparse(n.func)for n in ast.walk(function)if isinstance(n,ast.Call)}
            self.assertFalse(calls & {'str','repr','getattr','read_report','reports','open_reports','os.open','os.read','decode'})
            self.assertFalse(any(isinstance(n,ast.Attribute)and n.attr=='args'for n in ast.walk(function)))


if __name__ == '__main__':
    unittest.main()
