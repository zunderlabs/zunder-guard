"""Inert prep-boundary fixtures. No compiler/npm/network/provider is invoked."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import prepare_website as p


class PreparationBoundary(unittest.TestCase):
    def test_credential_and_injection_environment_refusals(self):
        for name in ('GITHUB_TOKEN', 'GH_TOKEN', 'APP_PRIVATE_KEY', 'WAITLIST_ADMIN_TOKEN',
                     'AWS_REGION', 'CLOUDFLARE_ACCOUNT_ID', 'NODE_OPTIONS', 'LD_PRELOAD',
                     'DYLD_INSERT_LIBRARIES', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTC_WRAPPER'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                p.no_credentials({name: 'never printed'})
        p.no_credentials({'CI': '1', 'GITHUB_ACTION': 'step', 'LANG': 'C'})

    def test_child_environment_does_not_inherit_ambient_values(self):
        with patch.dict(os.environ, {'UNRELATED': 'not copied', 'PATH': '/malicious'}, clear=True):
            env = p.environment(Path('/scratch'), '/tools/bin/node')
        self.assertNotIn('UNRELATED', env)
        self.assertEqual(env['PATH'], '/tools/bin:/usr/bin:/bin')
        self.assertEqual(env['NPM_CONFIG_USERCONFIG'], '/dev/null')
        self.assertEqual(env['NPM_CONFIG_IGNORE_SCRIPTS'], 'true')
        self.assertNotIn('PUBLIC_TESTNET_MERCHANT', env)

    def test_plan_has_only_fixed_no_lifecycle_commands(self):
        refs = {n: {'file': '/public/'+n, 'sha256': 'a'*64} for n in ('node', 'npm', 'rustup')}
        plan = p.command_plan(Path('/scratch'), refs, '0.2.104')
        self.assertEqual([n for n, _, _ in plan], ['toolchain', 'wasm-bindgen', 'cargo-fetch',
            'live-deps', 'wasm', 'wasm-glue', 'live-types', 'live-tests', 'live-build',
            'wasm-licenses', 'site-deps'])
        argv = [a for _, _, args in plan for a in args]
        self.assertFalse(any('run.sh' in a or '/scripts/' in a or a in ('bash', 'sh', 'npx') for a in argv))
        for name, _, args in plan:
            if name.endswith('-deps'): self.assertIn('--ignore-scripts', args)
            if name in ('wasm', 'wasm-licenses'): self.assertIn('--offline', args)
        with self.assertRaises(RuntimeError): p.command_plan(Path('/scratch'), refs, '1;curl evil')

    def test_licenses_use_actual_cargo_rows_and_reject_unknown_or_copyleft(self):
        output = p.licenses(b'zunder-risk-wasm v1.0.0 (/var/tmp/prep/source/crates/zunder-risk-wasm)|\nserde v1.0.228|MIT OR Apache-2.0\nserde_derive v1.0.228 (proc-macro)|MIT OR Apache-2.0\n')
        self.assertIn(b'3 crates', output)
        self.assertIn(b'serde_derive (build time only)', output)
        self.assertNotIn(b'/var/tmp', output)
        for row in (b'foreign v1.0.0|GPL-3.0\n', b'foreign v1.0.0|\n',
                    b'foreign v1.0.0|MIT AND GPL-3.0\n', b'bad|MIT\n'):
            with self.subTest(row=row), self.assertRaises(RuntimeError):
                p.licenses(b'zunder-risk-wasm v1.0.0|\n'+row)
        with self.assertRaises(RuntimeError): p.licenses(b'serde v1.0.0|MIT\n')

    def test_public_error_never_repeats_private_input_filename(self):
        with patch.object(p, '_prepare', side_effect=FileNotFoundError('/private/source/customer-name.astro')):
            with self.assertRaisesRegex(RuntimeError, '^Website preparation held$'):
                p.prepare({}, {})

    def test_input_namespace_accepts_astro_but_refuses_escape_and_credentials(self):
        for route in ('web/site/src/pages/[legal].astro', 'web/site/src/pages/[slug].md.ts',
                      'web/site/src/pages/docs/[...slug].md.ts',
                      'node_modules/vscode-languageserver-protocol/lib/common/protocol.$.js'):
            self.assertEqual(p.member(route), route)
        for route in ('../x', '/x', 'x//y', 'x/.env.production', 'x/key.pem', 'x/__proto__/y',
                      'x/%5Bslug%5D.astro', 'x\\y', 'x\n'):
            with self.subTest(route=route), self.assertRaises(RuntimeError): p.member(route)

    def test_full_tree_refuses_symlink_hardlink_case_collision_and_empty_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); (root/'x').write_bytes(b'one')
            self.assertEqual(len(p.inventory(root)['files']), 1)
            (root/'X').write_bytes(b'two')
            if (root/'X').stat().st_ino != (root/'x').stat().st_ino:
                with self.assertRaises(RuntimeError): p.inventory(root)
            (root/'X').unlink(); (root/'x').write_bytes(b'one')
            (root/'alias').symlink_to(root/'x')
            with self.assertRaises(RuntimeError): p.inventory(root)
            (root/'alias').unlink(); os.link(root/'x', root/'linked')
            with self.assertRaises(RuntimeError): p.inventory(root)
            (root/'linked').unlink(); (root/'empty').write_bytes(b'')
            with self.assertRaises(RuntimeError): p.inventory(root)

    def test_generated_outputs_and_elf_are_not_assumed_from_js_api(self):
        p.elf_x64(b'\x7fELF\x02\x01'+b'\0'*12+b'\x3e\x00')
        for raw in (b'#!/usr/bin/env node', b'\0asm\x01\0\0\0',
                    b'\x7fELF\x02\x01'+b'\0'*12+b'\xb7\x00'):
            with self.assertRaises(RuntimeError): p.elf_x64(raw)

    def test_native_reification_and_bin_omission_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp).resolve(); native = b'\x7fELF\x02\x01'+b'\0'*12+b'\x3e\x00'
            for name, version in p.CORE.items():
                d = site/'node_modules'/name; d.mkdir(parents=True, exist_ok=True)
                (d/'package.json').write_text(json.dumps({'name': name, 'version': version, 'license': 'MIT'}))
            elf = site/'node_modules/@esbuild/linux-x64/bin/esbuild'; elf.parent.mkdir(parents=True)
            elf.write_bytes(native)
            (elf.parent.parent/'package.json').write_text(json.dumps({'name': '@esbuild/linux-x64', 'version': '0.28.2', 'license': 'MIT'}))
            binary = site/'node_modules/esbuild/bin/esbuild'; binary.parent.mkdir()
            binary.write_bytes(b'#!/usr/bin/env node\n')
            (site/p.ROL_NATIVE).write_bytes(native)
            alias = site/'node_modules/.bin/esbuild'; alias.parent.mkdir()
            alias.symlink_to('../esbuild/bin/esbuild')
            stub = site/'stubs/sharp'; stub.mkdir(parents=True); (stub/'index.js').write_bytes(b'export default {};')
            (site/'node_modules/sharp').symlink_to('astro/stubs/sharp')
            for name in p.EMPTY_TOOL_FILES:
                d = site/name; d.parent.mkdir(parents=True, exist_ok=True); d.write_bytes(b'')
            events = p.normalize_tools(site)
            self.assertEqual(binary.read_bytes(), native)
            self.assertFalse(alias.exists()); self.assertFalse((site/'node_modules/sharp').is_symlink())
            self.assertEqual({r['kind'] for r in events}, {'fixed-source-stub', 'omit-bin-alias', 'fixed-esbuild-elf', 'fixed-empty-text-lf'})
            changes = [r for r in events if r['kind'] == 'fixed-empty-text-lf']
            self.assertEqual(len(changes), 43)
            for event in changes:
                self.assertEqual((site/event['path']).read_bytes(), b'\n')
                self.assertEqual(event['beforeSha256'], p.digest(b''))
                self.assertEqual(event['sha256'], p.digest(b'\n'))
            self.assertTrue(binary.stat().st_mode & 0o100)
            (site/'node_modules/unexpected.json').write_bytes(b'')
            with self.assertRaises(RuntimeError): p.normalize_tools(site)
            (site/'node_modules/unexpected.json').unlink()
            (site/'node_modules/unexpected').symlink_to('/tmp')
            with self.assertRaises(RuntimeError): p.normalize_tools(site)

    def test_reader_stage_abi_joins_distinct_wire_and_source_inventory_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); source = root/'build-source'; source.mkdir()
            controls = root/'build-input'; controls.mkdir()
            (source/'x.rs').write_bytes(b'// reviewed synthetic source')
            source_bytes = p.canonical(p.inventory(source)); (controls/'source.json').write_bytes(source_bytes)
            raw_manifest = {'files': [{'path': 'build-source/x.rs', 'size': 28, 'sha256': 'a'*64, 'mode': 384}], 'transformations': []}
            # Wire file rows preserve producer key order, distinct from canonical source.json.
            raw_bytes = json.dumps(raw_manifest, separators=(',', ':')).encode(); (controls/'raw-manifest.json').write_bytes(raw_bytes)
            candidate = p.canonical({'sourceCommit': 'b'*40, 'published': False}); (controls/'candidate.json').write_bytes(candidate)
            ref = lambda name: {'file': str(controls/name), 'sha256': p.digest((controls/name).read_bytes())}
            receipt = {'schema': 1, 'purpose': 'original-guard-website-build-input',
                'privateRepository': {'id': 123, 'fullName': 'zunderlabs/zunder'},
                'sourceCommit': 'c'*40, 'sourceRef': 'refs/heads/main', 'producer': {}, 'artifact': {},
                'inventorySha256': p.digest(json.dumps(raw_manifest['files'], ensure_ascii=True, separators=(',', ':')).encode()),
                'manifestSha256': p.digest(raw_bytes), 'source': {'root': str(source), 'manifest': ref('source.json')},
                'candidate': ref('candidate.json'), 'rawManifest': ref('raw-manifest.json'), 'readerTokenRevoked': True}
            def save(): (controls/'stage-receipt.json').write_bytes(p.canonical(receipt))
            save()
            with patch.object(p, 'INPUT', controls), patch.object(p, 'SOURCE', source):
                actual, rows = p.stage_input(ref('stage-receipt.json'))
                self.assertEqual(actual, receipt); self.assertEqual(rows, p.inventory(source))
                receipt['inventorySha256'] = p.digest(source_bytes); save()
                with self.assertRaises(RuntimeError): p.stage_input(ref('stage-receipt.json'))
                receipt['readerTokenRevoked'] = False; save()
                with self.assertRaises(RuntimeError): p.stage_input(ref('stage-receipt.json'))


if __name__ == '__main__': unittest.main()
