#!/usr/bin/env python3
"""Focused inert fixtures: no root setup, network, provider, browser or venue calls."""
import copy
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hosted_launch import contracts as c
from hosted_launch import materialize as m
from hosted_launch import inventory as i


def lock_fixture():
    records = {}
    for name, version in m.DEPENDENCIES.items():
        records['node_modules/'+name] = {'version': version,
            'resolved': 'https://registry.npmjs.org/'+name+'/-/fixture.tgz', 'license': 'MIT',
            'integrity': 'sha512-'+base64.b64encode(b'x'*64).decode()}
    records['node_modules/ethers']['dependencies'] = {'fixture-dependency': '1.0.0'}
    records['node_modules/fixture-dependency'] = {'version': '1.0.0',
        'resolved': 'https://registry.npmjs.org/fixture-dependency/-/fixture.tgz', 'license': 'MIT',
        'integrity': 'sha512-'+base64.b64encode(b'x'*64).decode()}
    records['node_modules/irrelevant'] = {'version': '1.0.0', 'link': True}
    return {'lockfileVersion': 3, 'packages': records}


class Contracts(unittest.TestCase):
    def test_duplicate_nonfinite_and_oversized_input_refused(self):
        for raw in (b'{"schema":1,"schema":1}', b'{"x":NaN}', b''):
            with self.assertRaises((RuntimeError, ValueError)): c.decode(raw)
        with self.assertRaises(RuntimeError): c.decode(b'{"schema":1}', 1)

    def test_digest_and_closed_real_identity(self):
        v = {'control_source': 'a'*40, 'caller_source': 'b'*40, 'run_id': 123, 'attempt': 1}
        self.assertEqual(c.identity(v), v)
        for change in ({'run_id': True}, {'attempt': 10}, {'control_source': 'main'}, {'extra': 'fixture'}):
            with self.assertRaises(RuntimeError): c.identity({**v, **change})

    def test_safe_member_grammar(self):
        self.assertEqual(c.relative('deploy/guard/e2e/hosted_launch/__init__.py'),
                         'deploy/guard/e2e/hosted_launch/__init__.py')
        for name in ('../escape', '/absolute', 'a//b', './x', 'x/../y', 'x\\y', '', 'a\nb'):
            with self.assertRaises(RuntimeError): c.relative(name)

    def test_runtime_cannot_omit_tool_or_adopt_observed_partial(self):
        value = {'schema': 1, 'files': {'/usr/bin/tool': 'a'*64},
                 'roots': {'python': '/usr/lib/python3.12', 'node': '/opt/node', 'packages': '/opt/packages'},
                 'tools': {}}
        with self.assertRaises(RuntimeError): c.runtime(value)
        value['tools'] = {name: {'file': '/usr/bin/tool', 'sha256': 'a'*64} for name in c.TOOLS}
        with self.assertRaises(RuntimeError): c.runtime(value)


class Materialization(unittest.TestCase):
    def test_selected_public_inputs_omit_historical_generated_evidence(self):
        self.assertFalse(m.selected_input('artifacts/private-journey/bundle-build.json'))
        self.assertFalse(m.selected_input('artifacts/private-journey/private-journey.mjs'))
        self.assertFalse(m.selected_input('predecessor-manifest.json'))
        self.assertTrue(m.selected_input('web/testnet-journey/root-runtime/full-return.ts'))

    def test_fresh_materialization_does_not_scrub_or_adopt_old_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root/'input'; source.mkdir()
            lock = source/'web/site/package-lock.json'; lock.parent.mkdir(parents=True)
            lock.write_bytes(c.canonical(lock_fixture()))
            (source/'web/site/package.json').write_text('{"historical":true}')
            artifact = source/'artifacts/private-journey'; artifact.mkdir(parents=True)
            old = b'{"absolute":"/private/project/build"}'
            (artifact/'bundle-build.json').write_bytes(old)
            (source/'predecessor-manifest.json').write_bytes(b'{"historical":true}')
            (source/'web/source.ts').write_text('export const fixture=1;')
            output = root/'output'; result = m.website(source, output)
            self.assertFalse((output/'artifacts/private-journey/bundle-build.json').exists())
            self.assertFalse((output/'predecessor-manifest.json').exists())
            self.assertEqual((artifact/'bundle-build.json').read_bytes(), old)
            self.assertEqual((output/'web/source.ts').read_bytes(), b'export const fixture=1;')
            self.assertEqual(result['omittedHistoricalGeneratedPrefix'], 'artifacts/private-journey/')

    def test_controller_runtime_and_real_git_layout_are_distinct(self):
        self.assertFalse(c.WEBSITE.is_relative_to(c.SOURCE))
        self.assertFalse(c.CHECKOUT.is_relative_to(c.SOURCE))
        self.assertEqual(str(c.WEBSITE), '/var/lib/zunder-hosted-ordinary/runtime/website/source')

    def test_exact_minimal_browser_helpers_and_transitive_imports(self):
        root = Path(__file__).resolve().parent/'browser'
        provenance = json.loads((root/'provenance.json').read_bytes())
        self.assertEqual(len(provenance['files']), 9)
        for name, pin in provenance['files'].items():
            self.assertEqual(c.digest((root/name).read_bytes()), pin['outputSha256'])
        self.assertEqual(provenance['files']['probes/browser-probes.mjs']['outputSha256'],
                         '982fc8705c4ad125bd247a026ee8bb8fd22dc814ac6b67a81cbcf02d352a5cec')
        self.assertEqual(provenance['files']['probes/contract.mjs']['outputSha256'],
                         '41c2f715bf034fd1ab8dfca5fbbf1e82a279e748be63431c7287f9adeba634c8')
        self.assertIn("'./cleanup-verifier.mjs'", (root/'probes/collect-teardown.mjs').read_text())

    def test_lock_retains_integrity_exact_transitive_versions(self):
        original = lock_fixture(); package, lock = m.focused_lock(original)
        self.assertEqual(package['dependencies'], m.DEPENDENCIES)
        self.assertNotIn('node_modules/irrelevant', lock['packages'])
        self.assertEqual(lock['packages']['node_modules/fixture-dependency'],
                         original['packages']['node_modules/fixture-dependency'])
        self.assertEqual(original, lock_fixture())

    def test_lock_rejects_unpinned_moved_or_missing_dependencies(self):
        for change in ('version', 'registry', 'integrity', 'link', 'missing', 'licence', 'query'):
            v = lock_fixture(); row = v['packages']['node_modules/ethers']
            if change == 'version': row['version'] = '6.18.0'
            if change == 'registry': row['resolved'] = 'https://example.invalid/arbitrary.tgz'
            if change == 'integrity': del row['integrity']
            if change == 'link': row['link'] = True
            if change == 'missing': del v['packages']['node_modules/fixture-dependency']
            if change == 'licence': row['license'] = 'GPL-3.0'
            if change == 'query': row['resolved'] += '?fixture=1'
            with self.assertRaises(RuntimeError): m.focused_lock(v)

    def test_nested_dependency_resolution_preserves_override(self):
        v = lock_fixture()
        child = copy.deepcopy(v['packages']['node_modules/fixture-dependency']); child['version'] = '2.0.0'
        v['packages']['node_modules/ethers/node_modules/fixture-dependency'] = child
        _, output = m.focused_lock(v)
        self.assertIn('node_modules/ethers/node_modules/fixture-dependency', output['packages'])
        self.assertNotIn('node_modules/fixture-dependency', output['packages'])

    def test_real_source_lock_projection_is_deterministic(self):
        file = Path(__file__).resolve().parents[1]/'hosted_journey/runtime_fork/web/site/package-lock.json'
        source = json.loads(file.read_bytes()); before = copy.deepcopy(source)
        package, lock = m.focused_lock(source)
        self.assertEqual((package, lock), m.focused_lock(source))
        self.assertEqual(source, before)
        self.assertLessEqual(len(lock['packages']), 100)
        self.assertIn('node_modules/@esbuild/linux-x64', lock['packages'])
        for name, row in lock['packages'].items():
            if name:
                self.assertEqual(row['integrity'], source['packages'][name]['integrity'])
                self.assertEqual(row['resolved'], source['packages'][name]['resolved'])

    def test_regularize_only_internal_bin_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root/'pkg').mkdir(); (root/'pkg/entry.js').write_text('fixture')
            (root/'.bin').mkdir(); (root/'.bin/tool').symlink_to('../pkg/entry.js')
            self.assertEqual(m.regularize_bin(root), [{'path': '.bin/tool', 'target': 'pkg/entry.js'}])
            self.assertFalse((root/'.bin').exists())
            (root/'bad').symlink_to('/usr/bin/python3')
            with self.assertRaises(RuntimeError): m.regularize_bin(root)

    def test_plain_read_rejects_link_and_size_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root/'file').write_bytes(b'fixture'); (root/'link').symlink_to(root/'file')
            self.assertEqual(i.read(root/'file', protected=False), b'fixture')
            for path, maximum in ((root/'link', 100), (root/'file', 2)):
                with self.assertRaises(RuntimeError): i.read(path, maximum, protected=False)


class WorkflowContract(unittest.TestCase):
    def test_workflow_mirrors_and_no_business_rights(self):
        root = Path(__file__).resolve().parents[4]
        for name in ('hosted-testnet-journey', 'hosted-testnet-journey-run', 'hosted-testnet-journey-negative'):
            raw = (root/'.github/workflows'/f'{name}.yml').read_bytes()
            self.assertEqual(raw, (root/'deploy/guard/github/workflows'/f'{name}.yml').read_bytes())
            text = raw.decode()
            for term in ('id-token:', 'secrets:', 'self-hosted', 'runner_label', '/opt/zunder-private-controller',
                         'aws-actions', 'environment:', 'write-all', 'packages: write'):
                self.assertNotIn(term, text)
        text = (root/'.github/workflows/hosted-testnet-journey-run.yml').read_text()
        self.assertIn('runs-on: ubuntu-24.04', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('sudo /usr/bin/env -i', text)


if __name__ == '__main__': unittest.main()
