import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-loaders.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class FakeCloudflare:
    def __init__(self, routes=None, scripts=None, settings=None):
        self.routes = routes or []
        self.scripts = scripts or []
        self.settings = settings if settings is not None else {'tags': [p.OWNER_TAG], 'bindings': []}
        self.calls = []
    def request(self, method, endpoint, data=None, content_type=None):
        self.calls.append((method, endpoint, data))
        if method == 'GET' and endpoint.endswith('/workers/routes'):
            return self.routes
        if method == 'GET' and endpoint.endswith('/workers/scripts'):
            return self.scripts
        if method == 'GET' and endpoint.endswith('/settings'):
            return self.settings
        if method == 'GET':
            return {'name': p.HOST, 'account': {'id': 'a' * 32}}
        return {}


class PublisherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in p.PATHS.values():
            (self.root/name).write_text('# v1.0.0\n# synthetic loader "quotes" ${literal}\n')
        self.manifest()
    def manifest(self):
        (self.root/'SHA256SUMS').write_text(''.join(p.sha((self.root/n).read_bytes()) + '  ' + n + '\n' for n in p.PATHS.values()))
    def test_valid_assets(self):
        self.assertEqual(set(p.load_assets(self.root, 'v1.0.0')), set(p.PATHS))
    def test_modified_asset(self):
        (self.root/'i').write_text('changed')
        with self.assertRaises(ValueError): p.load_assets(self.root, 'v1.0.0')
    def test_duplicate_manifest(self):
        m=self.root/'SHA256SUMS';m.write_text(m.read_text()*2)
        with self.assertRaises(ValueError): p.load_assets(self.root, 'v1.0.0')
    def test_symlink_asset(self):
        (self.root/'i').unlink(); (self.root/'i').symlink_to('i.ps1')
        with self.assertRaises(ValueError): p.load_assets(self.root, 'v1.0.0')
    def test_invalid_and_wrong_version(self):
        for tag in ['../v1.0.0', 'v1.0.0-rc1', 'v2.0.0']:
            with self.subTest(tag=tag), self.assertRaises(ValueError): p.load_assets(self.root, tag)
    def test_render_exact_bytes_and_paths(self):
        assets=p.load_assets(self.root,'v1.0.0')
        worker=self.root/'worker.mjs';worker.write_bytes(p.render_worker(assets,'v1.0.0'))
        probe=self.root/'probe.mjs'
        probe.write_text('''import assert from 'node:assert/strict';
import worker from './worker.mjs';
const assets = '''+json.dumps(assets)+''';
for (const [path, asset] of Object.entries(assets)) {
 const response=worker.fetch(new Request('https://zunderlabs.com'+path));
 assert.equal(await response.text(),asset.body); assert.equal(response.headers.get('cache-control'),'no-store');
 assert.equal(await worker.fetch(new Request('https://zunderlabs.com'+path,{method:'HEAD'})).text(),'');
 assert.equal(worker.fetch(new Request('https://zunderlabs.com'+path,{method:'POST'})).status,405);
}
assert.equal(worker.fetch(new Request('https://zunderlabs.com/impressum')).status,404);
assert.equal(worker.fetch(new Request('https://other.example/i')).status,404);
''')
        subprocess.run(['node',str(probe)],check=True,capture_output=True)
    def test_foreign_route_prevents_all_writes(self):
        client=FakeCloudflare([{'pattern':p.HOST+'/i','script':'other'}])
        with self.assertRaises(RuntimeError):p.publish(client,'a'*32,'b'*32,b'module')
        self.assertTrue(all(c[0]=='GET' for c in client.calls))
    def test_reserved_worker_must_not_own_other_routes(self):
        client=FakeCloudflare([{'pattern':p.HOST+'/other/*','script':p.SCRIPT}])
        with self.assertRaises(RuntimeError):p.publish(client,'a'*32,'b'*32,b'module')
        self.assertTrue(all(c[0]=='GET' for c in client.calls))
    def test_existing_routes_idempotent_preserves_unrelated(self):
        client=FakeCloudflare([{'pattern':p.HOST+r,'script':p.SCRIPT} for r in p.PATHS]+[{'pattern':p.HOST+'/api/*','script':'api'}])
        p.publish(client,'a'*32,'b'*32,b'module')
        self.assertEqual([c[0] for c in client.calls],['GET','GET','GET','PUT'])
    def test_unrelated_reserved_script_refused_even_without_zone_routes(self):
        for settings in [{}, {'tags':['unrelated']}, {'tags':[p.OWNER_TAG,'another-owner']},
                         {'tags':[p.OWNER_TAG],'bindings':[{'type':'secret_text','name':'SECRET'}]},
                         {'tags':[p.OWNER_TAG],'tail_consumers':[{'service':'other'}]}]:
            client=FakeCloudflare(scripts=[{'id':p.SCRIPT}], settings=settings)
            with self.subTest(settings=settings), self.assertRaises(RuntimeError):
                p.publish(client,'a'*32,'b'*32,b'module')
            self.assertTrue(all(c[0]=='GET' for c in client.calls))
    def test_managed_script_retry_preserves_ownership_metadata(self):
        client=FakeCloudflare(scripts=[{'id':p.SCRIPT}])
        p.publish(client,'a'*32,'b'*32,b'module')
        upload=next(c[2] for c in client.calls if c[0]=='PUT')
        self.assertIn(json.dumps([p.OWNER_TAG]).encode(),upload)
        self.assertTrue(any(c[1].endswith('/settings') for c in client.calls))
    def test_malformed_or_duplicate_script_inventory_refuses(self):
        for scripts in [{'unexpected':'shape'},[None],[{'id':p.SCRIPT},{'id':p.SCRIPT}]]:
            client=FakeCloudflare(scripts=scripts)
            with self.subTest(scripts=scripts), self.assertRaises(RuntimeError):
                p.publish(client,'a'*32,'b'*32,b'module')
            self.assertTrue(all(c[0]=='GET' for c in client.calls))
    def test_new_routes_only_exact_installers(self):
        client=FakeCloudflare();p.publish(client,'a'*32,'b'*32,b'module')
        self.assertEqual({c[2]['pattern'] for c in client.calls if c[0]=='POST'},{p.HOST+r for r in p.PATHS})
    def test_invalid_account_no_api(self):
        client=FakeCloudflare()
        with self.assertRaises(ValueError):p.publish(client,'invalid','b'*32,b'module')
        self.assertFalse(client.calls)
    def test_latest_stable_recheck(self):
        from io import BytesIO
        for info,ok in [({'tag_name':'v1.0.0','draft':False,'prerelease':False},True),({'tag_name':'v1.0.1'},False),({'tag_name':'v1.0.0','draft':True},False)]:
            with patch.object(p.urllib.request,'urlopen',return_value=BytesIO(json.dumps(info).encode())):
                if ok:p.require_latest('v1.0.0')
                else:
                    with self.assertRaises(RuntimeError):p.require_latest('v1.0.0')
    def test_api_errors_do_not_echo_credentials(self):
        from io import BytesIO
        response={'success':False,'errors':[{'message':'token-canary'}]}
        with patch.object(p.urllib.request,'urlopen',return_value=BytesIO(json.dumps(response).encode())):
            with self.assertRaises(RuntimeError) as raised:p.Cloudflare('token-canary').request('GET','/test')
            self.assertNotIn('token-canary',str(raised.exception))


class PublicationWiringTest(unittest.TestCase):
    def test_canonical_publication_requires_exact_promoted_chain_and_rollback(self):
        import yaml
        workflows = Path(__file__).parent / 'workflows'
        if not workflows.is_dir():
            workflows = Path(__file__).resolve().parents[3] / '.github/workflows'
        document = yaml.safe_load((workflows / 'promote.yml').read_text())
        self.assertEqual(document['concurrency'], {'group': 'guard-release-promotion', 'cancel-in-progress': False, 'queue': 'max'})
        self.assertEqual(document['jobs']['promote']['environment'], 'promote')
        steps = document['jobs']['promote']['steps']
        admission = next(i for i, step in enumerate(steps) if '--phase prepare' in step.get('run', ''))
        publish = next(i for i, step in enumerate(steps) if '--phase publish' in step.get('run', ''))
        self.assertLess(admission, publish)
        self.assertEqual(steps[publish]['env']['INSTALLER_PUBLISH_TOKEN'], '${{ secrets.INSTALLER_PUBLISH_TOKEN }}')
        self.assertEqual(document['jobs']['rollback']['needs'], ['promote', 'canonical-smoke', 'recovery-inputs'])
        self.assertIn('always()', document['jobs']['rollback']['if'])
        self.assertFalse((workflows / 'publish.yml').exists())


if __name__ == '__main__': unittest.main()
