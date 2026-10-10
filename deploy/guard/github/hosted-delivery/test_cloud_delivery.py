#!/usr/bin/env python3
"""Synthetic adapter regression fixtures; no cloud or payment operations."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('public_cloud_delivery', Path(__file__).with_name('cloud_delivery.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def release_fixture():
    base = 'https://github.com/zunderlabs/zunder-guard'
    url = base + '/releases/download/v1.0.4'
    assets = {'zunder-guard-v1.0.4.image.txt': {'url': url + '/zunder-guard-v1.0.4.image.txt', 'sha256': '1' * 64}}
    sums = ('1' * 64 + '  zunder-guard-v1.0.4.image.txt\n').encode()
    pin = {'schema': 1, 'version': '1.0.4', 'sourceCommit': 'a' * 40, 'published': True,
           'publishedAt': '2026-10-10T00:00:00Z', 'releaseId': 12, 'releaseUrl': base + '/releases/tag/v1.0.4',
           'assetsUrl': url, 'signedAssetManifest': {'url': url + '/SHA256SUMS', 'sha256': m.sha(sums),
           'sigstoreBundleUrl': url + '/SHA256SUMS.sigstore.json', 'provenanceUrl': url + '/zunder-guard-v1.0.4.intoto.jsonl'},
           'image': {'reference': 'ghcr.io/zunderlabs/zunder-guard@sha256:' + '2' * 64, 'descriptorAsset': 'zunder-guard-v1.0.4.image.txt'},
           'assets': assets, 'channels': {'unixInstallerUrl': None, 'windowsInstallerUrl': None, 'awsTemplateUrl': None, 'homebrewReady': False}}
    return pin, sums


def seal(kind, target, payload, config=None, release=None):
    files = [{'path': name, 'size': len(payload[name]), 'sha256': m.sha(payload[name])} for name in sorted(payload, key=lambda x: x.split('/'))]
    return {'kind': kind, 'target': target, 'sourceCommit': 'a' * 40, 'inventorySha256': m.sha(m.compact(files)),
            'config': {'path': config, 'sha256': m.sha(payload[config])} if config else None,
            'releasePin': {'path': release, 'sha256': m.sha(payload[release])} if release else None}


def pages_fixture(target='website-preview'):
    folder, project, _ = m.PROJECTS[target]
    release, _ = release_fixture()
    payload = {folder + '/index.html': b'<main>fixture</main>', folder + '/release-pin.json': m.compact(release),
               folder + '/deployment-profile.json': m.compact({'profile': 'staging' if folder == 'staging' else 'production', 'releasePublished': True, 'releaseVersion': '1.0.4'})}
    merchant = '0x' + '4' * 40
    if folder == 'staging':
        payload[folder + '/staging-payment-profile.json'] = m.compact({'schema': 1, 'merchant': merchant, 'stagingFixtureOnly': False})
    pin = seal('website', target, payload, release=folder + '/release-pin.json')
    policy = {'schema': 1, 'target': target, 'accountId': 'a' * 32, 'project': project, 'branch': 'main', 'stagingMerchant': merchant, 'requireAccess': target != 'website-production'}
    return pin, payload, policy


def worker_fixture():
    variables = {'DEPLOYMENT_PROFILE': 'production', 'ENVIRONMENT': 'production', 'LICENCE_CHAIN': 'mainnet',
                 'SITE_URL': 'https://zunderlabs.com', 'SALES_EVM_NETWORKS': 'arbitrum,base'}
    config = 'name = "zunder-waitlist"\nmain = "bundle/index.js"\ncompatibility_date = "2026-10-01"\n[vars]\n'
    config += '\n'.join(k + ' = "' + v + '"' for k, v in variables.items())
    config += '\n[[d1_databases]]\nbinding = "DB"\ndatabase_id = "11111111-1111-4111-8111-111111111111"\n'
    payload = {'wrangler.toml': config.encode(), 'bundle/index.js': b'export default { fetch(){ return new Response("fixture") } };',
               'migrations/0001.sql': b'-- present as data; never run\n'}
    pin = seal('customer-worker', 'customer-worker-production', payload, config='wrangler.toml')
    policy = {'schema': 1, 'target': 'customer-worker-production', 'accountId': 'a' * 32, 'zoneId': 'b' * 32,
              'worker': 'zunder-waitlist', 'migrations': 'none', 'compatibilityDate': '2026-10-01', 'compatibilityFlags': [],
              'vars': variables, 'databaseId': '11111111-1111-4111-8111-111111111111'}
    return pin, payload, policy


class AdapterTests(unittest.TestCase):
    def test_payload_mutation_and_private_pages_hooks_refused(self):
        pin, payload, policy = pages_fixture()
        self.assertEqual(m.prepare_pages(pin, payload, policy)['project'], 'zunder-design-preview')
        changed = {**payload, 'preview/index.html': b'changed'}
        with self.assertRaises(ValueError):
            m.prepare_pages(pin, changed, policy)
        for hook in ['preview/functions/evil.js', 'preview/package.json', 'preview/wrangler.toml']:
            changed = {**payload, hook: b'execution hook'}
            new_pin = seal('website', 'website-preview', changed, release='preview/release-pin.json')
            with self.assertRaises(ValueError):
                m.prepare_pages(new_pin, changed, policy)

    def test_real_staging_profile_merchant_and_binding_fences(self):
        pin, payload, policy = pages_fixture('website-staging')
        plan = m.prepare_pages(pin, payload, policy)
        info = {'name': plan['project'], 'production_branch': 'main', 'deployment_configs': {'production': {
            'env_vars': {'DEPLOYMENT_PROFILE': {'value': 'staging'}, 'TESTNET_SITE_ENABLED': {'value': 'explicitly-provisioned'}},
            'services': {'TESTNET_JOURNEY_API': {'service': 'zunder-testnet-journey-api', 'environment': 'production'}, 'TESTNET_INBOX': {'service': 'zunder-testnet-journey-inbox', 'environment': ''}}}}}
        m.pages_target(info, plan, policy)
        changed = copy.deepcopy(info)
        changed['deployment_configs']['production']['services']['CUSTOMER_API'] = {'service': 'zunder-waitlist', 'environment': ''}
        with self.assertRaises(ValueError):
            m.pages_target(changed, plan, policy)
        with self.assertRaises(ValueError):
            m.prepare_pages(pin, payload, {**policy, 'stagingMerchant': '0x' + '3' * 40})

    def test_pages_official_services_field_exact_default_handler_environment(self):
        pin, payload, policy = pages_fixture()
        plan = m.prepare_pages(pin, payload, policy)
        info = {'name': policy['project'], 'production_branch': 'main', 'deployment_configs': {'production': {
            'services': {'CUSTOMER_API': {'service': 'zunder-waitlist', 'environment': ''}}}}}
        m.pages_target(info, plan, policy)
        explicit = copy.deepcopy(info)
        explicit['deployment_configs']['production']['services']['CUSTOMER_API']['environment'] = 'production'
        m.pages_target(explicit, plan, policy)
        for binding in [{'service': 'other', 'environment': ''}, {'service': m.WORKER, 'environment': 'preview'},
                        {'service': m.WORKER}, {'service': m.WORKER, 'environment': None},
                        {'service': m.WORKER, 'environment': '', 'entrypoint': 'MyHandler'},
                        {'service': m.WORKER, 'environment': '', 'entrypoint': ''},
                        {'service': m.WORKER, 'environment': '', 'unknown': True}]:
            changed = copy.deepcopy(info)
            changed['deployment_configs']['production']['services']['CUSTOMER_API'] = binding
            with self.assertRaises(ValueError):
                m.pages_target(changed, plan, policy)
        for config in [{}, {'service_bindings': info['deployment_configs']['production']['services']},
                       {'services': None}, {'services': info['deployment_configs']['production']['services'], 'service_bindings': {}},
                       {'services': {**info['deployment_configs']['production']['services'], 'UNREVIEWED': {'service': 'other', 'environment': ''}}}]:
            changed = {**info, 'deployment_configs': {'production': config}}
            with self.assertRaises(ValueError):
                m.pages_target(changed, plan, policy)

    def test_full_gate_pin_binding_refuses_self_claims_and_inventory_drift(self):
        pin, sums = release_fixture()
        m.parse_release(pin)
        source = {'tag': 'v1.0.4', 'source': pin['sourceCommit']}
        native = {**source, 'manifest_sha256': m.sha(sums), 'release_id': 12, 'draft': False, 'image': pin['image']['reference']}
        release = {'id': 12, 'tag_name': 'v1.0.4', 'draft': False, 'prerelease': False, 'published_at': pin['publishedAt']}
        m.bind_release(pin, sums, source, native, release, pin['image']['reference'])
        for patch_ in [{'release_id': 99}, {'draft': True}, {'source': 'c' * 40}, {'manifest_sha256': 'd' * 64}]:
            with self.assertRaises(ValueError):
                m.bind_release(pin, sums, source, {**native, **patch_}, release, pin['image']['reference'])
        with self.assertRaises(ValueError):
            m.parse_release({**pin, 'assetsUrl': 'https://attacker.invalid'})
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'AUTHORITY', Path(tmp)):
            with self.assertRaises(ValueError):
                m.complete_release_gate(pin, 'public-read')

    def test_pages_full_gate_failure_happens_before_any_provider_read_or_write(self):
        pin, payload, policy = pages_fixture()
        class RefuseAPI:
            def request(self, *args):
                raise AssertionError('Provider called before full gate passed')
        def gate(*args):
            raise ValueError('Native acceptance missing')
        with self.assertRaisesRegex(ValueError, 'Native acceptance'):
            m.publish_pages(pin, payload, policy, RefuseAPI(), 'public-read', 'cf-scoped', {}, lambda: None, gate=gate)

    def test_pages_runtime_identity_and_access_are_fixed_to_target(self):
        pin, payload, policy = pages_fixture()
        plan = m.prepare_pages(pin, payload, policy)
        def read(url, access):
            if url.endswith('/release-pin.json'):
                return plan['files']['release-pin.json'], {}
            if url.endswith('/deployment-profile.json'):
                return plan['files']['deployment-profile.json'], {}
            return b'<main><meta name="zunder-deployment-profile" content="production"></main>', {}
        self.assertTrue(m.pages_smoke(plan, {'CF-Access-Client-Id': 'synthetic-id', 'CF-Access-Client-Secret': 'synthetic-secret'}, read)['runtimeObserved'])
        with self.assertRaises(ValueError):
            m.pages_smoke(plan, {}, read)
        with self.assertRaises(ValueError):
            m.pages_smoke(plan, {'CF-Access-Client-Secret': 'incomplete'}, read)
        production = {**plan, 'target': 'website-production'}
        with self.assertRaises(ValueError):
            m.pages_smoke(production, {'CF-Access-Client-Id': 'id', 'CF-Access-Client-Secret': 'secret'}, read)

    def test_pages_exact_public_uploader_and_canonical_deployment_bracket(self):
        pin, payload, policy = pages_fixture()
        deployed_id = '11111111-1111-4111-8111-111111111111'
        rechecks, runs, gates = [], [], []
        class API:
            def request(self, method, endpoint):
                self_outer.assertEqual(method, 'GET')
                return {'name': policy['project'], 'production_branch': 'main',
                        'deployment_configs': {'production': {'services': {'CUSTOMER_API': {'service': m.WORKER, 'environment': ''}}}},
                        'canonical_deployment': {'id': deployed_id if runs else 'old'}}
        self_outer = self
        def run(args, cwd, env):
            self.assertEqual(args[:2], ['node', str(m.HERE / 'pages-upload.mjs')])
            self.assertEqual(set(env) - {'PATH', 'HOME', 'TMPDIR'}, {'CLOUDFLARE_API_TOKEN'})
            self.assertEqual(env['CLOUDFLARE_API_TOKEN'], 'cf-synthetic')
            self.assertEqual((Path(args[2]) / 'index.html').read_bytes(), payload['preview/index.html'])
            self.assertEqual(args[3:7], [policy['accountId'], policy['project'], policy['branch'], pin['sourceCommit']])
            self.assertEqual(len(rechecks), 1)
            runs.append(True)
            return m.compact({'deploymentId': deployed_id, 'sourceCommit': pin['sourceCommit'], 'project': policy['project']})
        def read(url, access):
            for name in ['release-pin.json', 'deployment-profile.json']:
                if url.endswith('/' + name):
                    return payload['preview/' + name], {}
            return b'<main><meta name="zunder-deployment-profile" content="production"></main>', {}
        receipt = m.publish_pages(pin, payload, policy, API(), 'public-read', 'cf-synthetic',
                                  {'CF-Access-Client-Id': 'synthetic', 'CF-Access-Client-Secret': 'synthetic'},
                                  lambda: rechecks.append(True), read=read, run=run, gate=lambda *args: gates.append(args))
        self.assertEqual(receipt['deploymentId'], deployed_id)
        self.assertEqual(len(gates), 1)
        class Stale(API):
            def request(self, method, endpoint):
                info = super().request(method, endpoint)
                info['canonical_deployment']['id'] = 'unrelated'
                return info
        with self.assertRaisesRegex(ValueError, 'Canonical Pages'):
            m.publish_pages(pin, payload, policy, Stale(), 'public-read', 'cf-synthetic', {}, lambda: None,
                            read=read, run=lambda *args: m.compact({'deploymentId': deployed_id, 'sourceCommit': pin['sourceCommit'], 'project': policy['project']}), gate=lambda *args: None)

    def test_worker_reads_config_as_data_and_refuses_hooks_migrations_and_wrong_database(self):
        pin, payload, policy = worker_fixture()
        plan = m.prepare_worker(pin, payload, policy)
        self.assertEqual(set(plan['modules']), {'index.js'})
        self.assertNotIn('migrations/0001.sql', plan['modules'])
        for changed_policy in [{**policy, 'migrations': 'apply'}, {**policy, 'databaseId': 'wrong'}]:
            with self.assertRaises(ValueError):
                m.prepare_worker(pin, payload, changed_policy)
        changed = {**payload, 'wrangler.toml': payload['wrangler.toml'] + b'\n[build]\ncommand = "private-shell-command"\n'}
        new_pin = seal('customer-worker', 'customer-worker-production', changed, config='wrangler.toml')
        with self.assertRaises(ValueError):
            m.prepare_worker(new_pin, changed, policy)

    def test_worker_route_and_binding_drift_refused(self):
        _, _, policy = worker_fixture()
        routes = [{'id': str(i), 'pattern': pattern, 'script': 'zunder-waitlist'} for i, pattern in enumerate(['zunderlabs.com/api/waitlist*', 'zunderlabs.com/api/contact', 'zunderlabs.com/api/licence*'])]
        m.worker_routes(routes)
        with self.assertRaises(ValueError):
            m.worker_routes(routes + [{'id': 'override', 'pattern': 'zunderlabs.com/api/licence/status', 'script': None}])
        resources = {'script_runtime': {'compatibility_date': policy['compatibilityDate'], 'compatibility_flags': []},
                     'bindings': [{'type': 'plain_text', 'name': k, 'text': v} for k, v in policy['vars'].items()]
                     + [{'type': 'd1', 'name': 'DB', 'id': policy['databaseId']}, {'type': 'secret_text', 'name': 'SALES_ADMIN_TOKEN'}]}
        self.assertIn('secret_text', m.worker_bindings(resources, policy))
        changed = copy.deepcopy(resources)
        changed['bindings'][0]['text'] = 'staging'
        with self.assertRaises(ValueError):
            m.worker_bindings(changed, policy)

    def test_worker_upload_metadata_preserves_binding_types_without_private_config_or_secret_values(self):
        pin, payload, policy = worker_fixture()
        plan = m.prepare_worker(pin, payload, policy)
        body, mime = m.multipart_modules(plan, ['plain_text', 'secret_text', 'd1'])
        self.assertIn(b'"keep_bindings":["plain_text","secret_text","d1"]', body)
        self.assertNotIn(b'private-shell-command', body)
        self.assertNotIn(b'migrations/0001.sql', body)
        self.assertNotIn(b'SALES_ADMIN_TOKEN', body)
        self.assertTrue(mime.startswith('multipart/form-data;'))


    def test_worker_exact_upload_and_bracketed_runtime_observation_never_execute_payload_or_sql(self):
        pin, payload, policy = worker_fixture()
        plan = m.prepare_worker(pin, payload, policy)
        class API:
            def __init__(self, missing_etag=False):
                self.uploads, self.missing_etag = 0, missing_etag
            def request(self, method, endpoint, data=None, content_type=None):
                if method == 'PUT':
                    self.uploads += 1
                    self_outer.assertTrue(endpoint.endswith('/workers/scripts/zunder-waitlist'))
                    self_outer.assertNotIn(b'migrations/0001.sql', data)
                    self_outer.assertTrue(content_type.startswith('multipart/'))
                    return {'id': 'zunder-waitlist'}
                self_outer.assertEqual(method, 'GET')
                if endpoint.startswith('/zones/') and not endpoint.endswith('/workers/routes'):
                    return {'name': 'zunderlabs.com', 'account': {'id': policy['accountId']}}
                if endpoint.endswith('/workers/routes'):
                    return [{'id': str(i), 'pattern': p, 'script': 'zunder-waitlist'} for i, p in enumerate(['zunderlabs.com/api/waitlist*', 'zunderlabs.com/api/contact', 'zunderlabs.com/api/licence*'])]
                if endpoint.endswith('/deployments'):
                    return {'deployments': [{'id': '44444444-4444-4444-8444-444444444444', 'strategy': 'percentage', 'versions': [{'version_id': '22222222-2222-4222-8222-222222222222', 'percentage': 100}]}]}
                if '/versions/' in endpoint:
                    return {'id': '22222222-2222-4222-8222-222222222222', 'resources': {'script': {'etag': 'opaque-etag'},
                            'script_runtime': {'compatibility_date': policy['compatibilityDate'], 'compatibility_flags': []},
                            'bindings': [{'type': 'plain_text', 'name': k, 'text': v} for k, v in policy['vars'].items()] + [{'type': 'd1', 'name': 'DB', 'id': policy['databaseId']}, {'type': 'secret_text', 'name': 'PRIVATE_KEY_NAME_ONLY'}]}}
                raise AssertionError('Unexpected provider endpoint')
            def raw(self, method, endpoint):
                self_outer.assertEqual(method, 'GET')
                self_outer.assertTrue(endpoint.endswith('/content/v2'))
                value = plan['modules']['index.js'] if self.uploads else b'old-script'
                body = b'--fixture\r\nContent-Disposition: form-data; name="index.js"; filename="index.js"\r\nContent-Type: application/javascript+module\r\n\r\n' + value + b'\r\n--fixture--\r\n'
                headers = {'content-type': 'multipart/form-data; boundary=fixture', 'cf-entrypoint': 'index.js'}
                if not self.missing_etag:
                    headers['etag'] = '"opaque-etag"'
                return body, headers
        self_outer = self
        rechecks = []
        def read(url, headers):
            self.assertTrue(url.startswith(m.STATUS + '?delivery_smoke='))
            self.assertEqual(headers, {'Cache-Control': 'no-cache'})
            return m.compact({'ok': True, 'open': True, 'chain': 'mainnet', 'message': None, 'networks': ['hyperliquid', 'arbitrum', 'base']}), {'cache-control': 'no-store'}
        api = API()
        receipt = m.publish_worker(pin, payload, policy, api, lambda: rechecks.append('authenticated public admission'), read)
        self.assertEqual(api.uploads, 1)
        self.assertEqual(len(rechecks), 1)
        self.assertTrue(receipt['runtimeObserved'])
        self.assertFalse(receipt['responseVersionIdentity'])
        self.assertFalse(receipt['migrationsApplied'])
        missing = API(missing_etag=True)
        with self.assertRaises(ValueError):
            m.publish_worker(pin, payload, policy, missing, lambda: None, read)
        self.assertEqual(missing.uploads, 0)


if __name__ == '__main__':
    unittest.main()
