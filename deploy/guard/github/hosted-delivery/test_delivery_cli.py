#!/usr/bin/env python3
"""Controller integration tests, using only inert provider/admission fixtures."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('delivery_cli', Path(__file__).with_name('delivery_cli.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Integration(unittest.TestCase):
    def setUp(self):
        self.pin = {'id': 'fixture', 'target': 'customer-worker-production',
                    'sourceCommit': 'a' * 40, 'inventorySha256': 'b' * 64}
        self.payload = {'index.js': b'fixture'}
        self.env = {'CLOUDFLARE_API_TOKEN': 'synthetic-only'}

    def test_verify_has_no_provider_or_write(self):
        with patch.object(m.admit, 'acquire', return_value=self.payload), \
                patch.object(m.cloud, 'checked_payload'), patch.object(m.cloud, 'prepare_worker'), \
                patch.object(m.cloud, 'Cloudflare', side_effect=AssertionError('provider unavailable')):
            result = m.deliver(self.pin, {}, object(), 'public-read', False, {})
            self.assertIs(result['applied'], False)

    def test_write_calls_fresh_acquisition_and_refuses_changed_bytes(self):
        mutations = []
        def operation(pin, payload, policy, api, recheck):
            recheck()
            mutations.append('write')
            return {'runtimeObserved': True}
        with patch.object(m.admit, 'acquire', side_effect=[self.payload, {'index.js': b'changed'}]), \
                patch.object(m.cloud, 'checked_payload'), patch.object(m.cloud, 'Cloudflare'), \
                patch.object(m.cloud, 'publish_worker', side_effect=operation):
            with self.assertRaises(ValueError):
                m.deliver(self.pin, {}, object(), 'public-read', True, self.env)
        self.assertEqual(mutations, [])

    def test_write_rechecks_same_mapping_and_propagates_actual_receipt(self):
        with patch.object(m.admit, 'acquire', return_value=self.payload) as acquire, \
                patch.object(m.cloud, 'checked_payload'), patch.object(m.cloud, 'Cloudflare'), \
                patch.object(m.cloud, 'publish_worker', side_effect=lambda *a: (a[-1](), {'runtimeObserved': True})[1]):
            result = m.deliver(self.pin, {}, object(), 'public-read', True, self.env)
            self.assertEqual(acquire.call_count, 2)
            self.assertIs(result['applied'], True)
            self.assertIs(result['runtimeObserved'], True)

    def test_failed_provider_never_becomes_applied_receipt(self):
        with patch.object(m.admit, 'acquire', return_value=self.payload), \
                patch.object(m.cloud, 'checked_payload'), patch.object(m.cloud, 'Cloudflare'), \
                patch.object(m.cloud, 'publish_worker', side_effect=RuntimeError('unknown outcome')):
            with self.assertRaises(RuntimeError):
                m.deliver(self.pin, {}, object(), 'public-read', True, self.env)

    def test_preview_requires_access_before_publication(self):
        self.pin['target'] = 'website-preview'
        with patch.object(m.admit, 'acquire', return_value=self.payload), \
                patch.object(m.cloud, 'checked_payload'), patch.object(m.cloud, 'Cloudflare'), \
                patch.object(m.cloud, 'publish_pages') as publish:
            with self.assertRaises(ValueError):
                m.deliver(self.pin, {}, object(), 'public-read', True, self.env)
            publish.assert_not_called()

    def test_pages_verification_runs_complete_release_gate(self):
        self.pin['target'] = 'website-staging'
        with patch.object(m.admit, 'acquire', return_value=self.payload), \
                patch.object(m.cloud, 'checked_payload'), patch.object(m.cloud, 'prepare_pages', return_value={'pin': 'release'}) , \
                patch.object(m.cloud, 'complete_release_gate') as gate, \
                patch.object(m.cloud, 'Cloudflare', side_effect=AssertionError('no provider')):
            m.deliver(self.pin, {}, object(), 'public-read', False, {})
            gate.assert_called_once_with('release', 'public-read')


if __name__ == '__main__':
    unittest.main()
