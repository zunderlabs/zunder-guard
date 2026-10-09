#!/usr/bin/env python3
"""Offline exact installer fragments; no keys, network, service or filesystem writes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
ADMISSION = SOURCE.split('# A named sending service is a fresh installation,', 1)[1].split('\nif [ "$CONTAINER" -eq 1 ]; then', 1)[0]
ADMISSION = '# A named sending service is a fresh installation,' + ADMISSION
PREFLIGHT = SOURCE.split('# Refuse before installing a binary or touching state,', 1)[1].split('\nif [ -z "$PREFIX" ]; then', 1)[0]
PREFLIGHT = '# Refuse before installing a binary or touching state,' + PREFLIGHT
RENDER = SOURCE.split('  {\n    say "# Written by install.sh', 1)[1].split('  } | $SUDO sh -c', 1)[0]
RENDER = '  {\n    say "# Written by install.sh' + RENDER + '  }\n'
BASE = dict(SERVICE_INSTANCE='testnet', NETWORK='testnet', CONTAINER='0', NO_SERVICE='0',
            INSTALL_ONLY='0', FORCE='0', PREFIX='', RULES='zr1_fixture', ACCOUNT='0x' + 'a'*40,
            CAP='40', SHARE='1', LISTEN='127.0.0.1:8548', SERVICE_USER='zunder-guard',
            SERVICE_UNIT='zunder-guard', SERVICE_CONFIG='/etc/zunder-guard',
            SERVICE_HOME='/var/lib/zunder-guard', CRED_NAME='hl-api-wallet-key',
            CRED_ENCRYPTED='/etc/credstore.encrypted/zunder-guard.hl-api-wallet-key',
            CRED_PLAIN='/etc/zunder-guard/hl-api-wallet-key',
            MAINNET_ENV='/etc/zunder-guard/mainnet-confirm.env')
FUNCTIONS = 'die() { printf "%s\\n" "$*" >&2; exit 1; }; say() { printf "%s\\n" "$*"; };\n'
MOCKS = '''
priv() { [ "$1" = test ] || exit 98; [ "$3" = "${EXISTS:-}" ]; }
id() { [ "${USER_EXISTS:-0}" = 1 ]; }
ss() { [ "${SS_FAIL:-0}" = 0 ] || return 2; printf '%s' "${LISTENERS:-}"; }
'''


def run(block, **overrides):
    env = {'PATH': os.environ['PATH'], **BASE, **overrides}
    with tempfile.TemporaryDirectory() as temporary:
        tool = Path(temporary) / 'systemd-creds'
        tool.write_text('#!/bin/sh\n[ "${CREDS:-1}" = 1 ] && echo encrypt\n')
        tool.chmod(0o755)
        env['PATH'] = temporary + os.pathsep + env['PATH']
        return subprocess.run(['sh', '-eu', '-c', FUNCTIONS + block], env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True)


class NativeInstance(unittest.TestCase):
    def test_isolated_paths_and_identity(self):
        emit = '\nprintf "%s\\n" "$SERVICE_USER" "$SERVICE_UNIT" "$SERVICE_HOME" "$SERVICE_CONFIG" "$PREFIX" "$CRED_ENCRYPTED" "$CRED_PLAIN" "$MAINNET_ENV"\n'
        for network, port in [('testnet', '8548'), ('mainnet', '8549')]:
            with self.subTest(network=network):
                result = run(ADMISSION + emit, SERVICE_INSTANCE=network, NETWORK=network,
                             LISTEN='127.0.0.1:' + port)
                self.assertEqual(result.returncode, 0, result.stderr)
                name = 'zunder-guard-' + network
                self.assertEqual(result.stdout.splitlines(), [name, name, '/var/lib/' + name,
                    '/etc/' + name, '/opt/' + name + '/bin', '/etc/credstore.encrypted/' + name + '.hl-api-wallet-key',
                    '/etc/' + name + '/hl-api-wallet-key', '/etc/' + name + '/mainnet-confirm.env'])

    def test_default_paths_unchanged(self):
        result = run(ADMISSION + '\nprintf "%s\\n" "$SERVICE_HOME" "$SERVICE_USER" "$PREFIX"\n', SERVICE_INSTANCE='')
        self.assertEqual(result.stdout.splitlines(), ['/var/lib/zunder-guard', 'zunder-guard', ''])

    def test_input_refusals(self):
        cases = [dict(SERVICE_INSTANCE='../../paper'), dict(NETWORK='mainnet'), dict(NETWORK=''),
                 dict(CONTAINER='1'), dict(NO_SERVICE='1'), dict(INSTALL_ONLY='1'), dict(FORCE='1'),
                 dict(PREFIX='/usr/local/bin')]
        cases += [{field: ''} for field in ('RULES', 'ACCOUNT', 'CAP', 'SHARE')]
        cases += [dict(LISTEN=value) for value in ('', '0.0.0.0:8548', 'localhost:8548',
            '127.0.0.1:8547', '127.0.0.1:0', '127.0.0.1:01', '127.0.0.1:65536',
            '127.0.0.1:8548;touch /tmp/x', '127.0.0.1:99999999999999999999999')]
        cases += [dict(SHARE=value) for value in ('0', '1.1', '-1', '1..0', 'nan', '1e0', '0.0000000000000000000000000')]
        for values in cases:
            with self.subTest(values=values):
                self.assertNotEqual(run(ADMISSION, **values).returncode, 0)

    def test_share_positive_boundary(self):
        for value in ('0.5', '1', '1.0'):
            self.assertEqual(run(ADMISSION, SHARE=value).returncode, 0)

    def preflight(self, **overrides):
        return run(ADMISSION + MOCKS + PREFLIGHT, SERVICE='1', SUDO='priv', **overrides)

    def test_fresh_preflight_passes_without_actions(self):
        result = self.preflight()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_destinations_refuse(self):
        for target in ('/var/lib/zunder-guard-testnet', '/etc/zunder-guard-testnet',
                       '/opt/zunder-guard-testnet', '/etc/credstore.encrypted/zunder-guard-testnet.hl-api-wallet-key',
                       '/etc/systemd/system/zunder-guard-testnet.service',
                       '/etc/systemd/system/zunder-guard-testnet.service.d'):
            with self.subTest(target=target):
                result = self.preflight(EXISTS=target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('already exists', result.stderr)

    def test_dependency_identity_listener_refusals(self):
        for values in (dict(CREDS='0'), dict(USER_EXISTS='1'), dict(SS_FAIL='1'), dict(LISTENERS='LISTEN 0 128 *:8548 *:*')):
            with self.subTest(values=values):
                self.assertNotEqual(self.preflight(**values).returncode, 0)
        result = run(ADMISSION + MOCKS + PREFLIGHT, SERVICE='0', SUDO='priv')
        self.assertNotEqual(result.returncode, 0)

    def test_dropin_keeps_sandbox_and_pins_instance(self):
        for network in ('testnet', 'mainnet'):
            with self.subTest(network=network):
                result = run(ADMISSION + RENDER, SERVICE_INSTANCE=network, NETWORK=network,
                             VERSION='v1.0.2', NET=network, BIN='/opt/zunder-guard-' + network + '/bin/zunder-guard',
                             CREDENTIAL='LoadCredentialEncrypted=hl-api-wallet-key:/etc/credstore.encrypted/zunder-guard-' + network + '.hl-api-wallet-key')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('StateDirectory=\nStateDirectory=zunder-guard-' + network, result.stdout)
                self.assertIn('Environment=ZUNDER_GUARD_HOME=/var/lib/zunder-guard-' + network, result.stdout)
                self.assertIn('User=zunder-guard-' + network, result.stdout)
                self.assertIn('--key-stdin < "$$CREDENTIALS_DIRECTORY/hl-api-wallet-key"', result.stdout)
                self.assertNotIn('ProtectSystem=', result.stdout)
                self.assertEqual('EnvironmentFile=' in result.stdout, network == 'mainnet')
                if network == 'mainnet':
                    self.assertIn('EnvironmentFile=/etc/zunder-guard-mainnet/mainnet-confirm.env', result.stdout)

    def test_mainnet_first_install_stays_stopped(self):
        # Actual existing source gate, now addressed to the selected unit.
        block = SOURCE.split('  if [ "$NET" = mainnet ] && ! $SUDO test -e "$SERVICE_HOME/risk-mainnet.jsonl"; then', 1)[1].split('\n  $SUDO systemctl restart', 1)[0]
        # Expose inert mocked actions that the real script suppresses.
        block = block.replace('>/dev/null 2>&1', '')
        script = 'NET=mainnet\nif true; then' + block
        mocks = 'priv() { printf "ACTION:%s\\n" "$*"; };\n'
        result = run(mocks + script, SUDO='priv', BIN='/opt/zunder-guard-mainnet/bin/zunder-guard',
                     SERVICE_USER='zunder-guard-mainnet', SERVICE_UNIT='zunder-guard-mainnet',
                     SERVICE_HOME='/var/lib/zunder-guard-mainnet', KEY_FILE='')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ACTION:systemctl stop zunder-guard-mainnet', result.stdout)
        self.assertNotIn('ACTION:systemctl start', result.stdout)
        self.assertNotIn('ACTION:systemctl restart', result.stdout)
        self.assertIn('journal-init --mode mainnet', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
