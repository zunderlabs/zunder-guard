#!/usr/bin/env python3
"""Key-free flow selection and CI partition contracts; never executes Cargo."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / 'deploy/guard/github/check-flow-selection.py'
spec = importlib.util.spec_from_file_location('selection', HELPER)
selection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selection)
TESTS = (
    'the_generator_reaches_every_path',
    'the_implementation_is_the_reference',
    'the_implementation_is_the_reference_when_told_in_time',
    'the_order_of_the_reports_does_not_matter',
)
CI = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())


class SelectionTests(unittest.TestCase):
    def test_reviewed_names_are_exact(self):
        self.assertEqual(selection.FLOW_TESTS, TESTS)

    def test_each_single_exact_listing_passes(self):
        for name in TESTS:
            selection.validate_listing(name, f'{name}: test\n\n1 test, 0 benchmarks\n')

    def test_zero_duplicate_wrong_and_benchmark_listings_fail(self):
        name = TESTS[0]
        for output in ('0 tests, 0 benchmarks\n', f'{name}: test\n{name}: test\n2 tests, 0 benchmarks\n',
                       f'{TESTS[1]}: test\n1 test, 0 benchmarks\n',
                       f'{name}: benchmark\n0 tests, 1 benchmark\n',
                       f'{name}: test\n2 tests, 0 benchmarks\n', 'a' * 4097):
            with self.assertRaises(ValueError):
                selection.validate_listing(name, output)

    def test_typo_or_command_text_never_launches_cargo(self):
        for name in ('the_implementation_is_the_referenc', '$(echo bad)', TESTS[0] + '; echo bad', '--help', ''):
            with patch.object(selection.subprocess, 'run', side_effect=AssertionError('Must not execute')):
                with self.assertRaises(ValueError):
                    selection.check(name)

    def test_list_command_pins_package_target_exact_filter_and_timeout(self):
        name = TESTS[2]
        with patch.object(selection.subprocess, 'run', return_value=SimpleNamespace(stdout=f'{name}: test\n\n1 test, 0 benchmarks\n')) as run:
            selection.check(name)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['cargo', 'test', '--locked', '-p', 'zunder-venue', '--test', 'flows_model', name, '--', '--exact', '--list'])
        self.assertTrue(kwargs['check']);self.assertEqual(kwargs['timeout'], 900)
        self.assertNotIn('shell', kwargs)

    def test_failed_list_command_fails_shard(self):
        with patch.object(selection.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'cargo')):
            with self.assertRaises(subprocess.CalledProcessError):
                selection.check(TESTS[0])


class WorkflowTests(unittest.TestCase):
    def test_both_workflow_copies_equal(self):
        self.assertEqual((ROOT / '.github/workflows/ci.yml').read_bytes(),
                         (ROOT / 'deploy/guard/github/workflows/ci.yml').read_bytes())

    def test_exact_four_leaves_each_os_and_unchanged_case_counts(self):
        for stem, runner, cases in [('rust', 'ubuntu-24.04', '4000'), ('windows', 'windows-2025', '400')]:
            job = CI['jobs'][stem + '-flows']
            self.assertEqual(job['runs-on'], runner)
            self.assertEqual(job['strategy'], {'fail-fast': False, 'matrix': {'test': list(TESTS)}})
            self.assertEqual(job['env'], {'FLOW_TEST': '${{ matrix.test }}', 'ZUNDER_FLOWS_CASES': cases})
            self.assertNotIn('continue-on-error', job)
            steps = job['steps']
            validation = next(i for i, step in enumerate(steps) if step.get('name') == 'Require exactly one selected flow test')
            self.assertEqual(steps[validation]['run'], 'python deploy/guard/github/check-flow-selection.py "$FLOW_TEST"')
            self.assertEqual(validation + 1, len(steps) - 1)
            for step in steps:
                self.assertNotIn('continue-on-error', step)

    def test_main_linux_keeps_workspace_scope_and_exact_four_skips(self):
        steps = CI['jobs']['rust-main']['steps']
        self.assertEqual(steps[2]['run'], 'cargo fmt --all -- --check')
        self.assertEqual(steps[3]['run'], 'cargo clippy --workspace --all-targets --locked -- -D warnings')
        test = steps[4]
        self.assertEqual(test['env'], {'ZUNDER_FLOWS_CASES': '4000'})
        self.assertEqual(shlex.split(test['run']), ['cargo', 'test', '--workspace', '--locked', '--', '--exact'] +
                         [value for name in TESTS for value in ('--skip', name)])

    def test_main_windows_keeps_original_packages_and_exact_four_skips(self):
        steps = CI['jobs']['windows-main']['steps']
        self.assertEqual(steps[2]['run'], 'cargo clippy --locked --all-targets -p zunder-venue -p zunder-guard-core -p zunder-guard-mcp -p zunder-guard-rules -p zunder-guard -p zunder-redteam -- -D warnings')
        test = next(step for step in steps if step.get('name') == 'Native Windows tests (400 flow histories per property)')
        self.assertEqual(test['env'], {'ZUNDER_FLOWS_CASES': '400'})
        expected = "@('test', '--no-fail-fast', '--locked', '-p', 'zunder-venue', '-p', 'zunder-guard-core', '-p', 'zunder-guard-mcp', '-p', 'zunder-guard-rules', '-p', 'zunder-guard', '--', '--exact', " + ', '.join("'--skip', '" + name + "'" for name in TESTS) + ')'
        self.assertIn('$arguments = ' + expected, test['run'])
        self.assertTrue(any(step.get('shell') == 'powershell' and 'installer-windows.ps1' in step.get('run', '') for step in steps))
        self.assertTrue(any(step.get('shell') == 'pwsh' and 'installer-windows.ps1' in step.get('run', '') for step in steps))
        diagnostics = steps[-1]
        self.assertEqual(diagnostics['if'], 'failure()')
        self.assertIn('Show-Acl', diagnostics['run'])

    def test_windows_wrapper_is_identical_except_arguments(self):
        main = next(step['run'] for step in CI['jobs']['windows-main']['steps'] if step.get('name') == 'Native Windows tests (400 flow histories per property)')
        shard = CI['jobs']['windows-flows']['steps'][-1]['run']
        normalized = lambda script: '\n'.join(line for line in script.splitlines() if not line.strip().startswith('$arguments = '))
        self.assertEqual(normalized(main), normalized(shard))
        for required in ('$null = $tests.Handle', 'WaitForExit(30000)', 'Get-CimInstance', 'CpuSeconds',
                         'ReadOperationCount, WriteOperationCount, WriteTransferCount', '$testExit = $tests.ExitCode',
                         'taskkill.exe', '/T /F', '$tests.Dispose()', 'exit $testExit'):
            self.assertIn(required, shard)
        self.assertIn("'-p', 'zunder-venue', '--test', 'flows_model', $env:FLOW_TEST, '--', '--exact'", shard)

    def test_linux_shard_invocation_is_exact(self):
        self.assertEqual(CI['jobs']['rust-flows']['steps'][-1]['run'],
                         'cargo test --locked -p zunder-venue --test flows_model "$FLOW_TEST" -- --exact')

    def test_required_stable_aggregators_are_always_strict(self):
        for stem in ('rust', 'windows'):
            job = CI['jobs'][stem]
            self.assertEqual(job['name'], stem);self.assertEqual(job['if'], 'always()')
            self.assertEqual(job['needs'], [stem + '-main', stem + '-flows'])
            self.assertEqual(job['runs-on'], 'ubuntu-24.04')
            self.assertNotIn('continue-on-error', job)
            code = job['steps'][0]['run']
            for result in ('success', 'failure', 'cancelled', 'skipped', 'unknown'):
                for failed_dependency in job['needs']:
                    needs = {dep: {'result': result if dep == failed_dependency else 'success'} for dep in job['needs']}
                    env = dict(os.environ, REQUIRED_RESULTS=json.dumps(needs))
                    response = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, timeout=5)
                    self.assertEqual(response.returncode == 0, result == 'success')
            for needs in ({}, {stem + '-main': {'result': 'success'}},
                          {dep: {'result': 'success'} for dep in job['needs'] + ['foreign']}):
                response = subprocess.run([sys.executable, '-c', code], env=dict(os.environ, REQUIRED_RESULTS=json.dumps(needs)), capture_output=True, timeout=5)
                self.assertNotEqual(response.returncode, 0)

    def test_read_only_permissions_no_secret_or_publication_actions(self):
        self.assertEqual(CI['permissions'], {'contents': 'read'})
        for stem in ('rust', 'windows'):
            for suffix in ('', '-main', '-flows'):
                text = json.dumps(CI['jobs'][stem + suffix])
                self.assertNotIn('secrets.', text);self.assertNotIn('contents: write', text)
                self.assertNotIn('continue-on-error', text)

    def test_offline_contract_registered_after_existing_yaml_install(self):
        steps = CI['jobs']['scripts']['steps']
        selected = next(i for i, step in enumerate(steps) if step.get('run') == 'python3 -B deploy/guard/github/test_flow_shards.py')
        self.assertTrue(any('PyYAML==6.0.3' in step.get('run', '') for step in steps[:selected]))


if __name__ == '__main__':
    unittest.main()
