#!/usr/bin/env python3
"""Key-free flow selection and CI partition contracts; never executes Cargo."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / 'deploy/guard/github/check-flow-selection.py'
spec = importlib.util.spec_from_file_location('selection', HELPER)
selection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selection)
PLANNER = ROOT / 'deploy/guard/github/windows-test-shards.py'
spec = importlib.util.spec_from_file_location('shards', PLANNER)
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)
TESTS = (
    'the_generator_reaches_every_path',
    'the_implementation_is_the_reference',
    'the_implementation_is_the_reference_when_told_in_time',
    'the_order_of_the_reports_does_not_matter',
)
SOURCE_CI = ROOT / 'deploy/guard/github/workflows/ci.yml'
CI_PATH = SOURCE_CI if SOURCE_CI.exists() else ROOT / '.github/workflows/ci.yml'
CI = yaml.safe_load(CI_PATH.read_text())


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


def metadata(extra_tests=(), drop=(), **changes):
    """A `cargo metadata --no-deps` fixture shaped like the six Windows-tested packages."""
    layout = {
        'zunder-venue': ['flows_model', 'flows_regressions'],
        'zunder-venue-types': [],
        'zunder-guard-core': ['licence_vectors', 'wire_golden'],
        'zunder-guard-mcp': ['end_to_end', 'wire_golden'],
        'zunder-guard-rules': [],
        'zunder-guard': ['cli', 'end_to_end', 'journal', 'pilot', 'stream', 'hip3', *extra_tests],
    }
    packages = []
    for name, tests in layout.items():
        if name in drop:
            continue
        targets = [{'kind': ['lib'], 'crate_types': ['lib'], 'name': name.replace('-', '_'), 'test': True, 'doctest': True},
                   {'kind': ['custom-build'], 'crate_types': ['bin'], 'name': 'build-script-build', 'test': False, 'doctest': False}]
        if name in ('zunder-guard', 'zunder-guard-mcp'):
            targets.append({'kind': ['bin'], 'crate_types': ['bin'], 'name': name, 'test': True, 'doctest': False})
        if name == 'zunder-guard':
            targets.append({'kind': ['example'], 'crate_types': ['bin'], 'name': 'windows_service_fixture', 'test': False, 'doctest': False})
        targets += [{'kind': ['test'], 'crate_types': ['bin'], 'name': test, 'test': True, 'doctest': False} for test in tests]
        for (package, target), change in changes.get('targets', {}).items():
            if package == name:
                next(t for t in targets if t['name'] == target).update(change)
        packages.append({'name': name, 'id': f'path+file:///w/{name}#0.1.0', 'targets': targets})
    other = {'name': 'another-crate', 'id': 'path+file:///w/another-crate#0.1.0',
             'targets': [{'kind': ['test'], 'crate_types': ['bin'], 'name': 'another_test', 'test': True, 'doctest': False}]}
    return {'packages': packages + [other], 'workspace_members': [p['id'] for p in packages + [other]]}


class ShardPlanTests(unittest.TestCase):
    PACKAGES = ['-p', 'zunder-venue', '-p', 'zunder-venue-types', '-p', 'zunder-guard-core',
                '-p', 'zunder-guard-mcp', '-p', 'zunder-guard-rules', '-p', 'zunder-guard']
    LIBTEST = ['--', '--exact'] + [value for name in TESTS for value in ('--skip', name)]

    def test_packages_and_libtest_arguments_are_the_original_command(self):
        # windows-main ran: cargo test --no-fail-fast --locked -p <these six> -- --exact --skip <the four>.
        self.assertEqual(shards.FLOW_TESTS, TESTS)
        self.assertEqual(['--', *shards.LIBTEST], self.LIBTEST)
        clippy = next(step['run'] for step in CI['jobs']['windows-main']['steps'] if step.get('run', '').startswith('cargo clippy'))
        self.assertEqual([value for name in shards.PACKAGES for value in ('-p', name)] + ['-p', 'zunder-redteam'],
                         [value for value in shlex.split(clippy) if value == '-p' or value.startswith('zunder-')])

    def test_exact_invocations_per_shard(self):
        head = ['test', '--no-fail-fast', '--locked'] + self.PACKAGES
        fixture = metadata()
        self.assertEqual(shards.invocations(fixture, 'pilot'), [head + ['--test', 'pilot'] + self.LIBTEST])
        self.assertEqual(shards.invocations(fixture, 'io'),
                         [head + ['--test', 'end_to_end', '--test', 'journal', '--test', 'stream'] + self.LIBTEST])
        rest = ['cli', 'flows_model', 'flows_regressions', 'hip3', 'licence_vectors', 'wire_golden']
        self.assertEqual(shards.invocations(fixture, 'rest'), [
            head + ['--lib', '--bins'] + [value for name in rest for value in ('--test', name)] + self.LIBTEST,
            head + ['--doc'] + self.LIBTEST,
            ['build', '--locked', '--profile', 'test'] + self.PACKAGES + ['--examples'],
        ])

    def test_partition_is_disjoint_and_complete_and_new_tests_land_in_rest(self):
        fixture = metadata(extra_tests=('brand_new',))
        plan = shards.partition(fixture)
        named = [name for tests in plan.values() for name in tests]
        self.assertEqual(len(named), len(set(named)))
        self.assertEqual(set(named), shards.targets(fixture)['test'])
        self.assertIn('brand_new', plan['rest'])
        self.assertNotIn('another_test', named)  # other packages are not Windows-tested
        # Every test invocation selects all six packages: features resolve as in one command.
        for shard in shards.SHARDS:
            for run in shards.invocations(fixture, shard):
                self.assertEqual([v for v in run if v == '-p' or v.startswith('zunder-')], self.PACKAGES)

    def test_unreviewed_or_missing_targets_refuse(self):
        refused = [
            metadata(drop=('zunder-guard-rules',)),
            metadata(targets={('zunder-guard', 'pilot'): {'name': 'pilot_renamed'}}),
            metadata(targets={('zunder-guard', 'cli'): {'kind': ['bench']}}),
            metadata(targets={('zunder-guard', 'cli'): {'required-features': ['x']}}),
            metadata(targets={('zunder-guard', 'cli'): {'test': False}}),
            metadata(targets={('zunder-guard', 'zunder_guard'): {'doctest': False}}),
            metadata(targets={('zunder-guard', 'zunder_guard'): {'crate_types': ['proc-macro']}}),
            metadata(targets={('zunder-guard', 'windows_service_fixture'): {'test': True}}),
            metadata(targets={('zunder-guard', 'hip3'): {'name': '--doc'}}),
            metadata(targets={('zunder-guard', 'hip3'): {'kind': ['test', 'lib']}}),
        ]
        for fixture in refused:
            with self.subTest(fixture=fixture), self.assertRaises(shards.PlanError):
                shards.invocations(fixture, 'rest')
        duplicated = metadata()
        duplicated['packages'].append(dict(duplicated['packages'][0], id='path+file:///w/copy#0.1.0'))
        duplicated['workspace_members'].append('path+file:///w/copy#0.1.0')
        with self.assertRaises(shards.PlanError):
            shards.partition(duplicated)
        with self.assertRaises(shards.PlanError):
            shards.invocations(metadata(), 'everything')

    def test_plan_command_writes_the_shard_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'metadata.json'
            out = Path(directory) / 'plan.json'
            source.write_text(json.dumps(metadata()))
            result = subprocess.run([sys.executable, '-B', str(PLANNER), 'plan', 'io', '--out', str(out), '--metadata', str(source)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(out.read_text()), shards.invocations(metadata(), 'io'))
            self.assertIn('rest: cli flows_model', result.stdout)
            out.unlink()
            source.write_text(json.dumps(metadata(targets={('zunder-guard', 'stream'): {'name': 'streams'}})))
            result = subprocess.run([sys.executable, '-B', str(PLANNER), 'plan', 'io', '--out', str(out), '--metadata', str(source)],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('stream', result.stderr)
            self.assertFalse(out.exists())

    def test_named_tests_exist_in_this_tree(self):
        # The source tree's integration tests (Cargo's auto-discovery: tests/<name>.rs).
        for names in shards.NAMED.values():
            for name in names:
                self.assertTrue((ROOT / 'crates/zunder-guard/tests' / f'{name}.rs').is_file(), name)


class WorkflowTests(unittest.TestCase):

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
        self.assertTrue(any(step.get('run') == 'cargo fmt --all -- --check' for step in steps))
        self.assertTrue(any(step.get('run') == 'cargo clippy --workspace --all-targets --locked -- -D warnings' for step in steps))
        test = next(step for step in steps if step.get('run', '').startswith('cargo test --workspace'))
        self.assertEqual(test['env'], {'ZUNDER_FLOWS_CASES': '4000'})
        self.assertEqual(shlex.split(test['run']), ['cargo', 'test', '--workspace', '--locked', '--', '--exact'] +
                         [value for name in TESTS for value in ('--skip', name)])

    def test_main_windows_keeps_clippy_installers_and_diagnostics_but_no_tests(self):
        steps = CI['jobs']['windows-main']['steps']
        self.assertTrue(any(step.get('run') == 'cargo clippy --locked --all-targets -p zunder-venue -p zunder-venue-types -p zunder-guard-core -p zunder-guard-mcp -p zunder-guard-rules -p zunder-guard -p zunder-redteam -- -D warnings' for step in steps))
        # The native tests moved to windows-tests; nothing here runs `cargo test`.
        self.assertFalse(any('cargo' in step.get('run', '') and "'test'" in step.get('run', '') for step in steps))
        self.assertFalse(any('cargo test' in step.get('run', '') for step in steps))
        self.assertTrue(any(step.get('shell') == 'powershell' and 'installer-windows.ps1' in step.get('run', '') for step in steps))
        self.assertTrue(any(step.get('shell') == 'pwsh' and 'installer-windows.ps1' in step.get('run', '') for step in steps))
        diagnostics = steps[-1]
        self.assertEqual(diagnostics['if'], 'failure()')
        self.assertIn('Show-Acl', diagnostics['run'])

    def test_windows_tests_run_every_planned_shard_with_the_original_environment(self):
        job = CI['jobs']['windows-tests']
        self.assertEqual(job['runs-on'], 'windows-2025')
        self.assertEqual(job['strategy'], {'fail-fast': False, 'matrix': {'shard': list(shards.SHARDS)}})
        self.assertEqual(job['env'], {'TEST_SHARD': '${{ matrix.shard }}'})
        self.assertNotIn('continue-on-error', json.dumps(job))
        steps = job['steps']
        names = [step.get('name') for step in steps]
        plan = names.index("Plan this shard from the workspace's test targets")
        test = names.index('Native Windows tests (400 flow histories per property)')
        self.assertLess(plan, test)
        self.assertEqual(steps[plan]['run'], 'python deploy/guard/github/windows-test-shards.py plan "$TEST_SHARD" '
                                             '--out "$RUNNER_TEMP/windows-test-shard.json"')
        self.assertEqual(steps[test]['env'], {'ZUNDER_FLOWS_CASES': '400', 'RUST_TEST_THREADS': '1'})
        self.assertEqual(steps[test]['shell'], 'pwsh')
        self.assertIn("$runs = Get-Content -Raw -LiteralPath (Join-Path $env:RUNNER_TEMP 'windows-test-shard.json') "
                      "| ConvertFrom-Json -NoEnumerate", steps[test]['run'])
        # Every invocation runs; the step fails if any did.
        for required in ('foreach ($arguments in $runs)', 'if ($testExit -ne 0 -and $stepExit -eq 0) { $stepExit = $testExit }',
                         'exit $stepExit', "if ($runs.Count -lt 1) { throw 'No Cargo invocation to run' }"):
            self.assertIn(required, steps[test]['run'])
        self.assertEqual(steps[-1], CI['jobs']['windows-main']['steps'][-1])

    def test_windows_tests_share_one_cache_that_only_rest_saves(self):
        steps = CI['jobs']['windows-tests']['steps']
        restore = next(step for step in steps if step.get('uses', '').startswith('actions/cache/restore@'))
        save = next(step for step in steps if step.get('uses', '').startswith('actions/cache/save@'))
        self.assertEqual(restore['id'], 'cache')
        main = next(step for step in CI['jobs']['windows-main']['steps'] if step.get('uses', '').startswith('actions/cache@'))
        self.assertEqual(restore['with'], main['with'])
        self.assertNotIn('matrix', restore['with']['key'])
        self.assertEqual(save['with'], {'path': main['with']['path'], 'key': '${{ steps.cache.outputs.cache-primary-key }}'})
        self.assertEqual(save['if'], "matrix.shard == 'rest' && steps.cache.outputs.cache-hit != 'true'")
        self.assertGreater(steps.index(save), next(i for i, step in enumerate(steps) if step.get('name', '').startswith('Native Windows tests')))
        self.assertIn(shards.REST, shards.SHARDS)
        for step in (restore, save):
            self.assertEqual(step['uses'].split('@')[1], main['uses'].split('@')[1])

    def test_windows_wrapper_is_identical_except_arguments(self):
        flows = CI['jobs']['windows-flows']['steps'][-1]['run']
        tests = next(step['run'] for step in CI['jobs']['windows-tests']['steps'] if step.get('name') == 'Native Windows tests (400 flow histories per property)')
        # The leaf runs one invocation; the shard step runs the same per-process block for each.
        def block(script):
            lines = script.splitlines()
            start = next(i for i, line in enumerate(lines) if line.strip().startswith('$tests = Start-Process'))
            end = next(i for i, line in enumerate(lines) if line.strip() == "if ($null -eq $testExit) { throw 'The test process supplied no exit code' }")
            return [line.strip() for line in lines[start:end + 1]]
        self.assertEqual(block(flows), block(tests))
        for script in (flows, tests):
            self.assertTrue(script.startswith("$ErrorActionPreference = 'Stop'\n$cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop).Source\n"))
        for required in ('$null = $tests.Handle', 'WaitForExit(30000)', 'Get-CimInstance', 'CpuSeconds',
                         'ReadOperationCount, WriteOperationCount, WriteTransferCount', '$testExit = $tests.ExitCode',
                         'taskkill.exe', '/T /F', '$tests.Dispose()'):
            self.assertIn(required, tests)
        self.assertIn('exit $testExit', flows)
        self.assertIn("'-p', 'zunder-venue', '--test', 'flows_model', $env:FLOW_TEST, '--', '--exact'", flows)

    def test_linux_shard_invocation_is_exact(self):
        self.assertEqual(CI['jobs']['rust-flows']['steps'][-1]['run'],
                         'cargo test --locked -p zunder-venue --test flows_model "$FLOW_TEST" -- --exact')

    def test_required_stable_aggregators_are_always_strict(self):
        for stem, needs in (('rust', ['rust-main', 'rust-flows']),
                            ('windows', ['windows-main', 'windows-tests', 'windows-flows'])):
            job = CI['jobs'][stem]
            self.assertEqual(job['name'], stem);self.assertEqual(job['if'], 'always()')
            self.assertEqual(job['needs'], needs)
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

    def test_public_aggregate_rejects_every_non_success_and_incomplete_dependency_set(self):
        job = CI['jobs']['ci']
        code = job['steps'][0]['run']
        for outcome in ('success', 'failure', 'cancelled', 'skipped', 'unknown'):
            for dependency in job['needs']:
                needs = {name: {'result': outcome if name == dependency else 'success'}
                         for name in job['needs']}
                result = subprocess.run([sys.executable, '-c', code],
                                        env=dict(os.environ, REQUIRED_RESULTS=json.dumps(needs)),
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0, outcome == 'success')
        for names in ([], job['needs'][1:], job['needs'] + ['foreign']):
            result = subprocess.run([sys.executable, '-c', code],
                                    env=dict(os.environ, REQUIRED_RESULTS=json.dumps(
                                        {name: {'result': 'success'} for name in names})),
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_logged_harness_and_journey_failures_cannot_be_hidden_by_tee(self):
        for name, first_command in (('harness', 'ruff'), ('journeys', 'npm')):
            with self.subTest(job=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                # Fail the first check; later commands and tee cannot turn it green.
                for command in ('ruff', 'mypy', 'pytest', 'npm'):
                    stub = root / command
                    stub.write_text('#!/bin/sh\nprintf "fixture diagnostic\\n"\nexit ' +
                                    ('23' if command == first_command else '0') + '\n')
                    stub.chmod(0o755)
                step = next(step for step in CI['jobs'][name]['steps']
                            if 'tee ' in step.get('run', ''))
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                           RUNNER_TEMP=directory)
                result = subprocess.run(['bash', '-c', step['run']], env=env,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 23)
                self.assertIn('fixture diagnostic', (root / f'guard-{name}.log').read_text())

    def test_read_only_permissions_no_secret_or_publication_actions(self):
        self.assertEqual(CI['permissions'], {'contents': 'read'})
        for stem in ('rust', 'windows'):
            for suffix in ('', '-main', '-flows') + (('-tests',) if stem == 'windows' else ()):
                text = json.dumps(CI['jobs'][stem + suffix])
                self.assertNotIn('secrets.', text);self.assertNotIn('contents: write', text)
                self.assertNotIn('continue-on-error', text)

    def test_offline_contract_registered_after_existing_yaml_install(self):
        steps = CI['jobs']['scripts']['steps']
        selected = next(i for i, step in enumerate(steps) if step.get('run') == 'python3 -B deploy/guard/github/test_flow_shards.py')
        self.assertTrue(any('PyYAML==6.0.3' in step.get('run', '') for step in steps[:selected]))


if __name__ == '__main__':
    unittest.main()
