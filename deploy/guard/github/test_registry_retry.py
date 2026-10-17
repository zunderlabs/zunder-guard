"""registry-retry.sh: bounded retries of registry pulls, and the workflows that build through it.

Offline: a fake `docker` and a fake `sleep` on PATH record what the script runs and how long it
would wait. The registry lines are the forms BuildKit, buildx and the Docker daemon print.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

import yaml

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'registry-retry.sh'
DOCKERFILE = HERE.parent / 'Dockerfile'
WORKFLOWS = HERE / 'workflows'
if not WORKFLOWS.is_dir():  # the public repository keeps them under .github/workflows/
    WORKFLOWS = HERE.parents[2] / '.github/workflows'
WRAPPER = 'deploy/guard/github/registry-retry.sh'
DIGEST = 'sha256:' + 'ab' * 32
RUST = f'public.ecr.aws/docker/library/rust:1.97.0-alpine3.22@{DIGEST}'

# What the fake docker prints on its failed attempts, keyed by scenario name.
TRANSIENT = {
    'blob 429': 'ERROR: failed to build: failed to solve: failed to compute cache key: failed to copy: httpReadSeeker: '
                'failed open: unexpected status code https://public.ecr.aws/v2/docker/library/rust/blobs/sha256:'
                + 'c4' * 32 + ': 429 Too Many Requests - Server message: toomanyrequests: Data limit exceeded',
    'manifest timeout': '#4 ERROR: failed to do request: Head "https://public.ecr.aws/v2/docker/library/rust/manifests/'
                        + DIGEST + '": dial tcp [::1]:443: i/o timeout',
    'TLS timeout': 'ERROR: failed to solve: failed to do request: Head "https://public.ecr.aws/v2/docker/library/rust/'
                   'manifests/' + DIGEST + '": net/http: TLS handshake timeout',
    'token 503': 'ERROR: failed to solve: failed to fetch oauth token: unexpected status from GET request to '
                 'https://public.ecr.aws/token/?scope=repository%3Adocker%2Flibrary%2Frust%3Apull: 503 Service Unavailable',
    '502': 'ERROR: failed to solve: failed to resolve source metadata for ' + RUST
           + ': unexpected status from HEAD request to https://public.ecr.aws/v2/docker/library/rust/manifests/'
           + DIGEST + ': 502 Bad Gateway',
    '504': '#7 ERROR: failed to copy: httpReadSeeker: failed open: unexpected status code '
           'https://public.ecr.aws/v2/docker/library/rust/blobs/' + DIGEST + ': 504 Gateway Time-out',
    'daemon': 'Error response from daemon: toomanyrequests: Rate exceeded',
    'daemon timeout': 'Error response from daemon: Get "https://public.ecr.aws/v2/": net/http: request canceled while '
                      'waiting for connection (Client.Timeout exceeded while awaiting headers)',
}
PERMANENT = {
    'compile error': 'ERROR: failed to build: failed to solve: process "/bin/sh -c cargo build --release --locked" '
                     'did not complete successfully: exit code: 101',
    'missing manifest': 'ERROR: failed to solve: ' + RUST + ': failed to resolve source metadata for ' + RUST
                        + ': unexpected status from HEAD request to https://public.ecr.aws/v2/docker/library/rust/'
                        'manifests/sha256:a429b' + 'e' * 59 + ': 404 Not Found',
    'digest that ends in 503': 'ERROR: failed to solve: failed to resolve source metadata for '
                               'public.ecr.aws/docker/library/rust@sha256:' + 'e' * 60 + 'a503 Not Found',
    'quoted 429 in a build step': 'ERROR: failed to solve: process "/bin/sh -c echo 429 Too Many" did not complete '
                                  'successfully: exit code: 1',
    'crates.io 503 in a build step': '#12 31.0 error: failed to get 200 response from '
                                     '`https://index.crates.io/v2/se/rd/serde`, got 503',
    'transient text that is no error line': '#5 resolve https://public.ecr.aws/v2/x 503 Service Unavailable, retrying',
}

FAKE_DOCKER = r'''#!PYTHON
import json, os, pathlib, sys
state = pathlib.Path(os.environ['FAKE_STATE'])
calls = json.loads(state.read_text()) if state.exists() else []
entry = {'argv': sys.argv[1:]}
if '-f' in sys.argv:
    entry['dockerfile'] = pathlib.Path(sys.argv[sys.argv.index('-f') + 1]).read_text()
calls.append(entry)
state.write_text(json.dumps(calls))
print('#1 [internal] load build definition from Dockerfile')
if len(calls) <= int(os.environ['FAKE_FAILURES']):
    print(os.environ['FAKE_LINE'])
    sys.exit(int(os.environ.get('FAKE_STATUS', '1')))
print('#9 DONE 0.1s')
'''


class Fixture:
    def __init__(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'docker').write_text(FAKE_DOCKER.replace('PYTHON', sys.executable, 1))
        (bin_dir / 'sleep').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SLEEP_LOG"\n')
        for name in ('docker', 'sleep'):
            (bin_dir / name).chmod(0o755)
        self.state = self.root / 'calls.json'
        self.sleeps = self.root / 'sleeps'
        self.env = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', FAKE_STATE=str(self.state),
                        SLEEP_LOG=str(self.sleeps), FAKE_FAILURES='0', FAKE_LINE='')

    def run(self, *args, failures=0, line='', status=1):
        self.env.update(FAKE_FAILURES=str(failures), FAKE_LINE=line, FAKE_STATUS=str(status))
        return subprocess.run(['bash', str(SCRIPT), *args], check=False, env=self.env, capture_output=True, text=True,
                              timeout=60)

    def calls(self):
        return json.loads(self.state.read_text()) if self.state.exists() else []

    def slept(self):
        return self.sleeps.read_text().split() if self.sleeps.exists() else []


BUILD = ['run', '--', 'docker', 'buildx', 'build', '-f', 'deploy/guard/Dockerfile', '.']


class RetryTests(unittest.TestCase):
    def test_success_runs_once_and_passes_output_through(self):
        f = Fixture(self)
        result = f.run(*BUILD)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('#9 DONE', result.stdout)
        self.assertEqual([c['argv'] for c in f.calls()], [BUILD[3:]])
        self.assertEqual(f.slept(), [])

    def test_each_transient_registry_failure_is_retried_with_backoff(self):
        for name, line in TRANSIENT.items():
            with self.subTest(name):
                f = Fixture(self)
                result = f.run(*BUILD, failures=2, line=line)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(f.calls()), 3)
                self.assertEqual(f.slept(), ['60', '120'])
                self.assertEqual(result.stderr.count('::warning::registry-retry'), 2)

    def test_retries_are_bounded_and_keep_the_last_exit_status(self):
        f = Fixture(self)
        result = f.run(*BUILD, failures=99, line=TRANSIENT['blob 429'], status=17)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(f.calls()), 4)  # the first attempt and at most 3 retries
        self.assertEqual(f.slept(), ['60', '120', '240'])

    def test_other_failures_return_at_once(self):
        for name, line in PERMANENT.items():
            with self.subTest(name):
                f = Fixture(self)
                result = f.run(*BUILD, failures=1, line=line, status=101)
                self.assertEqual(result.returncode, 101)
                self.assertEqual(len(f.calls()), 1)
                self.assertEqual(f.slept(), [])

    def test_only_the_failed_attempts_output_decides(self):
        # A transient error that a later attempt replaced with a build failure stops the retries.
        f = Fixture(self)
        script = f.root / 'bin/docker'
        script.write_text(script.read_text().replace(
            "print(os.environ['FAKE_LINE'])",
            "print(os.environ['FAKE_LINE'] if len(calls) == 1 else 'ERROR: failed to solve: process \"/bin/sh -c x\" '"
            "'did not complete successfully: exit code: 2')"))
        result = f.run(*BUILD, failures=99, line=TRANSIENT['manifest timeout'], status=2)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(f.calls()), 2)
        self.assertEqual(f.slept(), ['60'])

    def test_usage_errors(self):
        f = Fixture(self)
        for args in ([], ['run'], ['run', '--'], ['run', 'docker'], ['pull', 'x'], ['warm', str(DOCKERFILE), '-']):
            with self.subTest(args):
                self.assertEqual(f.run(*args).returncode, 2)
        self.assertEqual(f.calls(), [])


class WarmTests(unittest.TestCase):
    def dockerfile(self, f, text):
        path = f.root / 'Dockerfile'
        path.write_text(text)
        return str(path)

    def test_fetches_the_pinned_stages_and_frontend_of_the_real_dockerfile(self):
        text = DOCKERFILE.read_text()
        syntax = text.splitlines()[0]
        self.assertRegex(syntax, r'^# syntax=\S+@sha256:[0-9a-f]{64}$')
        refs = {m[1]: m[0] for m in re.findall(r'^FROM (\S+) AS (\S+)$', text, re.MULTILINE)}
        f = Fixture(self)
        result = f.run('warm', str(DOCKERFILE), 'linux/amd64,linux/arm64', 'build', 'runtime')
        self.assertEqual(result.returncode, 0, result.stderr)
        [call] = f.calls()
        self.assertEqual(call['dockerfile'], '\n'.join([
            syntax, f'FROM {refs["build"]} AS base0', f'FROM {refs["runtime"]} AS base1', 'FROM scratch',
            'COPY --from=base0 / /base0/', 'COPY --from=base1 / /base1/', '']))
        argv = call['argv']
        self.assertEqual(argv[:2], ['buildx', 'build'])
        self.assertIn('type=cacheonly', argv[argv.index('--output') + 1])
        self.assertEqual(argv[argv.index('--platform') + 1], 'linux/amd64,linux/arm64')
        self.assertNotIn('--pull', argv)
        self.assertNotIn('--push', argv)
        self.assertNotIn('--load', argv)

    def test_native_platform_and_no_syntax_line(self):
        f = Fixture(self)
        path = self.dockerfile(f, f'ARG X=1\nFROM {RUST} AS build\nRUN true\n')
        result = f.run('warm', path, '-', 'build')
        self.assertEqual(result.returncode, 0, result.stderr)
        [call] = f.calls()
        self.assertNotIn('--platform', call['argv'])
        self.assertEqual(call['dockerfile'], f'FROM {RUST} AS base0\nFROM scratch\nCOPY --from=base0 / /base0/\n')

    def test_warm_retries_a_throttled_pull(self):
        f = Fixture(self)
        result = f.run('warm', str(DOCKERFILE), '-', 'build', failures=1, line=TRANSIENT['blob 429'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(f.calls()), 2)
        self.assertEqual(f.slept(), ['60'])

    def test_refuses_any_stage_that_is_not_one_image_pinned_by_digest(self):
        cases = {
            'tag only': 'FROM public.ecr.aws/docker/library/rust:1.97.0-alpine3.22 AS build\n',
            'short digest': f'FROM {RUST[:-1]} AS build\n',
            'missing stage': f'FROM {RUST} AS other\n',
            'two stages of that name': f'FROM {RUST} AS build\nFROM {RUST} AS build\n',
            'variable': 'FROM ${BASE} AS build\n',
            'platform flag': f'FROM --platform=linux/amd64 {RUST} AS build\n',
            'stage name': f'FROM {RUST} AS base\nFROM base AS build\n',
        }
        for name, text in cases.items():
            with self.subTest(name):
                f = Fixture(self)
                result = f.run('warm', self.dockerfile(f, text), '-', 'build')
                self.assertEqual(result.returncode, 1)
                self.assertIn('pinned by digest', result.stderr)
                self.assertEqual(f.calls(), [])

    def test_missing_dockerfile_refuses(self):
        f = Fixture(self)
        self.assertEqual(f.run('warm', str(f.root / 'absent'), '-', 'build').returncode, 1)
        self.assertEqual(f.calls(), [])


def jobs():
    for path in sorted(WORKFLOWS.glob('*.yml')):
        for name, job in (yaml.safe_load(path.read_text()).get('jobs') or {}).items():
            yield f'{path.name}:{name}', job


def builds_guard_image(step):
    run = step.get('run', '')
    uses = step.get('uses', '')
    return ('docker buildx build' in run and 'deploy/guard/Dockerfile' in run) or (
        uses.startswith('docker/build-push-action@') and step.get('with', {}).get('file') == 'deploy/guard/Dockerfile')


def warm_command(step):
    return [line for line in step.get('run', '').splitlines() if f'{WRAPPER} warm ' in line]


class WorkflowTests(unittest.TestCase):
    # Each job that builds the Guard Dockerfile, and the stages its build needs.
    EXPECTED: ClassVar[dict[str, list[str]]] = {
        'release.yml:build': ['build'],      # --target bin-build
        'release.yml:reproduce': ['build'],  # --target bin-build
        'release.yml:image': ['runtime'],    # GUARD_SOURCE=prebuilt: no compile stage
        'ci.yml:image': ['build', 'runtime'],
    }

    def test_every_guard_image_build_is_known(self):
        found = {name for name, job in jobs() if any(builds_guard_image(s) for s in job.get('steps', []))}
        self.assertEqual(found, set(self.EXPECTED))

    def test_every_build_command_runs_through_the_retry(self):
        for name, job in jobs():
            for step in job.get('steps', []):
                for line in step.get('run', '').splitlines():
                    if 'docker buildx build' in line or re.search(r'\bdocker (build|pull)\b', line):
                        with self.subTest(name, line=line):
                            self.assertTrue(line.strip().startswith(f'{WRAPPER} run -- docker '), line)
                            self.assertNotIn('--pull', line)

    def test_the_pinned_images_are_fetched_before_each_build(self):
        for name, job in jobs():
            if name not in self.EXPECTED:
                continue
            with self.subTest(name):
                steps = job['steps']
                buildx = [i for i, s in enumerate(steps) if s.get('uses', '').startswith('docker/setup-buildx-action@')]
                warm = [i for i, s in enumerate(steps) if warm_command(s)]
                build = [i for i, s in enumerate(steps) if builds_guard_image(s)]
                self.assertEqual((len(buildx), len(warm), len(build)), (1, 1, 1))
                self.assertLess(buildx[0], warm[0])
                self.assertLess(warm[0], build[0])
                warm_step, build_step = steps[warm[0]], steps[build[0]]
                self.assertEqual(warm_step.get('if'), build_step.get('if'))
                [line] = warm_command(warm_step)
                words = line.split()
                self.assertEqual(words[:3], [WRAPPER, 'warm', 'deploy/guard/Dockerfile'])
                self.assertEqual(words[4:], self.EXPECTED[name])
                if 'uses' in build_step:  # build-push-action: the same platforms, spelled out
                    self.assertEqual(words[3], build_step['with']['platforms'])
                    self.assertEqual(build_step['with'].get('build-args'), 'GUARD_SOURCE=prebuilt')
                    self.assertNotIn('pull', build_step['with'])
                elif '--platform' in build_step['run']:
                    self.assertEqual(words[3], '"$PLATFORM"')
                    self.assertIn('--platform "$PLATFORM"', build_step['run'])
                    self.assertEqual(warm_step['env']['PLATFORM'], build_step['env']['PLATFORM'])
                else:
                    self.assertEqual(words[3], '-')
                for step in (warm_step, build_step):
                    self.assertNotIn('${{', step.get('run', ''))  # inputs reach run: only through env

    def test_the_reproduce_check_still_compares_a_fresh_compile(self):
        release = dict(jobs())
        for name in ('release.yml:build', 'release.yml:reproduce'):
            [step] = [s for s in release[name]['steps'] if 'docker buildx build' in s.get('run', '')]
            with self.subTest(name):
                self.assertIn('--target bin-build', step['run'])
                self.assertIn('--no-cache', step['run'])

    def test_the_dockerfile_stages_the_workflows_warm_are_pinned(self):
        text = DOCKERFILE.read_text()
        for stage in ('build', 'runtime'):
            with self.subTest(stage):
                self.assertEqual(len(re.findall(rf'^FROM \S+@sha256:[0-9a-f]{{64}} AS {stage}$', text, re.MULTILINE)), 1)
        self.assertRegex(text.rstrip().split('\nFROM ')[-1], r'^\S+ AS runtime\n')  # still the default target

    def test_ci_runs_this_test_and_shellchecks_the_script(self):
        ci = (WORKFLOWS / 'ci.yml').read_text()
        self.assertIn('python3 -B deploy/guard/github/test_registry_retry.py', ci)
        self.assertIn('shellcheck deploy/guard/packaging/*.sh deploy/guard/github/*.sh', ci)


if __name__ == '__main__':
    unittest.main()
