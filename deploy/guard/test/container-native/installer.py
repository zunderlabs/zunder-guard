#!/usr/bin/python3
"""Additive disposable-guest setup/cleanup/boot-gate checks, never run on a shared host.

Uses the existing guest marker and QEMU runner. No production release/signature/venue claim.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import re
import selectors
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
PRODUCTION = HERE.parents[1] / 'container'
WORK = Path('/var/lib/zunder-container-installer-native')
BASE = Path('/etc/zunder-guard-container')
VOLUME = 'zunder-container-installer-native-data'
UNIT = 'zunder-guard-container.service'
GUARDIAN = 'zunder-guard-setup-guardian.service'
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LANG='C.UTF-8')


def require(ok, message):
    if not ok: raise RuntimeError(message)


def call(*args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=120, check=False)
    if check: require(result.returncode == 0, 'Native installer fixture command failed: ' + args[0])
    return result.stdout.decode().strip()


BUILD_TIMEOUT = 120
BUILD_OUTPUT_LIMITS = {'stdout': 4096, 'stderr': 65536}


def build_failure(reason, returncode):
    # Only fixed classifications and numeric exit status escape the capture.
    raise RuntimeError('Native installer fixture build failed: ' + json.dumps(
        {'reason': reason, 'returncode': returncode}, sort_keys=True)) from None


def build_fixture_image():
    """Bounded local build diagnostic; never disclose command output or arguments."""
    argv = ['/usr/bin/docker', 'build', '-q', '-f', str(HERE / 'Installer.Dockerfile'), str(HERE)]
    deadline = time.monotonic() + BUILD_TIMEOUT
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=ENV)
    except OSError:
        build_failure('exec-failed', None)
    buffers = {name: bytearray() for name in BUILD_OUTPUT_LIMITS}
    reason = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = 'timeout'; break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    name = key.data
                    if len(buffers[name]) + len(chunk) > BUILD_OUTPUT_LIMITS[name]:
                        reason = 'output-limit'; break
                    buffers[name].extend(chunk)
                if reason: break
            if reason is None:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = 'timeout'
    except OSError:
        reason = 'capture-failed'
    finally:
        try:
            if process.poll() is None:
                process.kill()
            # Separate bounded reap after the unchanged 120-second command cap.
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            build_failure('cleanup-failed', process.returncode)
        finally:
            process.stdout.close(); process.stderr.close()
    if reason:
        build_failure(reason, process.returncode)
    if process.returncode:
        error = bytes(buffers['stderr']).lower()
        # These describe observed stderr patterns, not a proven underlying cause.
        signatures = [('unsupported-dockerfile-option', (b'unknown flag: chmod', b'--chmod option requires buildkit', b'unknown flag: chown')),
                      ('daemon-unavailable', (b'cannot connect to the docker daemon',)),
                      ('registry-fetch-failed', (b'failed to resolve source metadata', b'pull access denied', b'toomanyrequests')),
                      ('storage-full', (b'no space left on device',))]
        reason = next((label for label, patterns in signatures if any(pattern in error for pattern in patterns)), 'build-failed')
        build_failure(reason, process.returncode)
    image = bytes(buffers['stdout']).strip()
    if re.fullmatch(rb'sha256:[0-9a-f]{64}', image) is None:
        build_failure('invalid-image-id', process.returncode)
    return image.decode('ascii')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def docker(*args):
    return call('/usr/bin/docker', '--config', str(BASE / 'docker-config'), '--host', 'unix:///var/run/docker.sock', *args)


def wait(predicate, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value: return value
        time.sleep(.5)
    raise RuntimeError('Native installer fixture deadline exceeded')


def wait_cleanup(operation, identifier, boot, image):
    """Container absence precedes durable guardian acknowledgement; require both."""
    require(isinstance(operation, str) and re.fullmatch('[a-f0-9]{32}', operation)
            and re.fullmatch('[a-f0-9]{64}', identifier), 'Invalid fixture cleanup identity.')
    directory = BASE / 'operations' / operation
    state = 'ack-pending'

    def read_record(name):
        path = directory / name
        require(not path.is_symlink(), 'Invalid fixture cleanup record.')
        with path.open('rb') as stream:
            raw = stream.read(4097)
        require(len(raw) <= 4096, 'Invalid fixture cleanup record.')
        return json.loads(raw)

    def complete():
        nonlocal state
        try:
            record = read_record('record.json')
            require(isinstance(record, dict) and record.get('version') == 2
                    and record.get('operation') == operation and record.get('boot') == boot
                    and record.get('image') == image and record.get('volume') == VOLUME
                    and read_record('id.json') == identifier, 'Invalid fixture cleanup record.')
            if docker('ps', '-aq', '--filter', 'label=com.zunderlabs.guard-install-operation'):
                state = 'container-present'
                return False
            state = 'ack-pending'
            try:
                done = read_record('done.json')
            except FileNotFoundError:
                return False
            require(isinstance(done, dict) and done.get('version') == 2
                    and done.get('outcome') == 'removed' and done.get('id') == identifier
                    and done.get('boot') == boot, 'Invalid fixture cleanup receipt.')
            return True
        except (OSError, ValueError, TypeError, RuntimeError):
            state = 'record-or-probe-failed'
            raise RuntimeError('Native installer cleanup observation failed.') from None

    try:
        wait(complete)  # Existing 90-second cleanup phase; no second acknowledgement phase.
    except RuntimeError:
        raise RuntimeError('Native installer cleanup failed: ' + state) from None


def setup():
    require(not BASE.exists() and not WORK.exists(), 'Fresh isolated guest fixture required.')
    WORK.mkdir(mode=0o700)
    BASE.mkdir(mode=0o700)
    (BASE / 'operations').mkdir(mode=0o700)
    (BASE / 'docker-config').mkdir(mode=0o700)
    for src, dst in [('operations.py', 'operations.py'), ('operations.py', 'container-operations.py'),
                     ('install-container.py', 'install-container.py')]:
        shutil.copyfile(PRODUCTION / src, WORK / dst)
    shutil.copyfile(HERE / 'installer-driver.py', WORK / 'installer-driver.py')
    image = build_fixture_image()
    (WORK / 'fixture.json').write_text(json.dumps(dict(image=image, volume=VOLUME)))
    docker('volume', 'create', VOLUME)
    # Production guardian service hardening; only executable path differs for local-image fixture admission.
    unit = (PRODUCTION / GUARDIAN).read_text().replace(
        '/usr/bin/python3 -I /usr/local/libexec/zunder-guard-container/operations.py',
        '/usr/bin/python3 -I ' + str(WORK / 'installer-driver.py') + ' guardian')
    unit += '\n'  # exact production hardening remains in the unit above
    Path('/etc/systemd/system', GUARDIAN).write_text(unit)
    call('/usr/bin/systemctl', 'daemon-reload')
    call('/usr/bin/systemctl', 'enable', '--now', GUARDIAN)
    evidence = {'status': 'running-native-synthetic-installer', 'boot_before': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'checks': [], 'production_operations_sha256': hashlib.sha256((PRODUCTION / 'operations.py').read_bytes()).hexdigest()}
    for victim in ('wrapper', 'docker-client'):
        process = subprocess.Popen(['/usr/bin/python3', '-I', str(WORK / 'installer-driver.py'), 'operation'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        def container_id():
            ids = docker('ps', '-q', '--no-trunc', '--filter', 'label=com.zunderlabs.guard-install-operation').splitlines()
            if not ids: return None
            info = json.loads(docker('inspect', ids[0]))[0]
            return ids[0] if info['State']['Running'] else None
        identifier = wait(container_id)
        time.sleep(2)
        info = json.loads(docker('inspect', identifier))[0]
        state = json.loads(docker('exec', identifier, 'python3', '-I', '-c',
                                 "from pathlib import Path; print(Path('/data/operation-ready.json').read_text())"))
        require(state['uid'] == 65532 and state['input_sha'] == hashlib.sha256(b'ab' * 32).hexdigest(),
                'Fresh volume must be writable by nonroot and synthetic stdin must arrive.')
        require(info['HostConfig']['LogConfig']['Type'] == 'none' and not info.get('LogPath'), 'Client output could be persisted.')
        require(info['HostConfig']['RestartPolicy']['Name'] in ('no', ''), 'Temporary restart policy exists.')
        operation = info['Config']['Labels'].get('com.zunderlabs.guard-install-operation')
        if victim == 'wrapper':
            process.kill()
        else:
            children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
            require(len(children) == 1, 'Expected one attached Docker client.')
            os.kill(int(children[0]), signal.SIGKILL)
        wait_cleanup(operation, identifier, evidence['boot_before'], image)
        process.wait(timeout=120)
        evidence['checks'].append(victim + '-loss-exact-id-cleanup-no-docker-log')
    # A harmless service stands in for Guard. Reproduce helper enable with an open transaction.
    unit = '[Unit]\nDescription=Synthetic boot-gate sentinel\n[Service]\nType=oneshot\nExecStart=/usr/bin/touch ' + str(WORK / 'boot-started') + '\n[Install]\nWantedBy=multi-user.target\n'
    Path('/etc/systemd/system', UNIT).write_text(unit)
    call('/usr/bin/systemctl', 'daemon-reload')
    call('/usr/bin/systemctl', 'enable', UNIT)
    wrapper = load('installer_wrapper', WORK / 'install-container.py')
    record = wrapper.inhibit(dict(account='0x' + 'b' * 40, volume=VOLUME), False)
    wrapper.phase(record, 'helpers-installed')
    call('/usr/bin/systemctl', 'enable', UNIT)  # unchanged supervisor install's risky interval
    wrapper.verify_gate()
    (WORK / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')


def after_reboot():
    evidence = json.loads((WORK / 'evidence.json').read_text())
    now = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(now != evidence['boot_before'], 'A real kernel reboot is required.')
    require(not (WORK / 'boot-started').exists(), 'Enabled unit escaped installation inhibition after reboot.')
    wrapper = load('installer_wrapper', WORK / 'install-container.py')
    wrapper.verify_gate()
    record = wrapper.ops.read(wrapper.GATE)
    require(record['original_enabled'] == 'enabled' and record['phase'] == 'helpers-installed', 'Transaction state changed across reboot.')
    call('/usr/bin/systemctl', 'start', UNIT)
    require(not (WORK / 'boot-started').exists(), 'Explicit start bypassed open transaction condition.')
    evidence['checks'].append('actual-reboot-after-enable-before-activation-remained-inhibited')
    evidence['boot_after'] = now
    evidence['status'] = 'passed-native-synthetic-installer-subset'
    evidence['pending'] = ['full interactive released-image setup', 'signature bootstrap with official artifact',
                           'daemon outage/live-restore transient cleanup', 'actual licence/venue API-wallet validation']
    (WORK / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['setup', 'after-reboot'])
    parser.add_argument('--marker', required=True)
    args = parser.parse_args()
    existing = load('original_native_guest', HERE / 'guest.py')
    existing.guarded_guest(args.marker)
    setup() if args.phase == 'setup' else after_reboot()
