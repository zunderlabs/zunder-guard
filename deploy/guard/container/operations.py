#!/usr/bin/python3
"""Owned, unlogged setup containers, with an independent systemd cleanup guardian."""
import fcntl
from contextlib import contextmanager
import json
import io
import tarfile
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
import threading
import time
import uuid

BASE = Path('/etc/zunder-guard-container')
REGISTRY = BASE / 'operations'
DOCKER = '/usr/bin/docker'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
LABEL = 'com.zunderlabs.guard-install-operation'
LEASE = 15
MAX_OPERATION = 1800
COMMAND_TIMEOUT = 60


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def trusted(path, directory=False):
    path = Path(path)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
            'Untrusted container operation path.')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            'Unexpected operation file type.')


def parents(path):
    for parent in Path(path).parents:
        trusted(parent, True)


def executable(path):
    # Distribution-owned interpreter links (python3 -> python3.12) are normal.
    original = Path(path)
    info = original.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022 if not stat.S_ISLNK(info.st_mode)
            else info.st_uid == 0, 'Untrusted system executable.')
    parents(original)
    resolved = original.resolve(strict=True)
    trusted(resolved)
    parents(resolved)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic(path, value):
    path = Path(path)
    trusted(path.parent, True)
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read(path):
    trusted(path)
    return json.loads(Path(path).read_text())


def boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def docker_argv(*args):
    return [DOCKER, '--config', str(BASE / 'docker-config'),
            '--host', 'unix:///var/run/docker.sock', *args]


def docker(*args):
    result = subprocess.run(docker_argv(*args), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=ENV, timeout=COMMAND_TIMEOUT, check=False)
    require(result.returncode == 0, 'Local Docker operation failed; activation remains inhibited.')
    return result.stdout


def identifiers(*filters):
    args = ['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}']
    for value in filters:
        args += ['--filter', value]
    values = docker(*args).decode().splitlines()
    require(all(re.fullmatch('[a-f0-9]{64}', v) for v in values), 'Invalid Docker identifiers.')
    return values


def validate(record):
    require(set(record) in ({'operation', 'image', 'volume', 'boot', 'created'},
                            {'operation', 'image', 'volume', 'boot', 'created', 'version'})
            and record.get('version') in (None, 2), 'Invalid operation record.')
    for key, pattern in [('operation', '[a-f0-9]{32}'),
                         ('image', r'ghcr\.io/zunderlabs/zunder-guard@sha256:[a-f0-9]{64}'),
                         ('volume', '[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'),
                         ('boot', '[a-f0-9-]{36}')]:
        require(isinstance(record[key], str) and re.fullmatch(pattern, record[key]), 'Invalid operation identity.')
    require(isinstance(record['created'], (float, int)), 'Invalid operation clock.')


def inspect(identifier, record):
    require(re.fullmatch('[a-f0-9]{64}', identifier), 'Full operation container ID required.')
    values = json.loads(docker('container', 'inspect', identifier))
    require(isinstance(values, list) and len(values) == 1, 'Invalid operation inspection.')
    obj = values[0]
    require(obj.get('Id') == identifier and obj.get('Name') == '/zunder-setup-' + record['operation'],
            'Operation container identity changed.')
    config, host = obj.get('Config', {}), obj.get('HostConfig', {})
    require((config.get('Labels') or {}).get(LABEL) == record['operation']
            and config.get('Image') == record['image'], 'Operation ownership changed.')
    require(host.get('RestartPolicy', {}).get('Name') in ('no', '')
            and host.get('LogConfig', {}).get('Type') == 'none', 'Operation logging/restart policy refused.')
    require(any(m.get('Type') == 'volume' and m.get('Name') == record['volume']
                and m.get('Destination') == '/data' for m in obj.get('Mounts', [])), 'Operation volume changed.')
    return obj


def resolve(record, path):
    named = identifiers('name=^/zunder-setup-' + record['operation'] + '$')
    labelled = identifiers('label=' + LABEL + '=' + record['operation'])
    require(len(named) <= 1 and set(named) == set(labelled), 'Ambiguous or renamed setup container.')
    if (path / 'id.json').exists():
        identifier = read(path / 'id.json')
        require(re.fullmatch('[a-f0-9]{64}', identifier), 'Invalid recorded container ID.')
        require(not named or named == [identifier], 'Setup name was reused; refusing cleanup.')
    return named


@contextmanager
def operation_lock(path):
    fd = os.open(path / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def terminal(path):
    """A legacy done marker/empty observation is not evidence a create finished."""
    if not (path / 'done.json').exists():
        return False
    done = read(path / 'done.json')
    record = read(path / 'record.json')
    if done.get('version') != 2:
        return False
    if done.get('outcome') == 'never-dispatched':
        return record.get('version') == 2 and not (path / 'create.json').exists()
    return (done.get('outcome') == 'removed' and (path / 'id.json').exists()
            and done.get('id') == read(path / 'id.json'))


def cleanup(record, path):
    found = resolve(record, path)
    for identifier in found:
        inspect(identifier, record)
        # A late but exact-owned result resolves an ambiguous single create request.
        atomic(path / 'id.json', identifier)
        docker('container', 'stop', '--time', '5', identifier)
        if identifier in identifiers():
            inspect(identifier, record)
            docker('container', 'rm', identifier)
    require(not resolve(record, path), 'Setup cleanup remains pending.')
    known_id = read(path / 'id.json') if (path / 'id.json').exists() else None
    never_dispatched = record.get('version') == 2 and not (path / 'create.json').exists()
    if not known_id and not never_dispatched:
        # Timeout/death can race an in-flight daemon create. Keep reconciling this public
        # tombstone after empty inspections, including old premature done markers.
        if (path / 'done.json').exists():
            (path / 'done.json').unlink()
            sync_directory(path)
        return
    atomic(path / 'done.json', {'version': 2, 'boot': boot(), 'at': time.monotonic(),
                                'outcome': 'removed' if known_id else 'never-dispatched', 'id': known_id})


def expired(record, path, now):
    if (path / 'cancel.json').exists() or record['boot'] != boot():
        return True
    lease = read(path / 'lease.json')
    return (lease['boot'] != boot() or now - lease['at'] > LEASE
            or now - record['created'] > MAX_OPERATION or lease['at'] > now + 1)


def tick(path):
    trusted(path, True)
    with operation_lock(path):
        record = read(path / 'record.json')
        validate(record)
        require(path.name == record['operation'], 'Operation directory differs from identity.')
        if terminal(path):
            return
        if (path / 'done.json').exists() or expired(record, path, time.monotonic()):
            cleanup(record, path)
            return
        # Acknowledgement proves a separate guardian has read this exact operation and ID.
        identifier = read(path / 'id.json') if (path / 'id.json').exists() else None
        if identifier:
            inspect(identifier, record)
        atomic(path / 'ack.json', {'id': identifier, 'boot': boot(), 'at': time.monotonic()})


def preflight():
    require(os.geteuid() == 0 and os.name == 'posix', 'Root Linux operation guardian required.')
    for directory in (BASE, BASE / 'docker-config', REGISTRY):
        trusted(directory, True)
        parents(directory)
    require(not list((BASE / 'docker-config').iterdir()), 'Docker config must be empty.')
    trusted(DOCKER)
    parents(DOCKER)


def guardian():
    preflight()
    lock = os.open(REGISTRY / 'guardian.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    while True:
        for path in REGISTRY.iterdir():
            if re.fullmatch('[a-f0-9]{32}', path.name):
                try:
                    tick(path)
                except (Refused, OSError, ValueError, KeyError, subprocess.TimeoutExpired):
                    # Retain registry/gate and retry on daemon recovery. Never log process output.
                    continue
        time.sleep(1)


def pending():
    return [p for p in REGISTRY.iterdir() if re.fullmatch('[a-f0-9]{32}', p.name)
            and not terminal(p)]


def wait_for(path, predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.2)
    raise Refused('Setup guardian did not acknowledge or finish; activation remains inhibited.')


def run(config, command, *, data=None, interactive=False, readonly=True, public_env=(), read_config=False):
    """Secret input is only forwarded after independent owned-ID acknowledgement."""
    preflight()
    require(not pending(), 'An earlier setup operation needs guardian cleanup first.')
    operation = uuid.uuid4().hex
    record = {'operation': operation, 'image': config['image'], 'volume': config['volume'],
              'boot': boot(), 'created': time.monotonic(), 'version': 2}
    validate(record)
    path = REGISTRY / operation
    path.mkdir(mode=0o700)
    sync_directory(REGISTRY)  # Persist the ownership directory before any Docker create.
    atomic(path / 'lease.json', {'boot': boot(), 'at': time.monotonic()})
    atomic(path / 'record.json', record)
    end = threading.Event()
    failed = threading.Event()
    child = None

    def heartbeat():
        while not end.wait(1):
            try:
                if child is not None and child.poll() is not None:
                    return
                atomic(path / 'lease.json', {'boot': boot(), 'at': time.monotonic()})
                if (path / 'ack.json').exists():
                    ack = read(path / 'ack.json')
                    require(ack['boot'] == boot() and time.monotonic() - ack['at'] <= LEASE,
                            'Operation guardian stopped.')
                require(time.monotonic() - record['created'] <= MAX_OPERATION, 'Setup operation timed out.')
            except (Refused, OSError, ValueError, KeyError):
                failed.set()
                if child is not None and child.poll() is None:
                    child.kill()
                return

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        def acknowledged(identifier):
            if not (path / 'ack.json').exists():
                return False
            ack = read(path / 'ack.json')
            return ack['id'] == identifier and ack['boot'] == boot() and time.monotonic() - ack['at'] <= LEASE
        wait_for(path, lambda: acknowledged(None))
        mount = 'type=volume,source=' + record['volume'] + ',target=/data' + (',readonly' if readonly else '')
        args = ['container', 'create', '--name', 'zunder-setup-' + operation,
                '--label', LABEL + '=' + operation, '--restart=no', '--log-driver=none',
                '--init', '--pull=never', '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true', '--ulimit', 'core=0',
                '--mount', mount, '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
                '--env', 'ZUNDER_GUARD_HOME=/data', '-i']
        if interactive:
            args.append('-t')
        for value in public_env:
            require(re.fullmatch('ZUNDER_MAINNET_CONFIRM=0x[a-fA-F0-9]{40}', value), 'Unexpected operation environment.')
            args += ['--env', value]
        with operation_lock(path):
            require(not (path / 'done.json').exists() and not expired(record, path, time.monotonic())
                    and not failed.is_set(), 'Operation expired before create dispatch.')
            atomic(path / 'create.json', {'dispatched': True})
        # Dispatch happens only after directory and create intent are durable. Even if
        # this call times out, the guardian retains an unresolved-create tombstone.
        identifier = docker(*args, record['image'], *command).decode().strip()
        inspect(identifier, record)
        atomic(path / 'id.json', identifier)
        wait_for(path, lambda: acknowledged(identifier))
        require(not failed.is_set(), 'Guardian unavailable before secret delivery.')
        if read_config:
            # Read only the known config into memory; never extract archive paths onto the host.
            archive = docker('container', 'cp', identifier + ':/data/guard.toml', '-')
            require(len(archive) <= 2 * 1024 * 1024, 'Configuration archive is oversized.')
            with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
                members = tar.getmembers()
                require(len(members) == 1 and members[0].name == 'guard.toml'
                        and members[0].isfile() and members[0].size <= 1024 * 1024,
                        'Unexpected configuration archive member.')
                return tar.extractfile(members[0]).read()
        argv = docker_argv('container', 'start', '--attach', '--interactive', identifier)
        if interactive:
            with open('/dev/tty', 'r+b', buffering=0) as terminal_stream:
                child = subprocess.Popen(argv, stdin=terminal_stream, stdout=terminal_stream, stderr=terminal_stream, env=ENV)
                code = child.wait(timeout=MAX_OPERATION)
                output = b''
        else:
            child = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
            output, _ = child.communicate(data, timeout=MAX_OPERATION)
            code = child.returncode
        require(code == 0 and not failed.is_set(), 'Guard setup command failed; activation remains inhibited.')
        return output
    finally:
        end.set()
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        thread.join(timeout=3)
        atomic(path / 'cancel.json', True)
        wait_for(path, lambda: terminal(path), seconds=90)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    guardian()
