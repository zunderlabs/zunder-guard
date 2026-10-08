#!/usr/bin/python3
"""Linux systemd credential → local Docker stdin. No key files or Docker restart policy.

Install only verified release bytes. This helper never initializes or resets Guard state.
"""
import argparse
import fcntl
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import uuid

BASE = Path('/etc/zunder-guard-container')
RUNTIME = Path('/run/zunder-guard-container')
HELPER = Path('/usr/local/libexec/zunder-guard-container/supervisor.py')
UNIT_SOURCE = HELPER.with_name('zunder-guard-container.service')
UNIT_PATH = Path('/etc/systemd/system/zunder-guard-container.service')
UNIT = 'zunder-guard-container.service'
NAME = 'zunder-guard-container'
LABEL = 'com.zunderlabs.guard-supervisor'
CREDENTIAL = 'guard-api-wallet'
CREDENTIAL_ROOT = Path('/run/credentials')
DOCKER = '/usr/bin/docker'
SYSTEMCTL = '/usr/bin/systemctl'
CREDS = '/usr/bin/systemd-creds'
COSIGN = '/usr/local/bin/cosign'
SOCKET = Path('/var/run/docker.sock')
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
IMAGE_RE = r'ghcr\.io/zunderlabs/zunder-guard@sha256:[a-f0-9]{64}'
ACCOUNT_RE = r'0x[a-fA-F0-9]{40}'
VOLUME_RE = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'


class Refused(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def execute(argv, *, data=None):
    # Never include command output in exceptions: key checks/encryption consume secrets.
    input_args = {'input': data} if data is not None else {'stdin': subprocess.DEVNULL}
    result = subprocess.run(argv, **input_args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=SAFE_ENV, check=False)
    require(result.returncode == 0, 'Required command failed; no new Guard was started.')
    return result.stdout


def trusted(path, *, directory=False):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode), 'Symlink refused for supervisor state or tool.')
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'Root ownership and no shared writes required.')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            'Unexpected file type.')


def directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    trusted(path, directory=True)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'Supervisor directory must be mode 0700.')


def preflight(*, installing=False):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root is required.')
    for binary in ((DOCKER, SYSTEMCTL, CREDS, COSIGN) if installing else (DOCKER,)):
        path = Path(binary)
        trusted(path)
        for parent in path.parents:
            trusted(parent, directory=True)
    info = SOCKET.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0, 'A root-owned local Docker socket is required.')
    if not installing:
        return
    version = execute([SYSTEMCTL, '--version']).decode().splitlines()[0]
    match = re.match(r'systemd ([0-9]+)', version)
    require(match is not None and int(match[1]) >= 250, 'systemd 250 or newer is required.')
    execute([CREDS, '--version'])


def docker(*args, data=None):
    return execute([DOCKER, '--config', str(BASE / 'docker-config'),
                    '--host', 'unix:///var/run/docker.sock', *args], data=data)


def docker_json(*args):
    try:
        return json.loads(docker(*args))
    except (ValueError, UnicodeError) as error:
        raise Refused('Docker returned invalid metadata.') from error


def validate(config):
    require(set(config) == {'image', 'tag', 'volume', 'account', 'instance'}, 'Unexpected supervisor configuration.')
    patterns = {'image': IMAGE_RE, 'tag': r'v[0-9]+\.[0-9]+\.[0-9]+',
                'volume': VOLUME_RE, 'account': ACCOUNT_RE, 'instance': r'[a-f0-9]{32}'}
    for field, pattern in patterns.items():
        require(isinstance(config[field], str) and re.fullmatch(pattern, config[field]),
                'Invalid ' + field + '.')
    require(config['account'].lower() != '0x' + '0' * 40, 'Zero account refused.')


def load():
    path = BASE / 'config.json'
    trusted(path)
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Supervisor config must be mode 0600.')
    config = json.loads(path.read_text())
    validate(config)
    return config


def ids(*filters):
    args = ['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}']
    for value in filters:
        args += ['--filter', value]
    values = docker(*args).decode().splitlines()
    require(all(re.fullmatch(r'[a-f0-9]{64}', value) for value in values), 'Unexpected container ID.')
    return values


def inspect_owned(identifier, config):
    require(re.fullmatch(r'[a-f0-9]{64}', identifier), 'Full container ID required.')
    objects = docker_json('container', 'inspect', identifier)
    require(isinstance(objects, list) and len(objects) == 1, 'Container inspection refused.')
    obj = objects[0]
    require(obj.get('Id') == identifier and obj.get('Name') == '/' + NAME, 'Container identity changed.')
    require((obj.get('Config', {}).get('Labels') or {}).get(LABEL) == config['instance'],
            'Container belongs to another owner; refusing cleanup.')
    mounts = obj.get('Mounts', [])
    require(any(m.get('Type') == 'volume' and m.get('Name') == config['volume']
                and m.get('Destination') == '/data' for m in mounts), 'Container volume does not match.')
    require(obj.get('Config', {}).get('Image') == config['image'], 'Container image does not match.')
    return obj


def cleanup(config):
    # Name resolution never authorizes deletion. Inspect/reinspect the immutable ID.
    named = ids('name=^/' + NAME + '$')
    require(len(named) <= 1, 'Ambiguous supervisor container name.')
    labelled = ids('label=' + LABEL + '=' + config['instance'])
    mounted = ids('volume=' + config['volume'])
    require(set(labelled) <= set(named) and set(mounted) <= set(named),
            'Another container owns this instance or volume; stop and resolve it first.')
    for identifier in named:
        inspect_owned(identifier, config)
        inspect_owned(identifier, config)
        docker('container', 'stop', '--time', '45', identifier)
        # --rm may already have removed it. Listing errors are not absence.
        if identifier in ids():
            inspect_owned(identifier, config)
            docker('container', 'rm', identifier)
    require(not ids('name=^/' + NAME + '$') and not ids('volume=' + config['volume']),
            'Cleanup did not finish; a new Guard will not start.')
    cid = RUNTIME / 'container.id'
    if cid.exists() or cid.is_symlink():
        trusted(cid)
        cid.unlink()


def volume_exists(config):
    volumes = docker_json('volume', 'inspect', config['volume'])
    require(isinstance(volumes, list) and len(volumes) == 1
            and volumes[0].get('Name') == config['volume'], 'Existing named volume required.')


def image_ready(config):
    objects = docker_json('image', 'inspect', config['image'])
    require(isinstance(objects, list) and len(objects) == 1, 'Verified image is not available locally.')
    obj = objects[0]
    require(config['image'] in obj.get('RepoDigests', []), 'Local image digest does not match.')
    require(obj.get('Config', {}).get('User') == '65532:65532', 'Signed image must use Guard nonroot UID.')


def container_args(config, *, readonly_volume=False):
    mount = 'type=volume,source=' + config['volume'] + ',target=/data'
    if readonly_volume:
        mount += ',readonly'
    return ['--rm', '--init', '--pull=never', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--ulimit', 'core=0',
            '--mount', mount, '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
            '--env', 'ZUNDER_GUARD_HOME=/data']


def operations():
    path = HELPER.with_name('operations.py')
    trusted(path)
    for parent in path.parents:
        trusted(parent, directory=True)
    spec = importlib.util.spec_from_file_location('guard_container_operations', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_config(config, *, transient=False):
    volume_exists(config)
    image_ready(config)
    if transient:
        run_operation = operations().run
    else:
        # Preserve the separately reviewed runtime preflight: these commands read only public
        # configuration, consume no key and emit no pairing/client key. Installer paths below
        # use the independently supervised operation utility, including their config queries.
        def run_operation(current, command):
            return docker('run', '--log-driver=none', *container_args(current, readonly_volume=True),
                          current['image'], *command)
    mode = run_operation(config, ['config', 'get', 'mode']).decode().strip()
    account = run_operation(config, ['config', 'get', 'account']).decode().strip()
    require(mode == 'mainnet' and account.lower() == config['account'].lower(),
            'Existing mainnet config and exact account must match.')
    run_operation(config, ['check-config'])


def atomic(path, content):
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def inactive():
    result = subprocess.run([SYSTEMCTL, 'is-active', UNIT], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=SAFE_ENV, check=False)
    require(result.returncode in (3, 4) and result.stdout.strip() in (b'inactive', b'failed', b'unknown'),
            'Stop the supervisor service before installation or reconfiguration.')


def install(args):
    config = dict(image=args.image, tag=args.tag, volume=args.volume,
                  account=args.account, instance=uuid.uuid4().hex)
    validate(config)
    require(args.confirm_account == args.account, 'Repeat the exact account confirmation.')
    inactive()
    require(not ids('name=^/' + NAME + '$') and not ids('volume=' + config['volume']),
            'Existing containers must be stopped and removed without removing the volume first.')
    if (BASE / 'config.json').exists():
        previous = load()
        require(previous['volume'] == config['volume'] and previous['account'] == config['account'],
                'Changing the supervisor account or volume requires a separate migration.')
        config['instance'] = previous['instance']
    execute([COSIGN, 'verify', config['image'], '--certificate-identity',
             'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/' + config['tag'],
             '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'])
    volume_exists(config)
    docker('pull', config['image'])
    check_config(config, transient=True)
    require(args.key_stdin or sys.stdin.isatty(), 'Use a terminal for the hidden prompt, or pass --key-stdin.')
    key = sys.stdin.buffer.readline(257) if args.key_stdin else (getpass.getpass('API wallet key (hidden): ') + '\n').encode()
    require(re.fullmatch(rb'(?:0x)?[a-fA-F0-9]{64}\r?\n?', key), 'Invalid API wallet key format.')
    try:
        # Existing initialized mainnet homes already have api_wallet. Read-only mount
        # refuses any attempted config update if they do not; no config is changed.
        operations().run(config, ['key', 'check', '--key-stdin'], data=key)
        encrypted = execute([CREDS, 'encrypt', '--name=' + CREDENTIAL, '-', '-'], data=key)
        require(bool(encrypted), 'Credential encryption produced no output.')
    finally:
        del key  # Lifetime reduction only; Python cannot promise memory zeroization.
    trusted(HELPER)
    trusted(UNIT_SOURCE)
    inactive()
    require(not ids('name=^/' + NAME + '$') and not ids('volume=' + config['volume']),
            'A container appeared during setup; refusing installation.')
    atomic(BASE / 'credential.cred', encrypted)
    atomic(BASE / 'config.json', (json.dumps(config, sort_keys=True) + '\n').encode())
    atomic(UNIT_PATH, UNIT_SOURCE.read_bytes())
    execute([SYSTEMCTL, 'daemon-reload'])
    execute([SYSTEMCTL, 'enable', UNIT])
    print('Supervisor installed and enabled, but STOPPED. Review the mainnet journal and start explicitly.')


def credential_stdin():
    """Open systemd's in-memory credential AFTER ExecStart; never read it into Python."""
    # Root system services have this fixed credential namespace. No caller path or
    # inherited stdin/environment key is accepted as a fallback.
    path = CREDENTIAL_ROOT / UNIT
    for parent in path.parents:
        trusted(parent, directory=True)
    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    credential_fd = None
    try:
        directory_info = os.fstat(directory_fd)
        require(stat.S_ISDIR(directory_info.st_mode) and directory_info.st_uid == 0
                and not directory_info.st_mode & 0o077, 'Private systemd credential directory required.')
        credential_fd = os.open(CREDENTIAL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        info = os.fstat(credential_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
                and 0 < info.st_size <= 257, 'Private systemd credential file required.')
        os.close(directory_fd)
        directory_fd = None
        if credential_fd == 0:
            os.set_inheritable(0, True)
        else:
            os.dup2(credential_fd, 0, inheritable=True)
    finally:
        if credential_fd is not None and credential_fd != 0:
            os.close(credential_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def runtime(config):
    cleanup(config)
    check_config(config)
    argv = [DOCKER, '--config', str(BASE / 'docker-config'), '--host', 'unix:///var/run/docker.sock',
            'run', '-i', *container_args(config), '--name', NAME,
            '--label', LABEL + '=' + config['instance'], '--cidfile', str(RUNTIME / 'container.id'),
            '--publish', '127.0.0.1:8547:8547', '--env', 'ZUNDER_GUARD_LISTEN=0.0.0.0:8547',
            '--env', 'ZUNDER_MAINNET_CONFIRM=' + config['account'], config['image'],
            'run', '--network', 'mainnet', '--key-stdin']
    # systemd has now installed the credential namespace. Open it afresh on each
    # ExecStart, after non-secret preflight commands, and forward only descriptor 0.
    credential_stdin()
    os.execve(DOCKER, argv, SAFE_ENV)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('install')
    for flag in ('image', 'tag', 'volume', 'account', 'confirm-account'):
        setup.add_argument('--' + flag, required=True)
    setup.add_argument('--key-stdin', action='store_true')
    commands.add_parser('run')
    commands.add_parser('stop')
    args = parser.parse_args()
    preflight(installing=args.command == 'install')
    trusted(BASE.parent, directory=True)
    directory(BASE)
    directory(BASE / 'docker-config')
    require(not list((BASE / 'docker-config').iterdir()), 'Docker configuration directory must remain empty.')
    trusted(RUNTIME.parent, directory=True)
    directory(RUNTIME)
    if args.command == 'stop':
        cleanup(load())
        return
    # The run lock survives exec and CLI lifetime. ExecStop/StopPost deliberately do
    # not acquire it; they stop only an admitted owned immutable container ID.
    lock = os.open(RUNTIME / 'supervisor.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.set_inheritable(lock, True)
        if args.command == 'install':
            install(args)
        else:
            runtime(load())
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError) as error:
        # Secret-bearing subprocess stderr is never replayed. Other errors are
        # deliberately generic; journal/status explain Guard failures separately.
        print('Container supervisor refused: ' + (str(error) if isinstance(error, Refused) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
