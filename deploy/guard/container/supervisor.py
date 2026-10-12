#!/usr/bin/python3
"""Linux systemd credential → local Docker stdin. No key files or Docker restart policy.

Install only verified release bytes. This helper never initializes or resets Guard state.
"""
import argparse
import fcntl
import getpass
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
import tempfile
import types
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


def sending_mode(config):
    # Missing mode is the immutable legacy mainnet schema, never inferred Testnet.
    mode = config.get('mode', 'mainnet')
    require(mode in ('mainnet', 'testnet'), 'Sending network must be explicit and supported.')
    return mode


def validate(config):
    fields = {'image', 'tag', 'volume', 'account', 'instance'}
    require(set(config) in (fields, fields | {'mode'}), 'Unexpected supervisor configuration.')
    sending_mode(config)
    patterns = {'image': IMAGE_RE, 'tag': r'v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?',
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


def owned_containers(config):
    # Name resolution never authorizes deletion. Inspect/reinspect the immutable ID.
    named = ids('name=^/' + NAME + '$')
    require(len(named) <= 1, 'Ambiguous supervisor container name.')
    labelled = ids('label=' + LABEL + '=' + config['instance'])
    mounted = ids('volume=' + config['volume'])
    require(set(labelled) <= set(named) and set(mounted) <= set(named),
            'Another container owns this instance or volume; stop and resolve it first.')
    for identifier in named:
        inspect_owned(identifier, config)
    return named


def cleanup(config):
    for identifier in owned_containers(config):
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


PREPARED_IMAGE = Path('/etc/zunder-guard-container-image-prepared')


def prepared_image(config, manifest, source):
    """Root-prepared image cache; never an acceptance attestation."""
    require(sending_mode(config) == 'testnet', 'Prepared private images are admitted on explicit Testnet only.')
    require(re.fullmatch('[0-9a-f]{64}', manifest or '') and re.fullmatch('[0-9a-f]{40}', source or ''),
            'Exact independently verified manifest/source binding required.')
    for parent in PREPARED_IMAGE.parents:
        trusted(parent, directory=True)
    trusted(PREPARED_IMAGE, directory=True)
    require(stat.S_IMODE(PREPARED_IMAGE.stat().st_mode) == 0o700
            and {p.name for p in PREPARED_IMAGE.iterdir()} == {'receipt.json'}, 'Private prepared-image receipt required.')
    receipt = PREPARED_IMAGE / 'receipt.json'
    trusted(receipt)
    info = receipt.stat()
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 65536,
            'Bounded root-only prepared-image receipt required.')
    value = json.loads(receipt.read_bytes())
    require(set(value) == {'schema', 'tag', 'image', 'image_id', 'manifest_sha256', 'source_commit'}
            and value['schema'] == 1 and value['tag'] == config['tag'] and value['image'] == config['image']
            and value['manifest_sha256'] == manifest and value['source_commit'] == source,
            'Prepared image does not bind this exact signed release/source.')
    objects = docker_json('image', 'inspect', config['image'])
    require(len(objects) == 1 and objects[0]['Id'] == value['image_id']
            and config['image'] in objects[0].get('RepoDigests', []), 'Prepared immutable local image changed.')
    image_ready(config)
    return value


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
    source = spec.loader.get_source(spec.name)
    require(source is not None, "Operation source is missing.")
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
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
    require(mode == sending_mode(config) and account.lower() == config['account'].lower(),
            'Existing sending network and exact account must match.')
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
    supplied = (getattr(args, 'manifest_sha256', ''), getattr(args, 'source_commit', ''))
    require((getattr(args, 'prepared_image', False) and all(supplied))
            or (not getattr(args, 'prepared_image', False) and not any(supplied)),
            'Prepared image/source inputs require an explicit matching admission.')
    config = dict(image=args.image, tag=args.tag, volume=args.volume,
                  account=args.account, instance=uuid.uuid4().hex)
    if getattr(args, 'network', 'mainnet') != 'mainnet':
        config['mode'] = args.network
    validate(config)
    require(args.confirm_account == args.account, 'Repeat the exact account confirmation.')
    inactive()
    require(not ids('name=^/' + NAME + '$') and not ids('volume=' + config['volume']),
            'Existing containers must be stopped and removed without removing the volume first.')
    if (BASE / 'config.json').exists():
        previous = load()
        require(sending_mode(previous) == sending_mode(config)
                and previous['volume'] == config['volume'] and previous['account'] == config['account'],
                'Changing the supervisor network, account or volume requires a separate migration.')
        config['instance'] = previous['instance']
    if getattr(args, 'prepared_image', False):
        prepared_image(config, args.manifest_sha256, args.source_commit)
    else:
        execute([COSIGN, 'verify', config['image'], '--certificate-identity',
                 'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/' + config['tag'],
                 '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'])
        docker('pull', config['image'])
    volume_exists(config)
    check_config(config, transient=True)
    require(args.key_stdin or sys.stdin.isatty(), 'Use a terminal for the hidden prompt, or pass --key-stdin.')
    key = read_key_frame(sys.stdin.buffer) if args.key_stdin else (getpass.getpass('API wallet key (hidden): ') + '\n').encode()
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
    print('Supervisor installed and enabled, but STOPPED. Review the ' + sending_mode(config) + ' journal and start explicitly.')


GUARDIAN = 'zunder-guard-setup-guardian.service'


def private_lock(path):
    if path.exists() or path.is_symlink():
        trusted(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'Private uninstall lock required.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_json(path):
    trusted(path)
    info = path.stat()
    require(info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= 1024 * 1024, 'Bounded private recovery record required.')
    return json.loads(path.read_bytes())


def uninstall_pending():
    # Equivalent to operations.pending/terminal, kept local so partially removed owned
    # helpers never become a missing-module fallback or an inferred successful cleanup.
    registry = BASE / 'operations'
    trusted(registry, directory=True)
    require(stat.S_IMODE(registry.stat().st_mode) == 0o700, 'Private operation history required.')
    pending = []
    for path in registry.iterdir():
        if path.name == 'guardian.lock':
            trusted(path)
            continue
        require(re.fullmatch('[a-f0-9]{32}', path.name), 'Unknown operation history entry.')
        trusted(path, directory=True)
        done_path = path / 'done.json'
        if not done_path.exists() and not done_path.is_symlink():
            pending.append(path)
            continue
        done = private_json(done_path)
        record = private_json(path / 'record.json')
        require(isinstance(done, dict) and isinstance(record, dict), 'Malformed operation history.')
        fields = {'operation', 'image', 'volume', 'boot', 'created'}
        require(set(record) in (fields, fields | {'version'}) and record.get('version') in (None, 2),
                'Malformed operation record identity.')
        for name, pattern in [('operation', '[a-f0-9]{32}'), ('image', IMAGE_RE),
                              ('volume', VOLUME_RE), ('boot', '[a-f0-9-]{36}')]:
            require(isinstance(record[name], str) and re.fullmatch(pattern, record[name]),
                    'Malformed operation identity.')
        require(record['operation'] == path.name and type(record['created']) in (int, float)
                and 0 <= record['created'] < float('inf'), 'Malformed operation directory/clock.')
        terminal = False
        if done.get('version') == 2:
            if done.get('outcome') == 'never-dispatched':
                terminal = (record.get('version') == 2 and not (path / 'create.json').exists()
                            and not (path / 'create.json').is_symlink())
            elif done.get('outcome') == 'removed' and (path / 'id.json').exists():
                identifier = private_json(path / 'id.json')
                terminal = (isinstance(identifier, str) and re.fullmatch('[a-f0-9]{64}', identifier)
                            and done.get('id') == identifier)
        if not terminal:
            pending.append(path)
    return pending


def loaded_command(command, expected):
    match = re.fullmatch(r'\{([^{}]*)\}', command.strip(), flags=re.S)
    if not match:
        return False
    fields = {}
    for part in match[1].split(';'):
        part = part.strip()
        if not part:
            continue
        name, separator, value = part.partition('=')
        if not separator or name.strip() in fields:
            return False
        fields[name.strip()] = value.strip()
    return fields.get('path') == expected[0] and fields.get('argv[]', '').split() == expected


def service_property(unit, property):
    return execute([SYSTEMCTL, 'show', unit, '--property=' + property, '--value']).decode().strip()


def uninstall_assets():
    return [UNIT_PATH, UNIT_PATH.with_name(GUARDIAN), UNIT_SOURCE,
            HELPER.with_name('operations.py'), HELPER]


def owned_bytecode_cache(allowed):
    cache = HELPER.parent / '__pycache__'
    if not cache.exists() and not cache.is_symlink():
        return []
    trusted(cache, directory=True)
    files = []
    for path in cache.iterdir():
        match = re.fullmatch(r'(supervisor|operations)\.' + re.escape(sys.implementation.cache_tag)
                             + r'(?:\.opt-([12]))?\.pyc', path.name)
        require(match is not None, 'Unknown compiled helper cache; refusing removal.')
        trusted(path)
        info = path.stat()
        require(info.st_nlink == 1 and 16 < info.st_size <= 8 * 1024 * 1024,
                'Unexpected compiled helper cache metadata.')
        source = HELPER.with_name(match[1] + '.py')
        trusted(source)
        body = source.read_bytes()
        require(len(body) <= 1024 * 1024 and hashlib.sha256(body).hexdigest()
                in allowed.get(str(source), []), 'Cache source lacks managed release ownership.')
        expected = compile(body, str(source), 'exec', dont_inherit=True, optimize=int(match[2] or 0))
        compiled = path.read_bytes()
        require(compiled[:4] == importlib.util.MAGIC_NUMBER
                and int.from_bytes(compiled[4:8], 'little') in (0, 1, 3), 'Unknown compiled helper format.')
        try:
            payload = marshal.loads(compiled[16:])
        except (ValueError, EOFError, TypeError, MemoryError):
            raise Refused('Compiled helper cache is malformed.') from None
        require(isinstance(payload, types.CodeType) and payload == expected
                and payload.co_filename == str(source), 'Compiled helper differs from admitted source.')
        files.append(path)
    return files


def remove_owned_bytecode_cache(receipt):
    # No cached code is executed. Authenticate every payload before any unlink.
    files = owned_bytecode_cache(receipt['allowed_files'])
    for path in files:
        path.unlink()
    cache = HELPER.parent / '__pycache__'
    if cache.exists():
        cache.rmdir()


def uninstall_admit(config, *, guardian_only=False):
    receipt = private_json(BASE / 'managed-install.json')
    fields = {'version', 'account', 'volume', 'allowed_files', 'config_refs'}
    require(isinstance(receipt, dict) and set(receipt) in (fields, fields | {'mode'})
            and receipt['version'] == 1 and sending_mode(receipt) == sending_mode(config)
            and receipt['account'] == config['account'] and receipt['volume'] == config['volume'],
            'Managed receipt does not bind this sending installation.')
    assets = uninstall_assets()
    allowed = receipt['allowed_files']
    require(isinstance(allowed, dict) and set(allowed) == {str(p) for p in assets}
            and all(isinstance(v, list) and v and all(isinstance(h, str)
                and re.fullmatch('[a-f0-9]{64}', h) for h in v) for v in allowed.values()),
            'Exact managed software identities and hashes required.')
    refs = receipt['config_refs']
    require(isinstance(refs, list) and any(isinstance(ref, dict)
            and set(ref) in ({'account', 'volume', 'tag', 'image'},
                             {'account', 'volume', 'tag', 'image', 'mode'})
            and sending_mode(ref) == sending_mode(config)
            and all(config.get(k) == v for k, v in ref.items()) for ref in refs),
            'Configuration differs from managed recovery references.')
    for path in assets:
        if guardian_only and path not in (UNIT_PATH.with_name(GUARDIAN), HELPER.with_name('operations.py')):
            continue
        for parent in path.parents:
            trusted(parent, directory=True)
        if path.exists() or path.is_symlink():
            trusted(path)
            require(path.stat().st_nlink == 1
                    and hashlib.sha256(path.read_bytes()).hexdigest() in allowed[str(path)],
                    'Owned software hash changed; refusing uninstall.')
    if not guardian_only:
        owned_bytecode_cache(allowed)
    require(set(HELPER.parent.iterdir()) <= {HELPER, HELPER.with_name('operations.py'), UNIT_SOURCE,
                                           HELPER.parent / '__pycache__'},
            'Unknown installed helper file requires separate review.')
    dropin = UNIT_PATH.with_name(UNIT + '.d') / '10-install-transaction.conf'
    gate = BASE / 'install-transaction.json'
    text = ('[Unit]\n# Persist through enable, installer death and host reboot.\n'
            'ConditionPathExists=!' + str(gate) + '\n').encode()
    if not guardian_only:
        if dropin.parent.exists() or dropin.parent.is_symlink():
            trusted(dropin.parent, directory=True)
            require(set(dropin.parent.iterdir()) <= {dropin}, 'Foreign supervisor drop-in refused.')
    guardian_dropins = UNIT_PATH.with_name(GUARDIAN + '.d')
    if guardian_dropins.exists() or guardian_dropins.is_symlink():
        trusted(guardian_dropins, directory=True)
        require(not list(guardian_dropins.iterdir()), 'Foreign guardian drop-in refused.')
    if not guardian_only:
        if dropin.exists() or dropin.is_symlink():
            trusted(dropin)
            require(dropin.read_bytes() == text, 'Activation drop-in ownership differs.')
    states = {}
    for unit, helper in ((UNIT, HELPER), (GUARDIAN, HELPER.with_name('operations.py'))):
        if guardian_only and unit != GUARDIAN:
            continue
        fragment = service_property(unit, 'FragmentPath')
        state = service_property(unit, 'LoadState')
        dropins = service_property(unit, 'DropInPaths').split()
        require(set(dropins) <= ({str(dropin)} if unit == UNIT else set()), 'Foreign loaded drop-in refused.')
        if state == 'not-found':
            require(not fragment and not UNIT_PATH.with_name(unit).exists(), 'Unexpected unloaded unit file.')
        else:
            require(state == 'loaded' and fragment == str(UNIT_PATH.with_name(unit)) and helper.exists(),
                    'Loaded unit is not owned by this installer.')
            expected = (['/usr/bin/python3', str(helper), 'run'] if unit == UNIT
                        else ['/usr/bin/python3', '-I', str(helper)])
            require(loaded_command(service_property(unit, 'ExecStart'), expected), 'Loaded command differs.')
        states[unit] = state
    return assets, dropin, states


def service_inactive(unit):
    result = subprocess.run([SYSTEMCTL, 'is-active', unit], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=SAFE_ENV,
                            timeout=15, check=False)
    require(result.returncode in (3, 4) and result.stdout.strip() in (b'inactive', b'failed', b'unknown'),
            'Owned service did not stop; uninstall refused.')


def uninstall(network):
    # The installer-wide lock precedes all installation/operation/configuration reads.
    lock = private_lock(BASE / 'installer.lock')
    guardian_lock = None
    try:
        directory(BASE / 'docker-config')
        require(not list((BASE / 'docker-config').iterdir()), 'Docker configuration directory must remain empty.')
        config = load()
        require(sending_mode(config) == network, 'Explicit uninstall network differs.')
        assets, dropin, states = uninstall_admit(config)
        gate = BASE / 'install-transaction.json'
        require(not gate.exists() and not gate.is_symlink(), 'Resolve installer transaction before uninstall.')
        require(not uninstall_pending(), 'Resolve setup operations before uninstall; guardian remains installed.')
        volume_exists(config)
        owned_containers(config)  # Admission is read-only; a foreign container cannot authorize a stop.
        missing_units = [unit for unit in (UNIT, GUARDIAN)
                         if states[unit] == 'loaded' and not UNIT_PATH.with_name(unit).exists()]
        if missing_units:
            # A previous removal may have failed before daemon-reload. Missing files do
            # not prove ownership or inactivity; require both admission and inactive readback.
            for unit in missing_units:
                service_inactive(unit)
            execute([SYSTEMCTL, 'daemon-reload'])
            assets, dropin, states = uninstall_admit(config)
        guardian_enabled = (service_property(GUARDIAN, 'UnitFileState')
                            if states[GUARDIAN] == 'loaded' else 'not-found')
        require(guardian_enabled in ('enabled', 'disabled', 'not-found'),
                'Guardian boot configuration requires separate review.')
        try:
            if states[UNIT] == 'loaded':
                execute([SYSTEMCTL, 'stop', UNIT])
                execute([SYSTEMCTL, 'disable', UNIT])
            service_inactive(UNIT)
            cleanup(config)
            require(not uninstall_pending(), 'Setup operations appeared; guardian remains installed.')
            if states[GUARDIAN] == 'loaded':
                execute([SYSTEMCTL, 'stop', GUARDIAN])
                execute([SYSTEMCTL, 'disable', GUARDIAN])
            service_inactive(GUARDIAN)
            guardian_lock = private_lock(BASE / 'operations/guardian.lock')
            require(not uninstall_pending(), 'Setup operation cleanup remains unresolved.')
            # Re-admit disk and loaded ownership under both locks immediately before unlinking.
            uninstall_admit(config)
            require(not gate.exists() and not gate.is_symlink(), 'Installer transaction appeared.')
            require(not ids('name=^/' + NAME + '$') and not ids('volume=' + config['volume']),
                    'Container/volume is still in use; software is preserved.')
            remove_owned_bytecode_cache(private_json(BASE / 'managed-install.json'))
        except BaseException:
            if guardian_lock is not None:
                os.close(guardian_lock)
                guardian_lock = None
            if states[GUARDIAN] == "loaded":
                try:
                    uninstall_admit(config, guardian_only=True)
                except BaseException:
                    raise Refused('Guardian ownership changed; recovery is unknown and software is preserved.') from None
                recovery_failed = False
                try:
                    execute([SYSTEMCTL, 'enable' if guardian_enabled == 'enabled' else 'disable', GUARDIAN])
                    require(service_property(GUARDIAN, 'UnitFileState') == guardian_enabled,
                            'Guardian boot recovery readback differs.')
                except BaseException:
                    recovery_failed = True
                try:
                    execute([SYSTEMCTL, 'start', GUARDIAN])  # Cleanup guardian only, never Guard.
                    require(service_property(GUARDIAN, 'ActiveState') == 'active',
                            'Guardian active recovery readback differs.')
                except BaseException:
                    recovery_failed = True
                require(not recovery_failed, 'Guardian recovery is uncertain; resolve it explicitly.')
            raise
        for path in (UNIT_PATH, UNIT_PATH.with_name(GUARDIAN), dropin):
            if path.exists():
                path.unlink()
        if dropin.parent.exists():
            dropin.parent.rmdir()
        execute([SYSTEMCTL, 'daemon-reload'])
        for unit in (UNIT, GUARDIAN):
            require(service_property(unit, 'LoadState') == 'not-found'
                    and not service_property(unit, 'FragmentPath'), 'Owned service remains registered.')
        volume_exists(config)
        # Keep helpers through fallible service cleanup, and the running helper until last.
        for path in assets[2:]:
            if path.exists():
                path.unlink()
        HELPER.parent.rmdir()
        require(not any(path.exists() or path.is_symlink() for path in assets), 'Owned software remains.')
        print('Owned container services and software uninstalled. Named volume and private recovery data retained.')
    finally:
        if guardian_lock is not None:
            os.close(guardian_lock)
        os.close(lock)


def read_key_frame(stream):
    # Exactly one LF-terminated frame; bound malformed input without consuming another frame.
    # A buffered readline may steal the next frame from a child inheriting fd 0.
    source = getattr(stream, 'raw', stream)
    key = bytearray()
    while len(key) < 257:
        value = source.read(1)
        if not value:
            break
        key.extend(value)
        if value == b'\n':
            break
    key = bytes(key)
    require(re.fullmatch(rb'(?:0x)?[a-fA-F0-9]{64}\r?\n', key), 'Invalid private stdin key frame.')
    return key


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
            '--publish', '127.0.0.1:8547:8547', '--env', 'ZUNDER_GUARD_LISTEN=0.0.0.0:8547']
    mode = sending_mode(config)
    if mode == 'mainnet':
        argv += ['--env', 'ZUNDER_MAINNET_CONFIRM=' + config['account']]
    argv += [config['image'], 'run', '--network', mode, '--key-stdin']
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
    setup.add_argument('--prepared-image', action='store_true')
    setup.add_argument('--manifest-sha256', default='')
    setup.add_argument('--source-commit', default='')
    setup.add_argument('--key-stdin', action='store_true')
    setup.add_argument('--network', choices=('mainnet', 'testnet'), default='mainnet')
    commands.add_parser('run')
    commands.add_parser('stop')
    remove = commands.add_parser('uninstall')
    remove.add_argument('--network', choices=('mainnet', 'testnet'), required=True)
    args = parser.parse_args()
    preflight(installing=args.command == 'install')
    if args.command == 'uninstall':
        for parent in BASE.parents:
            trusted(parent, directory=True)
        trusted(BASE, directory=True)
        require(stat.S_IMODE(BASE.stat().st_mode) == 0o700, 'Private installation state required.')
        trusted(Path(SYSTEMCTL))
        for parent in Path(SYSTEMCTL).parents:
            trusted(parent, directory=True)
        uninstall(args.network)
        return
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
