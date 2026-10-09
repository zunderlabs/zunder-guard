#!/usr/bin/python3
"""Verified Linux container setup. Unattended provisioning requires explicit Testnet."""
import argparse
import base64
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import time
import tomllib
from decimal import Decimal
import uuid

STAGE = Path(__file__).resolve().parent
BASE = Path('/etc/zunder-guard-container')
LIB = Path('/usr/local/libexec/zunder-guard-container')
UNIT_DIR = Path('/etc/systemd/system')
UNIT = 'zunder-guard-container.service'
GUARDIAN = 'zunder-guard-setup-guardian.service'
GATE = BASE / 'install-transaction.json'
DROPIN = UNIT_DIR / (UNIT + '.d') / '10-install-transaction.conf'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}


def load_module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Bootstrap authenticates these root-private files before invoking this script with -I.
ops = load_module('container_operations', STAGE / 'container-operations.py')
require = ops.require


def run(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=90, check=False)
    require(result.returncode == 0, 'Required host command failed; setup remains stopped.')
    return result.stdout.decode().strip()


def mkdir(path, mode=0o700):
    if not path.exists():
        path.mkdir(mode=mode)
    ops.trusted(path, True)
    ops.parents(path)


def file_write(path, data, mode=0o644):
    import tempfile
    ops.trusted(path.parent, True)
    if path.exists() or path.is_symlink():
        ops.trusted(path)
    fd, temporary = tempfile.mkstemp(prefix='.verified-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        ops.sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prompt(text):
    with open('/dev/tty', 'r+') as terminal:
        terminal.write(text + ' ')
        terminal.flush()
        answer = terminal.readline()
    require(bool(answer), 'Terminal closed; activation remains inhibited.')
    return answer.strip()


def sending_mode(config):
    mode = config.get('mode', 'mainnet')
    require(mode in ('mainnet', 'testnet'), 'Unsupported sending network.')
    return mode


def validate_input(args, terminal):
    require(args.network in ('mainnet', 'testnet'), 'Unsupported sending network.')
    if args.non_interactive or args.key_stdin:
        require(args.network == 'testnet' and args.non_interactive and args.key_stdin,
                'Unattended private stdin provisioning requires explicit Testnet.')
        require(not terminal, 'Testnet key input must be a private redirected pipe, never an echoing terminal.')
        require(re.fullmatch('0x[a-fA-F0-9]{40}', args.account or ''), 'Explicit Testnet account required.')
    else:
        require(terminal, 'An interactive terminal is required.')


def confirm(text, expected):
    require(prompt(text) == expected, 'Confirmation did not match; setup remains stopped.')


def registry_auth(path):
    """Explicit isolated basic GHCR auth only; no helpers or ambient fallback."""
    require(path.is_absolute() and path.resolve() == path, 'Canonical isolated registry auth directory required.')
    ops.parents(path); ops.trusted(path, True)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700 and {p.name for p in path.iterdir()} == {'config.json'},
            'Isolated auth directory must contain only config.json, mode 0700.')
    config = path / 'config.json'; ops.trusted(config)
    info = config.stat()
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and 0 < info.st_size <= 4096,
            'Root-only bounded auth file required.')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'Duplicate registry auth field.'); value[key] = item
        return value
    try:
        value = json.loads(config.read_bytes(), object_pairs_hook=pairs)
        require(type(value) is dict and set(value) == {'auths'} and type(value['auths']) is dict
                and set(value['auths']) == {'ghcr.io'} and type(value['auths']['ghcr.io']) is dict
                and set(value['auths']['ghcr.io']) == {'auth'}, 'Only explicit ghcr.io basic auth is admitted.')
        encoded = value['auths']['ghcr.io']['auth']
        require(type(encoded) is str and len(encoded) <= 2048, 'Bounded basic auth required.')
        secret = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(secret).decode() == encoded
                and re.fullmatch(rb'[A-Za-z0-9_-]{1,64}:[A-Za-z0-9_]{1,512}', secret),
                'Canonical GHCR basic authentication required.')
    except (ValueError, UnicodeError, TypeError):
        raise ops.Refused('Malformed isolated registry authentication.') from None
    return (path.stat().st_dev, path.stat().st_ino, info.st_dev, info.st_ino)


def scrub_registry_auth(path, identity):
    config = path / 'config.json'
    require((path.stat().st_dev, path.stat().st_ino, config.stat().st_dev, config.stat().st_ino) == identity
            and {p.name for p in path.iterdir()} == {'config.json'}, 'Registry auth changed; refuse blind removal.')
    ops.trusted(path, True); ops.trusted(config)
    require(config.stat().st_nlink == 1, 'Linked auth is never scrubbed blindly.')
    config.unlink(); path.rmdir()
    require(not path.exists() and not config.exists(), 'Registry auth cleanup incomplete.')
    descriptor = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def prepare_image(args, sup):
    require(args.network == 'testnet' and not any((args.rules, args.account, args.volume, args.equity_cap,
            args.ip_share, args.licence, args.key_stdin, args.non_interactive, args.prepared_image)),
            'Image preparation admits no wallet/setup options.')
    require(re.fullmatch('[0-9a-f]{40}', args.source_commit or ''), 'Independently verified exact source required.')
    auth = Path(args.registry_auth_dir); identity = registry_auth(auth)
    try:
        require(not sup.PREPARED_IMAGE.exists() and not sup.PREPARED_IMAGE.is_symlink(),
                'Existing prepared image requires separate review; never replace silently.')
        image = (STAGE / ('zunder-guard-' + args.version + '.image.txt')).read_text().strip()
        require(re.fullmatch(r'ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}', image), 'Exact signed OCI descriptor required.')
        env = dict(ENV, DOCKER_CONFIG=str(auth))  # Public path only, never a token value.
        commands = [
            [sup.COSIGN, 'verify', image, '--certificate-identity',
             'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/' + args.version,
             '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'],
            [sup.DOCKER, '--config', str(auth), '--host', 'unix:///var/run/docker.sock', 'pull', image],
            [sup.DOCKER, '--config', str(auth), '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', image]]
        outputs = []
        for command in commands:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, timeout=600, check=False)
            require(result.returncode == 0 and len(result.stdout) <= 1024*1024 and len(result.stderr) <= 1024*1024,
                    'Private artifact verification/pull failed; no wallet input is admitted.')
            outputs.append(result.stdout)
        objects = json.loads(outputs[-1])
        require(len(objects) == 1 and re.fullmatch('sha256:[0-9a-f]{64}', objects[0]['Id'])
                and image in objects[0].get('RepoDigests', []) and objects[0].get('Config', {}).get('User') == '65532:65532',
                'Immutable signed image binding differs.')
        manifest = hashlib.sha256((STAGE / 'SHA256SUMS').read_bytes()).hexdigest()
        value = dict(schema=1, tag=args.version, image=image, image_id=objects[0]['Id'],
                     manifest_sha256=manifest, source_commit=args.source_commit)
    finally:
        # Any failure after admission still scrubs only the exact owned auth input.
        scrub_registry_auth(auth, identity)
    sup.directory(sup.PREPARED_IMAGE)
    fd = os.open(sup.PREPARED_IMAGE / 'receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((json.dumps(value, sort_keys=True) + '\n').encode()); stream.flush(); os.fsync(stream.fileno())
    print('Exact signed image prepared. Isolated registry auth was removed. No wallet was read or installed.')


def enabled_state():
    result = subprocess.run([SYSTEMCTL, 'is-enabled', UNIT], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=15, check=False)
    value = result.stdout.decode().strip()
    if not value and not (UNIT_DIR / UNIT).exists():
        value = 'not-found'
    require(value in ('enabled', 'disabled', 'not-found'),
            'Masked, indirect or externally managed service requires separate review.')
    return value


def active_state():
    result = subprocess.run([SYSTEMCTL, 'is-active', UNIT], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=15, check=False)
    value = result.stdout.decode().strip()
    require(value in ('active', 'inactive', 'failed', 'unknown'), 'Service is transitioning; try again later.')
    return value


def gate_text():
    return ('[Unit]\n# Persist through enable, installer death and host reboot.\n'
            'ConditionPathExists=!' + str(GATE) + '\n').encode()


def verify_gate(loaded=True):
    ops.trusted(DROPIN)
    require(DROPIN.read_bytes() == gate_text() and GATE.exists(), 'Durable activation gate missing.')
    ops.trusted(GATE)
    if loaded:
        loaded_paths = run(SYSTEMCTL, 'show', UNIT, '--property=DropInPaths', '--value').split()
        require(str(DROPIN) in loaded_paths, 'Loaded systemd activation condition missing.')


def inhibit(config, fresh):
    mkdir(DROPIN.parent, 0o755)
    if DROPIN.exists() or DROPIN.is_symlink():
        ops.trusted(DROPIN)
        require(DROPIN.read_bytes() == gate_text(), 'An external installation condition requires separate review.')
    require(not any(path != DROPIN for path in DROPIN.parent.iterdir()),
            'Other supervisor drop-ins require separate review before managed upgrade.')
    if GATE.exists():
        record = ops.read(GATE)
        require(sending_mode(record) == sending_mode(config)
                and record.get('account') == config['account'] and record.get('volume') == config['volume']
                and record.get('original_enabled') in ('enabled', 'disabled', 'not-found')
                and re.fullmatch('[a-f0-9]{32}', record.get('transaction', '')),
                'Incomplete transaction does not match this installation.')
        require(not record.get('activation_committed', False), 'Unexpected transaction state.')
        file_write(DROPIN, gate_text())
    else:
        record = {'transaction': uuid.uuid4().hex, 'account': config['account'], 'volume': config['volume'],
                  'original_enabled': enabled_state(), 'original_active': active_state(),
                  'fresh': fresh, 'phase': 'inhibited'}
        if sending_mode(config) == 'testnet':
            record['mode'] = 'testnet'
        file_write(DROPIN, gate_text())
        ops.atomic(GATE, record)
    run(SYSTEMCTL, 'daemon-reload')
    verify_gate(loaded=(UNIT_DIR / UNIT).exists())
    return record


def phase(record, name):
    record['phase'] = name
    ops.atomic(GATE, record)


def managed_assets():
    return {
        LIB / 'supervisor.py': STAGE / 'container-supervisor.py',
        LIB / 'operations.py': STAGE / 'container-operations.py',
        LIB / 'zunder-guard-container.service': STAGE / 'zunder-guard-container.service',
        UNIT_DIR / UNIT: STAGE / 'zunder-guard-container.service',
        UNIT_DIR / GUARDIAN: STAGE / GUARDIAN,
    }


def ownership_receipt():
    path = BASE / 'managed-install.json'
    if not path.exists() and not path.is_symlink():
        return None
    ops.trusted(path)
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Managed receipt must be root-only.')
    receipt = ops.read(path)
    require(set(receipt) in ({'version', 'account', 'volume', 'allowed_files', 'config_refs'},
                             {'version', 'account', 'volume', 'allowed_files', 'config_refs', 'mode'})
            and receipt['version'] == 1, 'Invalid managed-install receipt.')
    require(set(receipt['allowed_files']) == {str(path) for path in managed_assets()},
            'Unexpected managed-install file identities.')
    require(all(isinstance(values, list) and values and
                all(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) for value in values)
                for values in receipt['allowed_files'].values()), 'Invalid managed-install hashes.')
    sending_mode(receipt)
    require(isinstance(receipt['config_refs'], list), 'Invalid managed configuration references.')
    return receipt


def exact_loaded_command(command, expected):
    # systemctl show --value renders each ExecStart as one {...} record. Our units
    # contain a single direct exec with fixed, whitespace-free paths/arguments.
    # Reject multiple records, duplicate fields and any different argument vector.
    match = re.fullmatch(r'\{([^{}]*)\}', command.strip(), flags=re.S)
    if not match:
        return False
    values = {}
    for part in match[1].split(';'):
        part = part.strip()
        if not part:
            continue
        key, separator, value = part.partition('=')
        if not separator or key.strip() in values:
            return False
        values[key.strip()] = value.strip()
    return values.get('path') == expected[0] and values.get('argv[]', '').split() == expected


def admit_services(config):
    """Root-owned is not installer-owned: bind disk AND systemd's loaded fragment."""
    receipt = ownership_receipt()
    if receipt:
        require(sending_mode(receipt) == sending_mode(config)
                and receipt['account'] == config['account'] and receipt['volume'] == config['volume'],
                'Managed receipt names another account or volume.')
    for target in managed_assets():
        if target.exists() or target.is_symlink():
            require(receipt is not None, 'Reserved service/helper exists without a managed-install receipt; refusing changes.')
            ops.trusted(target)
            ops.parents(target)
            require(hashlib.sha256(target.read_bytes()).hexdigest() in receipt['allowed_files'][str(target)],
                    'Installed service/helper differs from its managed receipt; refusing changes.')
    config_path = BASE / 'config.json'
    if config_path.exists() or config_path.is_symlink():
        require(receipt is not None, 'Existing supervisor config has no managed-install receipt.')
        current = ops.read(config_path)
        require(sending_mode(current) == sending_mode(config)
                and any(isinstance(ref, dict) and set(ref) in ({'account', 'volume', 'tag', 'image'},
                                                               {'account', 'volume', 'tag', 'image', 'mode'})
                    and sending_mode(ref) == sending_mode(current)
                    and all(current.get(key) == value for key, value in ref.items())
                    for ref in receipt['config_refs']), 'Installed configuration identity differs from its receipt.')
    if DROPIN.exists() or DROPIN.is_symlink():
        require(receipt is not None, 'Reserved service drop-in is not owned by this installer.')
        ops.trusted(DROPIN)
        require(DROPIN.read_bytes() == gate_text(), 'Reserved service drop-in was replaced.')
    for unit, helper in ((UNIT, LIB / 'supervisor.py'), (GUARDIAN, LIB / 'operations.py')):
        fragment = run(SYSTEMCTL, 'show', unit, '--property=FragmentPath', '--value')
        state = run(SYSTEMCTL, 'show', unit, '--property=LoadState', '--value')
        dropins = run(SYSTEMCTL, 'show', unit, '--property=DropInPaths', '--value').split()
        require(set(dropins) <= ({str(DROPIN)} if unit == UNIT else set()),
                'Externally configured service drop-ins require separate review.')
        if state == 'not-found':
            require(not fragment and not (UNIT_DIR / unit).exists(), 'Unexpected unloaded reserved service file.')
            continue
        require(state == 'loaded' and receipt is not None and fragment == str(UNIT_DIR / unit),
                'Systemd loaded an unowned reserved service fragment; refusing changes.')
        require(helper.exists(), 'Managed service helper is missing.')
        if unit == UNIT:
            require(config_path.exists(), 'Managed runtime service configuration is missing.')
        command = run(SYSTEMCTL, 'show', unit, '--property=ExecStart', '--value')
        expected = (['/usr/bin/python3', str(helper), 'run'] if unit == UNIT
                    else ['/usr/bin/python3', '-I', str(helper)])
        require(exact_loaded_command(command, expected), 'Systemd loaded an unexpected service command.')


def prepare_receipt(config):
    # Authenticate ownership before admitting additional signed upgrade bytes. Persist this
    # intent before any drop-in or helper replacement so interrupted upgrades remain resumable.
    admit_services(config)
    receipt = ownership_receipt() or {
        'version': 1, 'account': config['account'], 'volume': config['volume'],
        'allowed_files': {str(path): [] for path in managed_assets()}, 'config_refs': []}
    if sending_mode(config) == 'testnet':
        receipt['mode'] = 'testnet'
    for target, source in managed_assets().items():
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if digest not in receipt['allowed_files'][str(target)]:
            receipt['allowed_files'][str(target)].append(digest)
    reference = {key: config[key] for key in ('account', 'volume', 'tag', 'image')}
    if sending_mode(config) == 'testnet':
        reference['mode'] = 'testnet'
    if reference not in receipt['config_refs']:
        receipt['config_refs'].append(reference)
    ops.atomic(BASE / 'managed-install.json', receipt)


def install_files(config):
    admit_services(config)
    mkdir(Path('/usr/local/libexec'), 0o755)
    mkdir(LIB, 0o755)
    for src, dst in [('container-supervisor.py', 'supervisor.py'),
                     ('container-operations.py', 'operations.py'),
                     ('zunder-guard-container.service', 'zunder-guard-container.service')]:
        file_write(LIB / dst, (STAGE / src).read_bytes())
    file_write(UNIT_DIR / GUARDIAN, (STAGE / GUARDIAN).read_bytes())
    mkdir(ops.REGISTRY)
    run(SYSTEMCTL, 'daemon-reload')
    run(SYSTEMCTL, 'enable', GUARDIAN)
    run(SYSTEMCTL, 'restart', GUARDIAN)
    require(not ops.pending(), 'Prior transient setup cleanup is pending; rerun after guardian recovery.')


def volume_names():
    return ops.docker('volume', 'ls', '--format', '{{.Name}}').decode().splitlines()


def verify_volume(config, owner=None):
    values = json.loads(ops.docker('volume', 'inspect', config['volume']))
    require(len(values) == 1 and values[0].get('Name') == config['volume']
            and values[0].get('Driver') == 'local' and not values[0].get('Options'),
            'Only local named volumes without driver options are supported.')
    if owner:
        require((values[0].get('Labels') or {}).get('com.zunderlabs.guard-install-volume') == owner,
                'Volume already belonged to another installation; refusing adoption.')
    require(not ops.identifiers('volume=' + config['volume']), 'Another container uses this volume.')


def create_volume(config, record, unattended=False):
    require(config['volume'] not in volume_names(), 'Volume name already exists; explicit adoption required.')
    require(not unattended or sending_mode(config) == 'testnet', 'Only Testnet can create unattended.')
    if not unattended:
        confirm('Type CREATE ' + config['volume'] + ' to create this NEW persistent volume:', 'CREATE ' + config['volume'])
    ops.docker('volume', 'create', '--driver', 'local', '--label',
               'com.zunderlabs.guard-install-volume=' + record['transaction'], config['volume'])
    verify_volume(config, record['transaction'])
    phase(record, 'volume-created')


def licence_fee_free(key):
    """Decode expectations; runtime must validate signature/account/expiry."""
    if not key:
        return False
    require(type(key) is str and len(key) <= 4096 and key.startswith('zgl1_'), 'Configured licence encoding differs.')
    parts = key[5:].split('.')
    require(len(parts) == 2 and all(re.fullmatch('[A-Za-z0-9_-]+', part) for part in parts),
            'Configured licence encoding differs.')
    try:
        payload = base64.urlsafe_b64decode(parts[0] + '=' * ((4 - len(parts[0]) % 4) % 4))
        require(base64.urlsafe_b64encode(payload).rstrip(b'=').decode() == parts[0], 'Configured licence payload differs.')
        value = json.loads(payload)
        features = value.get('features')
        require(type(features) is list and all(type(item) is str and item == 'fee_free' for item in features),
                'Configured licence feature profile differs.')
    except (ValueError, UnicodeError, TypeError, AttributeError):
        raise ops.Refused('Configured licence payload is malformed.') from None
    return 'fee_free' in features


def readiness(config, expect_fee_free, configured_licence=None):
    expected_testnet_fee = None
    if sending_mode(config) == 'testnet':
        require(not expect_fee_free or configured_licence, 'Explicit Testnet licence expectation requires the configured signed key.')
        expected_testnet_fee = 'fee_free' if licence_fee_free(configured_licence) else 'off'
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection('127.0.0.1', 8547, timeout=2)
            connection.request('GET', '/healthz')
            response = connection.getresponse()
            require(response.status == 200, 'Guard is not healthy.')
            response.read()
            connection.close()
            connection = http.client.HTTPConnection('127.0.0.1', 8547, timeout=2)
            connection.request('GET', '/guard/status')
            response = connection.getresponse()
            require(response.status == 200, 'Guard status unavailable.')
            status = json.loads(response.read(1024 * 1024))
            connection.close()
            require(status.get('mode') == sending_mode(config) and status.get('network') == sending_mode(config)
                    and status.get('account', '').lower() == config['account'].lower(), 'Guard account/mode mismatch.')
            require(status.get('risk', {}).get('journal_ready') is True
                    and status.get('risk', {}).get('state') == 'active'
                    and 'killed' in status and status['killed'] is None,
                    'Guard risk state is not ready; no automatic resume is permitted.')
            fee = status.get('fee', {}).get('mode')
            if sending_mode(config) == 'testnet':
                require(fee == expected_testnet_fee, 'Testnet fee differs from the exact configured licence features.')
                require(status.get('licence', {}).get('state') == ('active' if configured_licence else 'none'),
                        'Testnet configured licence did not validate, or absent licence state differs.')
            else:
                require(fee == 'fee_free' if expect_fee_free else fee in ('fee_free', 'builder'), 'Unexpected licence/fee state.')
            if fee == 'builder':
                require(status['fee'].get('approval', {}).get('state') in
                        ('approved', 'unchecked', 'not_approved', 'refused',
                         'refused_by_venue', 'refused_by_venue_builder'),
                        'Builder approval state is unavailable or unsupported.')
            return status
        except (ops.Refused, OSError, ValueError, http.client.HTTPException):
            time.sleep(1)
    raise ops.Refused('Guard did not reach the expected healthy account/risk/licence state.')


def activate(config, record, fresh, expect_fee_free, unattended=False, configured_licence=None):
    require(not unattended or sending_mode(config) == 'testnet', 'Only Testnet can activate unattended.')
    verify_gate()
    answer = ('START ' + config['account']) if unattended else prompt('Type START ' + config['account'] + ' to activate this ' + sending_mode(config) + ' Guard; anything else leaves it stopped:')
    if answer != 'START ' + config['account']:
        print('Installed and stopped. Boot activation remains inhibited; rerun this installer to continue.')
        return
    if fresh and sending_mode(config) == 'mainnet':
        note = prompt('Who approved the first mainnet risk journal, and why?')
        require(3 <= len(note) <= 512 and '\x00' not in note, 'An attributable journal note is required.')
        ops.run(config, ['journal-init', '--mode', 'mainnet', '--note', note], readonly=False,
                public_env=['ZUNDER_MAINNET_CONFIRM=' + config['account']])
        phase(record, 'journal-initialized')
    require(not ops.pending(), 'Transient cleanup must finish before activation.')
    boot_enabled = record['original_enabled'] != 'disabled'
    print('Boot recovery will be ' + ('enabled.' if boot_enabled else 'disabled (preserving previous state).'))
    # This second choice also covers the enabled-state change on first installation.
    if not unattended:
        confirm('Type ACTIVATE to commit that start/boot choice:', 'ACTIVATE')
    run(SYSTEMCTL, 'enable' if boot_enabled else 'disable', UNIT)
    verify_gate()
    record['phase'] = 'ready-to-activate'
    record['boot_enabled'] = boot_enabled
    ops.atomic(BASE / 'last-install.json', record)
    GATE.unlink()
    ops.sync_directory(BASE)
    try:
        run(SYSTEMCTL, 'start', UNIT)
        status = readiness(config, expect_fee_free, configured_licence)
    except BaseException:
        ops.atomic(GATE, record)
        run(SYSTEMCTL, 'stop', UNIT)
        raise
    if status['fee']['mode'] == 'builder' and status['fee'].get('approval', {}).get('state') != 'approved':
        print('Guard is installed and running, but pay-per-order approval is still needed (' +
              status['fee'].get('approval', {}).get('state', 'unknown') + '). Entries remain blocked.')
        print('Open https://zunderlabs.com/approve, select Hyperliquid Mainnet, and connect the main wallet for ' +
              config['account'] + ' to review the builder approval. Do not use the API wallet.')
        print('Before connecting your bot, recheck http://127.0.0.1:8547/guard/status: '
              'fee.approval.state must be approved (or fee.mode must be fee_free with a valid licence).')
        return
    print('Guard ready on http://127.0.0.1:8547; account ' + config['account'] + '; fee mode ' + status['fee']['mode'] + '.')
    print('Use the pairing code from setup to connect your bot after reviewing Guard status.')


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    for flag in ('volume', 'account', 'rules', 'equity-cap', 'ip-share', 'licence'):
        parser.add_argument('--' + flag, default='')
    parser.add_argument('--network', choices=('mainnet', 'testnet'), default='mainnet')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--prepare-image', action='store_true')
    parser.add_argument('--prepared-image', action='store_true')
    parser.add_argument('--registry-auth-dir', default='')
    parser.add_argument('--source-commit', default='')
    parser.add_argument('--key-stdin', action='store_true')
    args = parser.parse_args()
    if not args.prepare_image:
        require(not args.registry_auth_dir, 'Registry auth is only admitted during image preparation.')
        require(args.prepared_image == bool(args.source_commit), 'Prepared image needs exact source; no ambiguous fallback.')
        validate_input(args, sys.stdin.isatty())
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root is required.')
    require(re.fullmatch('v[0-9]+\\.[0-9]+\\.[0-9]+', args.version), 'Invalid release version.')
    for tool in (SYSTEMCTL, '/usr/bin/docker', '/usr/bin/systemd-creds', '/usr/bin/python3', '/usr/local/bin/cosign'):
        ops.executable(tool)
    sup = load_module('container_supervisor', STAGE / 'container-supervisor.py')
    if args.prepare_image:
        prepare_image(args, sup)
        return
    mkdir(BASE)
    mkdir(BASE / 'docker-config')
    sup.preflight(installing=True)
    require(not list((BASE / 'docker-config').iterdir()), 'Docker config directory must be empty.')
    lock = os.open(BASE / 'installer.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Held through main; a second installer never performs concurrent mutations.
    existing = sup.load() if (BASE / 'config.json').exists() else None
    pending_record = ops.read(GATE) if GATE.exists() else None
    account = args.account or (existing or pending_record or {}).get('account') or prompt('Hyperliquid account (public 0x address):')
    volume = args.volume or (existing or pending_record or {}).get('volume') or (
        'zunder-guard-testnet-data' if args.network == 'testnet' else 'zunder-guard-data')
    image = (STAGE / ('zunder-guard-' + args.version + '.image.txt')).read_text()
    image = image[:-1] if image.endswith('\n') else image
    config = {'image': image, 'tag': args.version, 'volume': volume, 'account': account, 'instance': uuid.uuid4().hex}
    if args.network == 'testnet':
        config['mode'] = 'testnet'
    sup.validate(config)
    if existing:
        require(sending_mode(existing) == args.network, 'Existing supervisor belongs to another network.')
        require(existing['account'] == account and existing['volume'] == volume, 'Existing account/volume cannot change here.')
        require(not any((args.rules, args.equity_cap, args.ip_share, args.licence)),
                'Existing setup options cannot be replaced by reinstall; use the documented configuration/licence command.')
    if pending_record:
        require(sending_mode(pending_record) == args.network, 'Interrupted setup belongs to another network.')
        require(not any((args.rules, args.equity_cap, args.ip_share, args.licence)),
                'Interrupted setup preserves existing choices; rerun without setup options.')
    print('Verified release ' + args.version + '; ' + args.network + ' account ' + account + '; persistent volume ' + volume + '.')
    manifest = hashlib.sha256((STAGE / 'SHA256SUMS').read_bytes()).hexdigest()
    if args.prepared_image:
        sup.prepared_image(config, manifest, args.source_commit)
    else:
        sup.execute([sup.COSIGN, 'verify', image, '--certificate-identity',
                     'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/' + args.version,
                     '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'])
        sup.docker('pull', image)
    sup.image_ready(config)
    fresh = not existing and not pending_record and volume not in volume_names()
    if not fresh and not existing and not pending_record:
        require(not args.non_interactive, 'Unattended setup cannot adopt an existing unowned volume.')
        confirm('Type ADOPT ' + volume + ' only for a complete existing ' + args.network + ' home with no other restart owner:', 'ADOPT ' + volume)
    if existing and not args.non_interactive:
        confirm('Stop your bot. Type STOP to stop Guard and prepare the verified upgrade:', 'STOP')
    prepare_receipt(config)
    record = inhibit(config, fresh)
    run(SYSTEMCTL, 'stop', UNIT) if (UNIT_DIR / UNIT).exists() else None
    sup.inactive()
    # After inhibition and stop, the existing supervisor alone may clean its admitted container.
    if existing:
        sup.cleanup(existing)
    require(not ops.identifiers('name=^/zunder-guard-container$'), 'Foreign supervisor container exists.')
    install_files(config)
    phase(record, 'helpers-installed')
    if fresh:
        create_volume(config, record, args.non_interactive)
        command = ['init', '--network', args.network, '--account', account]
        command += (['--non-interactive', '--no-key', '--key-stdin', '--service-key-check']
                    if args.key_stdin else ['--interactive'])
        if args.network == 'testnet' and not args.key_stdin:
            # Hidden input is checked by Guard; only the service supervisor
            # persists the key through its protected encrypted credential path.
            command += ['--no-key', '--service-key-check']
            if not args.equity_cap:
                args.equity_cap = prompt('The most equity Guard sizes from, in TESTNET USDC (at most 2500):')
                require(bool(args.equity_cap), 'An explicit Testnet equity cap is required.')
        for name in ('rules', 'equity_cap', 'ip_share', 'licence'):
            value = getattr(args, name)
            if value:
                command += ['--' + name.replace('_', '-'), value]
        if args.key_stdin:
            key = sup.read_key_frame(sys.stdin.buffer)
            try:
                ops.run(config, command, data=key, readonly=False)
            finally:
                del key  # Lifetime reduction; Python cannot promise memory zeroization.
        else:
            ops.run(config, command, interactive=True, readonly=False)
        phase(record, 'initialized')
    else:
        verify_volume(config)
    # Use the installed module so its trusted operation helper is the release-installed one.
    sup = load_module('installed_supervisor', LIB / 'supervisor.py')
    sup.check_config(config, transient=True)
    public_config = tomllib.loads(ops.run(config, ['check-config'], read_config=True).decode())
    cap = public_config.get('policy', {}).get('max_trading_equity_usd')
    require(isinstance(cap, str) and 0 < Decimal(cap) <= 2500, 'Configured equity cap is missing or invalid.')
    print('Configured ' + args.network + ' equity cap: ' + cap + '. Initial pairing is emitted by init; reinstall preserves clients.')
    admit_services(config)
    repeated = account if args.non_interactive else prompt('Repeat the full account to authorize encrypted service provisioning:')
    require(repeated == account, 'Account confirmation differs.')
    # A separate process retains supervisor locking/preflight and its hidden terminal prompt.
    command = ['/usr/bin/python3', '-I', str(LIB / 'supervisor.py'), 'install',
               '--tag', args.version, '--image', image, '--volume', volume,
               '--account', account, '--confirm-account', repeated, '--network', args.network]
    if args.prepared_image:
        command += ['--prepared-image', '--manifest-sha256', manifest, '--source-commit', args.source_commit]
    if args.key_stdin:
        command.append('--key-stdin')
    result = subprocess.run(command, stdin=sys.stdin.buffer if args.key_stdin else None, env=ENV, check=False)
    require(result.returncode == 0, 'Encrypted supervisor installation failed; activation remains inhibited.')
    verify_gate()
    phase(record, 'installed-stopped')
    # An interrupted/adopted home is never inferred fresh. Its missing journal needs explicit recovery.
    activate(config, record, fresh, bool(args.licence), args.non_interactive, public_config.get('licence'))
    os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except ops.Refused as error:
        print('Container installation refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except (Exception, KeyboardInterrupt):
        # Do not replay exception strings/subprocess output containing terminal/key material.
        print('Container installation stopped. State is preserved; rerun the verified installer to continue.\n'
              'If setup began, mainnet boot activation remains inhibited until successful explicit activation.', file=sys.stderr)
        sys.exit(1)
