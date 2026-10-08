#!/usr/bin/python3
"""Destructive synthetic lifecycle checks, ONLY inside the marked disposable QEMU guest.

Never run this on a build box. The host wrapper creates the required root-only marker.
No venue client, real wallet, trading order, public cloud resource or signing credential.
"""
import argparse
import hashlib
import json
import math
import os
import re
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
PRODUCTION = HERE.parents[1] / 'container'
WORK = Path('/var/lib/zunder-container-native')
BASE = Path('/etc/zunder-container-native')
RUNTIME = Path('/run/zunder-container-native')
NAME = 'zunder-container-native'
UNIT = NAME + '.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT
VOLUME = NAME + '-data'
LABEL = 'com.zunderlabs.guard-supervisor'
INSTANCE = 'd' * 32
ACCOUNT = '0x' + 'b' * 40
KEY = b'ab' * 32 + b'\n'  # Public synthetic fixture, not a funded wallet/API key.
STATE = (json.dumps(dict(mode='mainnet', account=ACCOUNT, journal='immutable-fixture-journal',
                         licence='synthetic-fee-free-fixture', clients=['synthetic-client'])) + '\n').encode()
STATE_SHA = hashlib.sha256(STATE).hexdigest()
SAFE = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LANG='C.UTF-8')


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def call(argv, *, data=None, check=True, timeout=300):
    kw = {'input': data} if data is not None else {'stdin': subprocess.DEVNULL}
    result = subprocess.run(argv, **kw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=SAFE, check=False, timeout=timeout)
    if check:
        require(result.returncode == 0, 'Native fixture command failed: ' + argv[0])
    return result.stdout.decode().strip()


def docker(*args, **kwargs):
    return call(['/usr/bin/docker', '--config', str(BASE / 'docker-config'),
                 '--host', 'unix:///var/run/docker.sock', *args], **kwargs)


def ctl(*args, **kwargs):
    return call(['/usr/bin/systemctl', *args], **kwargs)


def guarded_guest(marker):
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd', 'Native systemd root guest required.')
    path = Path('/etc/zunder-native-disposable')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            'Disposable-guest marker ownership mismatch.')
    require(path.read_text().strip() == marker and len(marker) == 32, 'Not the designated disposable guest.')
    require(call(['/usr/bin/systemd-detect-virt', '--vm']) in ('qemu', 'kvm'), 'QEMU/KVM disposable guest required.')


def save(data):
    (WORK / 'evidence.json').write_text(json.dumps(data, indent=2) + '\n')


def failure_diagnostics():
    """Export bounded enums/frame coordinates only; never journal text or Docker config."""
    result = {'scope': 'synthetic disposable guest only'}
    fields = ('ActiveState', 'SubState', 'Result', 'ExecMainCode', 'ExecMainStatus', 'NRestarts')
    try:
        data = ctl('show', UNIT, *[arg for field in fields for arg in ('-p', field)],
                   check=False, timeout=10)
        enums = {'ActiveState': {'active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance', 'refreshing'},
                 'SubState': {'running', 'dead', 'failed', 'auto-restart', 'start-pre', 'start', 'start-post', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-sigterm', 'final-sigkill', 'exited'},
                 'Result': {'success', 'resources', 'timeout', 'exit-code', 'signal', 'core-dump', 'watchdog', 'start-limit-hit', 'protocol', 'oom-kill'}}
        result['unit'] = {name: value for name, separator, value in
                          (line.partition('=') for line in data.splitlines())
                          if separator and name in fields and
                          (value in enums.get(name, set()) or
                           (name in ('ExecMainCode', 'ExecMainStatus', 'NRestarts') and re.fullmatch(r'[0-9]{1,10}', value)))}
    except (OSError, subprocess.TimeoutExpired):
        result['unit_collection'] = 'unavailable'
    try:
        journal = call(['/usr/bin/journalctl', '-u', UNIT, '--no-pager', '-n', '80', '-o', 'cat'],
                       check=False, timeout=10)[-32768:]
        # These are fixed, nonsecret error messages and exception types from the helper,
        # fixture, systemd or Docker. Unknown log content is deliberately not exported.
        phrases = ('Root ownership and no shared writes required.', 'Supervisor directory must be mode 0700.',
                   'Unexpected file type.', 'Symlink refused for supervisor state or tool.',
                   'Required command failed; no new Guard was started.', 'Fixture immutable image ID mismatch.',
                   'Fixture must be nonroot.', 'fixture credential refused', 'fixture confirmation refused',
                   'fixture state refused', 'unexpected fixture command', 'Permission denied',
                   'Read-only file system', 'Failed to set up credentials', 'Failed at step CREDENTIALS',
                   'Address already in use', 'FileNotFoundError', 'PermissionError', 'BlockingIOError',
                   'Refused', 'TypeError', 'ValueError', 'KeyError', 'OSError')
        result['known_errors'] = [phrase for phrase in phrases if phrase in journal]
        result['python_frames'] = [dict(file=file, line=int(line), function=function)
            for file, line, function in re.findall(
                r'File "/var/lib/zunder-container-native/(supervisor\.py|driver\.py)", line ([0-9]{1,5}), in ([A-Za-z_][A-Za-z0-9_]{0,63})', journal)][:24]
        result['journal_raw_exported'] = False
    except (OSError, subprocess.TimeoutExpired):
        result['journal_collection'] = 'unavailable'
    return result


def ready(after=0, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen('http://127.0.0.1:8547/guard/status', timeout=2) as response:
                status = json.load(response)
            if status['sequence'] > after:
                require(status['state_sha256'] == STATE_SHA and status['account'] == ACCOUNT, 'Persistent state changed.')
                require(status['key_sha256'] == hashlib.sha256(KEY.strip()).hexdigest() and status['uid'] == 65532,
                        'Credential or container UID mismatch.')
                return status
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(1)
    raise RuntimeError('Guard fixture did not recover before deadline.')


def image():
    return json.loads((BASE / 'config.json').read_text())['image']


def inspect_id(identifier):
    return json.loads(docker('container', 'inspect', identifier))[0]


def audit():
    identifiers = docker('ps', '--no-trunc', '--filter', 'label=' + LABEL + '=' + INSTANCE,
                         '--format', '{{.ID}}').splitlines()
    require(len(identifiers) == 1, 'Exactly one running Guard fixture required.')
    obj = inspect_id(identifiers[0])
    require(obj['Config']['User'] == '65532:65532', 'Container is not nonroot.')
    require(obj['HostConfig']['RestartPolicy']['Name'] == 'no', 'Docker restart owner leaked into unit.')
    require(obj['HostConfig']['PortBindings']['8547/tcp'] == [{'HostIp': '127.0.0.1', 'HostPort': '8547'}], 'Port is not host loopback only.')
    require(any(x['Name'] == 'core' and x['Hard'] == 0 and x['Soft'] == 0 for x in obj['HostConfig']['Ulimits']), 'Container core dumps enabled.')
    require(ctl('show', UNIT, '-p', 'LimitCORE', '--value') == '0', 'Host core dumps enabled.')
    pid = int(ctl('show', UNIT, '-p', 'MainPID', '--value'))
    evidence = [json.dumps(obj).encode(), Path(f'/proc/{pid}/cmdline').read_bytes(),
                Path(f'/proc/{pid}/environ').read_bytes(), docker('logs', identifiers[0]).encode(),
                call(['/usr/bin/journalctl', '-u', UNIT, '--no-pager', '-o', 'cat']).encode()]
    for directory in (BASE, RUNTIME):
        evidence.extend(p.read_bytes() for p in directory.rglob('*') if p.is_file())
    require(all(KEY.strip() not in item for item in evidence), 'Synthetic credential appeared outside stdin/credential delivery.')
    return dict(container_id=identifiers[0], process_id=pid, leak_scan='passed',
                persistent_state_sha256=STATE_SHA)


def setup():
    require(not WORK.exists() and not BASE.exists() and not UNIT_FILE.exists(), 'Native fixture already exists; refusing overwrite.')
    WORK.mkdir(mode=0o700)
    BASE.mkdir(mode=0o700)
    (BASE / 'docker-config').mkdir(mode=0o700)
    require(not docker('ps', '--all', '--quiet'), 'Disposable guest must have no existing containers.')
    docker('build', '--tag', NAME + ':fixture', str(HERE), timeout=900)
    image_id = json.loads(docker('image', 'inspect', NAME + ':fixture'))[0]['Id']
    require(image_id.startswith('sha256:') and len(image_id) == 71, 'Immutable local fixture image ID required.')
    docker('volume', 'create', VOLUME)
    # Explicit fixture bootstrap, not a production Guard init or journal reset.
    docker('run', '--rm', '-i', '--user', '0', '--mount', 'type=volume,source=' + VOLUME + ',target=/data',
           '--entrypoint', 'python3', image_id, '-c',
           'import os,pathlib,sys; p=pathlib.Path("/data/state.json"); p.write_bytes(sys.stdin.buffer.read()); os.chown(p,65532,65532); os.chown("/data",65532,65532)', data=STATE)
    config = dict(image=image_id, tag='v0.0.0', volume=VOLUME, account=ACCOUNT, instance=INSTANCE)
    config_file = BASE / 'config.json'
    config_file.write_text(json.dumps(config) + '\n')
    config_file.chmod(0o600)
    # Real systemd encryption; never write KEY to a plaintext file or environment.
    ciphertext = subprocess.run(['/usr/bin/systemd-creds', 'encrypt', '--name=guard-api-wallet', '-', '-'],
                                input=KEY, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=SAFE, check=True).stdout
    require(KEY.strip() not in ciphertext, 'Credential encryption returned plaintext.')
    credential = BASE / 'credential.cred'
    credential.write_bytes(ciphertext)
    credential.chmod(0o600)
    shutil.copyfile(PRODUCTION / 'supervisor.py', WORK / 'supervisor.py')
    shutil.copyfile(HERE / 'driver.py', WORK / 'driver.py')
    production_unit = (PRODUCTION / 'zunder-guard-container.service').read_text()
    unit = production_unit.replace('/usr/local/libexec/zunder-guard-container/supervisor.py', str(WORK / 'driver.py'))
    unit = unit.replace('zunder-guard-container', NAME)
    UNIT_FILE.write_text(unit)
    (WORK / 'unit.saved').write_text(unit)
    ctl('daemon-reload')
    call(['/usr/bin/systemd-analyze', 'verify', str(UNIT_FILE)])
    ctl('enable', UNIT)
    require(ctl('is-active', UNIT, check=False) == 'inactive', 'Fixture installation started implicitly.')
    result = dict(scope='real Linux systemd/Docker lifecycle with synthetic process, no venue or signed-release claim',
                  boot_before=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  production_helper_sha256=hashlib.sha256((WORK / 'supervisor.py').read_bytes()).hexdigest(),
                  production_unit_sha256=hashlib.sha256(production_unit.encode()).hexdigest(),
                  fixture_image=image_id, checks=['installed enabled but stopped'], status='prepared')
    save(result)


def blocker(*, bad_volume=False, name=NAME, own_label=False):
    args = ['create', '--name', name, '--label', LABEL + '=' + (INSTANCE if own_label else 'foreign'),
            '--entrypoint', 'python3']
    if bad_volume:
        docker('volume', 'create', NAME + '-other')
        args += ['--mount', 'type=volume,source=' + NAME + '-other,target=/data']
    return docker(*args, image(), '-c', 'import time; time.sleep(600)')


def explicit_stop_stays_stopped(seconds=25):
    # More than two RestartSec intervals: Restart=always must respect an
    # administrator stop, without even one replacement process/container.
    ctl('stop', UNIT)
    require(ctl('is-active', UNIT, check=False) == 'inactive', 'Explicit stop did not finish inactive.')
    attempts = ctl('show', UNIT, '-p', 'NRestarts', '--value')
    starts = docker('run', '--rm', '--log-driver=none', '--read-only', '--network=none',
                    '--mount', 'type=volume,source=' + VOLUME + ',target=/data,readonly',
                    '--entrypoint', 'python3', image(), '-c',
                    'from pathlib import Path; print(len(Path("/data/starts.jsonl").read_text().splitlines()))')
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        require(ctl('is-active', UNIT, check=False) == 'inactive', 'Explicit stop restarted the service.')
        require(ctl('show', UNIT, '-p', 'NRestarts', '--value') == attempts, 'Explicit stop scheduled another restart.')
        require(not docker('ps', '--all', '--quiet', '--filter', 'label=' + LABEL + '=' + INSTANCE),
                'Explicit stop left or recreated an owned container.')
        time.sleep(1)
    after = docker('run', '--rm', '--log-driver=none', '--read-only', '--network=none',
                   '--mount', 'type=volume,source=' + VOLUME + ',target=/data,readonly',
                   '--entrypoint', 'python3', image(), '-c',
                   'from pathlib import Path; print(len(Path("/data/starts.jsonl").read_text().splitlines()))')
    require(after == starts, 'Explicit stop allowed another Guard fixture start.')


def exercise():
    record = json.loads((WORK / 'evidence.json').read_text())
    ctl('start', UNIT)
    status = ready()
    record['checks'].append('real encrypted credential and first start')
    identifier = audit()['container_id']
    # The fixture installs the same clean SIGTERM->exit0 behavior as Guard.
    # This previously bypassed Restart=on-failure.
    docker('kill', '--signal=TERM', identifier)
    status = ready(status['sequence'])
    record['checks'].append('clean SIGTERM exit recovered with persistent state and fresh credential')
    audit()
    explicit_stop_stays_stopped()
    record['checks'].append('explicit systemctl stop remained inactive without container or new starts for 25 seconds')
    ctl('start', UNIT)
    status = ready(status['sequence'])
    audit()
    try:
        urlopen('http://127.0.0.1:8547/crash', timeout=3).read()
    except OSError:
        pass
    status = ready(status['sequence'])
    record['checks'].append('Guard child crash recovered')
    pid = audit()['process_id']
    require(b'/usr/bin/docker' in Path(f'/proc/{pid}/cmdline').read_bytes(), 'MainPID is not the foreground Docker client.')
    os.kill(pid, signal.SIGKILL)
    status = ready(status['sequence'])
    record['checks'].append('Docker client-only SIGKILL recovered without parallel Guard')
    audit()
    # This is the VM daemon, never the CI runner or a shared build-box daemon.
    ctl('restart', 'docker.service')
    status = ready(status['sequence'])
    record['checks'].append('actual guest Docker daemon restart recovered with clean-exit SIGTERM fixture')
    audit()
    for condition in ('missing', 'stale-to-foreign-id'):
        ctl('stop', UNIT)
        cid = RUNTIME / 'container.id'
        if condition == 'missing':
            cid.unlink(missing_ok=True)
            foreign = None
        else:
            foreign = blocker(name=NAME + '-foreign')
            cid.write_text(foreign)
            cid.chmod(0o600)
        ctl('start', UNIT)
        status = ready(status['sequence'])
        if foreign:
            require(inspect_id(foreign)['Id'] == foreign, 'Stale cidfile caused foreign deletion.')
            docker('rm', foreign)
        record['checks'].append(condition + ' cidfile recovery')
    for condition in ('foreign-name-retry-budget', 'wrong-volume'):
        ctl('stop', UNIT)
        foreign = blocker(bad_volume=condition == 'wrong-volume', own_label=condition == 'wrong-volume')
        started = time.monotonic()
        ctl('start', UNIT, check=False)
        initial = int(ctl('show', UNIT, '-p', 'NRestarts', '--value'))
        minimum = 75 if condition == 'foreign-name-retry-budget' else 15
        while time.monotonic() - started < minimum:
            require(inspect_id(foreign)['Id'] == foreign, 'Supervisor deleted a foreign container.')
            time.sleep(2)
        attempts = int(ctl('show', UNIT, '-p', 'NRestarts', '--value')) - initial
        if condition == 'foreign-name-retry-budget':
            # RestartSec bounds the pause, not the Docker/Python startup time.
            # Slow disposable guests must still demonstrate four real retries.
            while attempts < 4 and time.monotonic() - started < 180:
                require(inspect_id(foreign)['Id'] == foreign, 'Supervisor deleted a foreign container.')
                time.sleep(2)
                attempts = int(ctl('show', UNIT, '-p', 'NRestarts', '--value')) - initial
            require(time.monotonic() - started <= 180, 'Service retry observation exceeded its 180-second deadline.')
            require(attempts >= 4, 'Four service retries were not observed before the 180-second deadline.')
            require(attempts <= math.ceil((time.monotonic() - started) / 10) + 2, 'Restart loop is not rate bounded.')
        docker('rm', foreign)
        status = ready(status['sequence'])  # No restart/reset-failed command: autonomous recovery.
        record['checks'].append(condition + ': refused deletion, recovered when cleared')
        audit()
    ctl('stop', UNIT)
    baseline = {name: hashlib.sha256((BASE / name).read_bytes()).hexdigest() for name in ('config.json', 'credential.cred')}
    ctl('disable', UNIT)
    UNIT_FILE.unlink()
    ctl('daemon-reload')
    UNIT_FILE.write_bytes((WORK / 'unit.saved').read_bytes())
    ctl('daemon-reload')
    ctl('enable', UNIT)
    ctl('start', UNIT)
    status = ready(status['sequence'])
    require(all(hashlib.sha256((BASE / name).read_bytes()).hexdigest() == digest for name, digest in baseline.items()),
            'Reinstall changed persistent configuration or credential.')
    record['checks'].append('service uninstall/reinstall preserved state; not a version upgrade claim')
    record['before_reboot_sequence'] = status['sequence']
    record['last_audit'] = audit()
    record['status'] = 'awaiting-actual-guest-reboot'
    save(record)


def after_reboot():
    record = json.loads((WORK / 'evidence.json').read_text())
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(boot != record['boot_before'], 'A real kernel reboot has not occurred.')
    require(record['status'] == 'awaiting-actual-guest-reboot', 'Pre-reboot phase did not complete.')
    ready(record['before_reboot_sequence'], timeout=300)
    record['last_audit'] = audit()
    record['boot_after'] = boot
    record['checks'].append('actual QEMU guest kernel reboot recovered enabled service and encrypted credential')
    record['status'] = 'passed-native-synthetic-lifecycle'
    save(record)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['setup', 'exercise', 'after-reboot'])
    parser.add_argument('--marker', required=True)
    args = parser.parse_args()
    guarded_guest(args.marker)
    try:
        {'setup': setup, 'exercise': exercise, 'after-reboot': after_reboot}[args.phase]()
    except Exception:
        # Retain the failing verdict and collect only after the disposable-guest guard.
        try:
            record = json.loads((WORK / 'evidence.json').read_text()) if (WORK / 'evidence.json').exists() else {'status': 'setup-incomplete'}
            record['failed_phase'] = args.phase
            record['failure_diagnostics'] = failure_diagnostics()
            save(record)
        except Exception:
            pass  # Diagnostic collection must not replace the original failing verdict.
        raise
