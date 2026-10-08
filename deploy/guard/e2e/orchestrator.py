#!/usr/bin/env python3
"""Portable release testnet orchestration; no publication or mainnet path."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent
REPO = 'zunderlabs/zunder-guard'
ACCOUNT = '0x0f50112710913b51a5d037795e5f4efc08debf2a'
INSTANCE = 'i-0ca66c349ad743928'
DOC = 'ZunderReleaseTestnetControl'
REGION = 'eu-central-1'
AWS_ACCOUNT = '436632189317'
KEY_PATH = '/zunder/testnet/api-wallet-key'


def need(ok, message):
    if not ok: raise RuntimeError(message)


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def json_write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    path.chmod(0o600)


def utc(value=None):
    value = datetime.now(timezone.utc) if value is None else value
    need(value.tzinfo is not None, 'Timezone-aware timestamp required.')
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def make_stop(binding):
    return dict(schema=1, kind='actual-testnet-runner-stop', network='testnet', **binding,
                account_sha256=hashlib.sha256(ACCOUNT.encode()).hexdigest(), runner_stopped_confirmed=True,
                exclusive_account_confirmed=True, service='zunder-exec-testnet', instance_id=INSTANCE,
                observed_at=utc())


def make_pause(binding, stop_path, flat_path):
    now = datetime.now(timezone.utc)
    return dict(tag=binding['tag'], source=binding['source'], account_sha256=hashlib.sha256(ACCOUNT.encode()).hexdigest(),
                runner_stopped_confirmed=True, exclusive_account_confirmed=True, testnet_orders_approved=True,
                max_notional_usdc='40', observed_at=utc(now),
                expires_at=utc(datetime.fromtimestamp(now.timestamp()+1800, timezone.utc)),
                complete_flat_receipt_sha256=sha(flat_path), runner_stop_receipt_sha256=sha(stop_path))


def tag(value):
    need(isinstance(value, str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', value), 'Invalid release tag.')
    return value


def admitted(event_name, event, *, repository, ref, workflow_ref, policy_sha):
    need(repository == REPO and ref == 'refs/heads/main', 'Only the canonical main workflow is trusted.')
    need(re.fullmatch('[0-9a-f]{40}', policy_sha), 'Immutable automation commit required.')
    need(workflow_ref == REPO + '/.github/workflows/release-e2e.yml@refs/heads/main', 'Unexpected caller workflow.')
    if event_name == 'workflow_dispatch':
        return tag(event.get('inputs', {}).get('tag'))
    need(event_name == 'workflow_run', 'PR, fork and other events are forbidden.')
    run = event.get('workflow_run', {})
    need(run.get('event') == 'push' and run.get('status') == 'completed' and run.get('conclusion') == 'success'
         and run.get('path') == '.github/workflows/release.yml'
         and run.get('repository', {}).get('full_name') == REPO
         and run.get('head_repository', {}).get('full_name') == REPO
         and re.fullmatch('[0-9a-f]{40}', run.get('head_sha', ''))
         and type(run.get('id')) is int and run['id'] > 0,
         'Untrusted upstream release run.')
    return tag(run.get('head_branch'))


def env(*, aws=False, github=False):
    tools = str(Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'zunder-tools')
    result = dict(PATH=tools + ':/usr/local/bin:/usr/bin:/bin', HOME=str(Path.home()), LANG='C.UTF-8',
                  AWS_PAGER='', AWS_CLI_AUTO_PROMPT='off', AWS_EC2_METADATA_DISABLED='true')
    if aws:
        for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'):
            need(bool(os.environ.get(name)), 'Short-lived OIDC credentials required.')
            result[name] = os.environ[name]
        result['AWS_CONFIG_FILE'] = os.environ['AWS_CONFIG_FILE']
    if github:
        result.update(GITHUB_REPOSITORY=REPO, GH_TOKEN=os.environ['GH_TOKEN'])
        result['DOCKER_CONFIG'] = os.environ['DOCKER_CONFIG']
    return result


def capture(argv, *, aws=False, data=b'', limit=65536, timeout=45):
    child = subprocess.Popen(argv, env=env(aws=aws), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    result = bytearray()
    try:
        need(len(data) <= 1024, 'Bounded input required.')
        child.stdin.write(data); child.stdin.close()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout, selectors.EVENT_READ)
            while poll.get_map():
                need(time.monotonic() < deadline, 'Read-only command timeout.')
                for item, _ in poll.select(0.1):
                    chunk = os.read(item.fd, min(4096, limit + 1 - len(result)))
                    if chunk:
                        result.extend(chunk); need(len(result) <= limit, 'Read-only output bound exceeded.')
                    else: poll.unregister(item.fileobj)
        need(child.wait(timeout=max(0.01, deadline-time.monotonic())) == 0, 'Read-only command failed.')
        return bytes(result)
    finally:
        if child.poll() is None: child.kill(); child.wait(timeout=5)
        child.stdout.close()
        if not child.stdin.closed: child.stdin.close()
        result[:] = b'\0' * len(result)


def aws(*argv, timeout=45):
    return json.loads(capture(['/usr/local/bin/aws', '--region', REGION, '--no-cli-pager',
                              *argv, '--output', 'json'], aws=True, timeout=timeout))


def gh(path):
    child = subprocess.run(['/usr/bin/gh', 'api', path], env=env(github=True),
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45)
    need(child.returncode == 0 and len(child.stdout) <= 2 * 1024 * 1024, 'GitHub admission query failed.')
    return json.loads(child.stdout)


def control(operation, lease, cleanup='0' * 64):
    need(operation in ('stop', 'status', 'restore') and re.fullmatch('[0-9]{1,20}-[0-9]{1,4}', lease)
         and re.fullmatch('[0-9a-f]{64}', cleanup), 'Invalid fixed control request.')
    value = aws('ssm', 'send-command', '--document-name', DOC, '--document-version', '1',
                '--document-hash-type', 'Sha256', '--document-hash', policy()['ssm_document_sha256'],
                '--instance-ids', INSTANCE, '--parameters', json.dumps(dict(operation=[operation], lease=[lease],
                                                                         cleanup=[cleanup])),
                '--timeout-seconds', '1000')
    command = value['Command']['CommandId']
    need(re.fullmatch('[0-9a-f-]{36}', command), 'Unexpected SSM command identifier.')
    deadline = time.monotonic() + 1000
    first_lookup = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            value = aws('ssm', 'get-command-invocation', '--command-id', command, '--instance-id', INSTANCE)
        except RuntimeError:
            if time.monotonic() - first_lookup <= 20: continue  # SSM is eventually consistent.
            raise
        if value['Status'] in ('Pending', 'InProgress', 'Delayed'): continue
        need(value['Status'] == 'Success' and value['ResponseCode'] == 0, 'Fixed host control failed; inspect actual runner state.')
        result = json.loads(value['StandardOutputContent'])
        need(result.get('lease') == lease and result.get('service') == 'zunder-exec-testnet'
             and result.get('operation') == operation, 'Host control receipt differs.')
        return result
    raise RuntimeError('Host control deadline; inspect actual runner state before claiming a pause.')


def policy():
    value = json.loads((ROOT / 'policy.json').read_text())
    need(value.get('automation_commit_source') == 'authenticated-reusable-workflow-claim', 'Unexpected policy binding mode.')
    need(value.get('aws_credential_trust_scope') == 'canonical-repository-and-environment', 'Unexpected testnet credential trust scope.')
    value['automation_commit'] = os.environ.get('CONTROL_POLICY_COMMIT', '')
    need(re.fullmatch('[0-9a-f]{40}', value['automation_commit'])
         and re.fullmatch('0x[0-9a-f]{40}', value['approved_public_api_wallet'])
         and value['approved_public_api_wallet'] != '0x' + '0' * 40
         and re.fullmatch('[0-9a-f]{64}', value['ssm_document_sha256']), 'Unrendered automation policy.')
    for name, expected in value['files'].items():
        need(re.fullmatch('[A-Za-z0-9_.-]+', name) and sha(ROOT / name) == expected, 'Reviewed control file changed.')
    return value


def private_root():
    expected = '/tmp/zunder-release-e2e-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    need(re.fullmatch(r'/tmp/zunder-release-e2e-[0-9]{1,20}-[0-9]{1,4}', expected)
         and os.environ.get('E2E_PRIVATE_ROOT') == expected, 'Fixed fresh private root required.')
    return Path(expected)


def verify():
    p = policy()
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    release_tag = admitted(os.environ['GITHUB_EVENT_NAME'], event, repository=os.environ['GITHUB_REPOSITORY'],
                           ref=os.environ['GITHUB_REF'], workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],
                           policy_sha=p['automation_commit'])
    source = gh('repos/' + REPO + '/commits/' + release_tag)['sha']
    need(re.fullmatch('[0-9a-f]{40}', source), 'Unexpected source.')
    comparison = gh('repos/' + REPO + '/compare/' + source + '...main')
    need(comparison.get('status') in ('ahead', 'identical'), 'Release source is not an ancestor of protected main.')
    if os.environ['GITHUB_EVENT_NAME'] == 'workflow_run':
        need(source == event['workflow_run']['head_sha'], 'Upstream release source differs from tag.')
        release_run=gh('repos/'+REPO+'/actions/runs/'+str(event['workflow_run']['id']))
    else:
        runs=gh('repos/'+REPO+'/actions/workflows/release.yml/runs?head_sha='+source+'&event=push&status=success&per_page=100')
        candidates=[run for run in runs['workflow_runs'] if run.get('head_sha')==source
                    and run.get('head_branch')==release_tag and run.get('path')=='.github/workflows/release.yml'
                    and run.get('status')=='completed' and run.get('conclusion')=='success']
        need(bool(candidates),'Successful exact release run required for Actions transport.')
        release_run=gh('repos/'+REPO+'/actions/runs/'+str(max(candidates,key=lambda run:run['id'])['id']))
    root = private_root()
    need(not root.exists(), 'Fresh runner evidence directory required.')
    root.mkdir(mode=0o700)
    assets = root / 'assets'
    spec=importlib.util.spec_from_file_location('actions_artifacts',ROOT/'actions-artifacts.py')
    transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)
    transport_receipt=root/'actions-transport.json';staged=root/'actions-staged'
    transport.stage(release_tag,source,release_run['id'],release_run['run_attempt'],staged,transport_receipt)
    result = subprocess.run(['/bin/bash', str(ROOT / 'verify-release-assets.sh'), release_tag, str(assets),str(staged)],
                            env=env(github=True), stdin=subprocess.DEVNULL, timeout=900)
    need(result.returncode == 0, 'Actual signed release verification failed.')
    for file in assets.iterdir(): file.chmod(0o600)
    assets.chmod(0o700)
    marker = json.loads((assets / '.verified-release-source.json').read_text())
    need(marker == dict(tag=release_tag, source=source), 'Actual verified source differs.')
    archive = assets / ('zunder-guard-' + release_tag + '-linux-amd64.tar.gz')
    binary = root / 'zunder-guard'
    with tarfile.open(archive, 'r:gz') as bundle:
        member = bundle.getmember('zunder-guard')
        need(member.isfile() and 0 < member.size <= 256 * 1024 * 1024, 'Invalid signed binary member.')
        with bundle.extractfile(member) as stream, binary.open('xb') as target:
            while chunk := stream.read(65536): target.write(chunk)
    binary.chmod(0o500)
    json_write(root / 'binding.json', dict(tag=release_tag, source=source, manifest_sha256=sha(assets / 'SHA256SUMS'),
                                         policy_commit=p['automation_commit'], binary_sha256=sha(binary),
                                         release_run_id=release_run['id'],release_run_attempt=release_run['run_attempt'],
                                         artifact_transport_receipt_sha256=sha(transport_receipt)))


def execute():
    p = policy()
    root = private_root()
    binding = json.loads((root / 'binding.json').read_text())
    need(aws('sts', 'get-caller-identity')['Account'] == AWS_ACCOUNT, 'Wrong OIDC AWS account.')
    # CI uses an empty fixed AWS config supplied by the workflow; no response history.
    need(os.environ.get('AWS_CONFIG_FILE') == str(root / 'aws-config'), 'Isolated empty AWS configuration required.')
    need((root / 'aws-config').read_text() == '[default]\ncli_history = disabled\n', 'AWS history is not disabled.')
    lease = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    stopped = control('stop', lease)
    need(stopped.get('inactive') is True and stopped.get('exclusive') is True, 'Actual stopped-runner readback required.')
    stop_receipt = make_stop(binding)
    stop_path = root / 'stop.json'; json_write(stop_path, stop_receipt)
    flat_path = root / 'flat.json'
    base = [sys.executable, '-B']
    fields = ['--tag', binding['tag'], '--source', binding['source'], '--manifest-sha256', binding['manifest_sha256'],
              '--account', ACCOUNT]
    result = subprocess.run(base + [str(ROOT / 'scan.py'), '--runner-stop', str(stop_path), '--receipt', str(flat_path)] + fields,
                            env=env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=780)
    need(result.returncode == 0, 'Complete preflight scan failed; retain runner pause.')
    pause = make_pause(binding, stop_path, flat_path)
    pause_path = root / 'pause.json'; json_write(pause_path, pause)
    value = aws('ssm', 'get-parameter', '--name', KEY_PATH, '--with-decryption')['Parameter']
    need(value.get('Name') == KEY_PATH and value.get('Type') == 'SecureString'
         and re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', value.get('Value', '')), 'Invalid fixed testnet secret.')
    secret = bytearray(value['Value'].encode()); del value
    command = base + [str(ROOT / 'journey.py'), '--assets', str(root / 'assets'), '--binary', str(root / 'zunder-guard'),
                      '--pause', str(pause_path), '--work', str(root / 'journey'), '--preflight-flat', str(flat_path),
                      '--api-wallet', p['approved_public_api_wallet']] + fields
    child = subprocess.Popen(command, env=env(), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    try:
        child.stdin.write(secret + b'\n'); child.stdin.close()
        secret[:] = b'\0' * len(secret)
        code = child.wait(timeout=1890)
    except (Exception, KeyboardInterrupt):
        child.terminate()
        try: child.wait(timeout=90)
        except subprocess.TimeoutExpired: pass
        raise RuntimeError('Journey interrupted; retain protection and runner pause.') from None
    finally:
        secret[:] = b'\0' * len(secret)
        if not child.stdin.closed: child.stdin.close()
    actual_path = root / 'journey' / 'receipt.json'
    actual = json.loads(actual_path.read_text())
    need(code == 0 and actual.get('journey_passed') is True and actual.get('cleanup_complete') is True
         and actual.get('account_flat_after') is True and actual.get('source') == binding['source'],
         'Journey cleanup incomplete; runner remains paused.')
    # The host independently scans every DEX before restoring, under the same exclusive lease.
    restored = control('restore', lease, sha(actual_path))
    need(restored.get('active') is True and restored.get('all_dex_flat') is True, 'Runner restore readback failed.')
    report = dict(schema=1, kind='machine-signed-testnet-journey', **binding,
                  aws_credential_trust_scope=p['aws_credential_trust_scope'],run_id=os.environ['GITHUB_RUN_ID'],
                  run_attempt=os.environ['GITHUB_RUN_ATTEMPT'], account_sha256=hashlib.sha256(ACCOUNT.encode()).hexdigest(),
                  journey_receipt_sha256=sha(actual_path), runner_restored=True, journey_passed=True,
                  mainnet_actions=False, release_ready=False,
                  coverage=['signed-release-verification', 'testnet-signed-guard-mcp-entry-stop-owned-cleanup',
                            'complete-perp-dex-flat', 'existing-runner-pause-restore'])
    output = root / 'public'; output.mkdir(mode=0o700)
    json_write(output / 'testnet-evidence.json', report)


if __name__ == '__main__':
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('phase', choices=('verify', 'execute'))
    args = parser.parse_args()
    def interrupted(*unused): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        verify() if args.phase == 'verify' else execute()
    except (Exception, KeyboardInterrupt):
        print('Release testnet orchestration incomplete; inspect actual runner state and owned exposure before claiming a retained pause.', file=sys.stderr)
        sys.exit(1)
