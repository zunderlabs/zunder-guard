#!/usr/bin/env python3
"""Publication gate for identified maintainer-attested native observations.

GitHub authenticates the uploader; release signatures authenticate the software.
Neither this validator nor an uploaded log cryptographically proves an observation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

REPOSITORY = 'zunderlabs/zunder-guard'
REPORT = 'native-readiness.json'
MAX_REPORT = 262144
MAX_LOG = 1048576
MAX_LOG_TOTAL = 8388608
MAX_LOGS = 32
MAX_API = 2097152
MAX_PAGES = 5
TIMEOUT = 30
COMMON = {'signed_install', 'credential_confinement', 'account_network_risk', 'pairing',
          'fee_licence', 'explicit_stop', 'restart', 'crash_recovery', 'state_preservation',
          'host_reboot', 'signed_reinstall', 'interrupted_replacement_rollback', 'prior_version_upgrade'}
# Source policy, never a subset selected by the report.
ROUTES = {
    'linux-amd64-systemd': ('linux-amd64', set()),
    'linux-arm64-systemd': ('linux-arm64', set()),
    'darwin-amd64-keychain': ('darwin-amd64', set()),
    'darwin-arm64-keychain': ('darwin-arm64', set()),
    'windows-amd64-scm': ('windows-amd64', {'pre_login_readiness'}),
    'linux-amd64-container': ('linux-amd64', {'daemon_restart', 'single_instance', 'interrupted_setup_boot_inhibition'}),
    'linux-arm64-container': ('linux-arm64', {'daemon_restart', 'single_instance', 'interrupted_setup_boot_inhibition'}),
}


HOMEBREW_CHECKS = {'signed_formula_install', 'installed_binary_and_notices', 'configuration_paths',
                   'init_pairing', 'licence_activation', 'service_start_stop_restart',
                   'signed_reinstall_state_preservation', 'uninstall_preserves_state', 'prior_version_upgrade'}
AWS_CHECKS = {'signed_template_stack', 'pinned_loader_bootstrap', 'creation_signal_health',
              'ssm_access', 'pairing', 'safe_defaults', 'lifecycle_state_preservation', 'cleanup_retained_state'}
CHANNELS = {
    'native': (REPORT, 'operator-attested-native-rehearsal', ROUTES, COMMON),
    'homebrew': ('homebrew-readiness.json', 'operator-attested-homebrew-channel',
                 {platform + '-homebrew': (platform, set()) for platform in
                  ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64')}, HOMEBREW_CHECKS),
    'aws': ('aws-readiness.json', 'operator-attested-aws-channel',
            {'aws-ap-northeast-1-arm64': ('linux-arm64', set())}, AWS_CHECKS),
}


class Refused(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(obj, keys, label):
    require(type(obj) is dict and set(obj) == set(keys), 'Unexpected fields: ' + label)


def number(value):
    require(type(value) is int and value > 0, 'Expected positive integer, not bool.')
    return value


def text(value, maximum=512):
    require(type(value) is str and 0 < len(value) <= maximum and '\x00' not in value,
            'Expected bounded nonempty text.')
    return value


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'Invalid SHA256.')
    return value


def timestamp(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value), 'Expected UTC timestamp.')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise Refused('Invalid timestamp.') from error


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key.')
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(Refused('Nonfinite JSON.')))
        def walk(value, depth=0):
            require(depth <= 12, 'JSON depth exceeded.')
            if type(value) is dict:
                require(len(value) <= 512, 'Too many object members.')
                for key, child in value.items():
                    text(key, 256)
                    walk(child, depth + 1)
            elif type(value) is list:
                require(len(value) <= 512, 'Too many array members.')
                for child in value:
                    walk(child, depth + 1)
            elif type(value) is str:
                require(len(value) <= 65536, 'JSON string too large.')
        walk(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused('Malformed JSON.') from error


def command(argv, limit=MAX_API, timeout=TIMEOUT):
    """Bound stdout during collection, rather than capturing unbounded API output."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=dict(os.environ, GH_HOST='github.com'))
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'GitHub command timed out.')
                if not poll.select(min(remaining, 0.25)):
                    continue
                chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                require(len(output) <= limit, 'GitHub response exceeds byte limit.')
        require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                'GitHub command failed; no permission or evidence fallback.')
        return bytes(output)
    except subprocess.TimeoutExpired as error:
        raise Refused('GitHub command timed out.') from error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


class GitHub:
    def api(self, path, *, binary=False, limit=MAX_API):
        require(path == 'user' or path.startswith('repos/' + REPOSITORY + '/'), 'Untrusted API path.')
        data = command(['gh', 'api', '--hostname', 'github.com', '-H',
                        'Accept: application/octet-stream' if binary else 'Accept: application/vnd.github+json',
                        '-H', 'X-GitHub-Api-Version: 2022-11-28', path], limit)
        return data if binary else strict_json(data)

    def pages(self, path):
        result = []
        for page in range(1, MAX_PAGES + 1):
            values = self.api(path + f'?per_page=100&page={page}')
            require(type(values) is list and len(values) <= 100, 'Malformed paginated API response.')
            result.extend(values)
            if len(values) < 100:
                return result
        raise Refused('API pagination bound exceeded; refusing incomplete inventory.')


def role(api, user):
    require(type(user) is dict and user.get('type') == 'User', 'An identified human uploader is required.')
    identifier = number(user.get('id'))
    login = text(user.get('login'), 100)
    require(re.fullmatch('[A-Za-z0-9-]+', login), 'Invalid GitHub login.')
    response = api.api(f'repos/{REPOSITORY}/collaborators/{login}/permission')
    current = response.get('user', {})
    require(current.get('type') == 'User' and type(current.get('id')) is int
            and current['id'] == identifier and current.get('login') == login, 'GitHub identity mismatch.')
    require((response.get('role_name'), response.get('permission')) in
            {('admin', 'admin'), ('maintain', 'write')}, 'Current admin or maintain role required.')
    return {'id': identifier, 'login': login, 'role': response['role_name']}


def metadata(asset):
    require(type(asset) is dict and asset.get('state') == 'uploaded', 'Incomplete release asset.')
    name = text(asset.get('name'), 160)
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*', name) and '..' not in name, 'Unsafe release asset name.')
    result = {key: asset.get(key) for key in ('id', 'name', 'size', 'digest', 'created_at', 'updated_at', 'uploader')}
    number(result['id']); number(result['size'])
    timestamp(result['created_at']); timestamp(result['updated_at'])
    require(result['digest'] is None or (type(result['digest']) is str and
            re.fullmatch('sha256:[0-9a-f]{64}', result['digest'])), 'Unknown asset digest format.')
    return result


def download(api, asset, maximum):
    meta = metadata(asset)
    require(meta['size'] <= maximum, 'Evidence asset exceeds byte limit.')
    data = api.api(f'repos/{REPOSITORY}/releases/assets/{meta["id"]}', binary=True, limit=maximum)
    require(len(data) == meta['size'], 'Evidence asset size changed.')
    require(meta['digest'] is None or meta['digest'] == 'sha256:' + sha(data), 'API asset digest mismatch.')
    return data


def manifest(directory):
    raw = (directory / 'SHA256SUMS').read_bytes()
    require(len(raw) <= MAX_REPORT, 'Manifest too large.')
    result = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        require(match is not None and '..' not in match[2], 'Invalid manifest entry.')
        hashed, name = match.groups()
        require(name not in result and len(result) < 256, 'Duplicate/oversized manifest.')
        path = directory / name
        require(path.is_file() and not path.is_symlink(), 'Missing verified asset.')
        h = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1048576), b''):
                h.update(block)
        require(h.hexdigest() == hashed, 'Verified local asset changed.')
        result[name] = hashed
    return sha(raw), result


def required_inventory(tag, hashes, channel='native'):
    required = {'i', 'i.ps1', 'install.sh', 'install-windows-service.ps1', 'install-macos-service.sh',
                'install-container.py', 'container-supervisor.py', 'container-operations.py',
                'zunder-guard-container.service', 'zunder-guard-setup-guardian.service',
                f'zunder-guard-{tag}.image.txt'}
    for platform, _ in ROUTES.values():
        required.add(f'zunder-guard-{tag}-{platform}.' + ('zip' if platform.startswith('windows') else 'tar.gz'))
    if channel == 'homebrew': required.add('zunder-guard.rb')
    if channel == 'aws': required.add('cloudformation.yaml')
    require(required <= hashes.keys(), 'Published platform inventory is incomplete.')


def previous_release(api, tag, release_id):
    version = tuple(map(int, tag[1:].split('.')))
    for item in api.pages(f'repos/{REPOSITORY}/releases'):
        require(type(item) is dict and type(item.get('draft')) is bool and type(item.get('prerelease')) is bool,
                'Malformed release history.')
        if item.get('id') == release_id or item['draft'] or item['prerelease']:
            continue
        name = item.get('tag_name')
        require(type(name) is str and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', name), 'Unknown stable release history.')
        if tuple(map(int, name[1:].split('.'))) < version:
            return True
    return False


def verify(api, tag, directory, channel='native'):
    require(channel in CHANNELS, 'Unknown publication channel.')
    report_name, kind, routes, common = CHANNELS[channel]
    require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag) is not None, 'Invalid release tag.')
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'Unexpected publication repository.')
    source = strict_json((directory / '.verified-release-source.json').read_bytes())
    exact(source, ('tag', 'source'), 'verified source')
    require(source['tag'] == tag and type(source['source']) is str and
            re.fullmatch('[0-9a-f]{40}', source['source']), 'Invalid authenticated source binding.')
    manifest_sha, hashes = manifest(directory)
    required_inventory(tag, hashes, channel)
    image = (directory / f'zunder-guard-{tag}.image.txt').read_text().strip()
    require(re.fullmatch('ghcr.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}', image), 'Invalid image reference.')
    repo = api.api(f'repos/{REPOSITORY}/')
    require(repo.get('full_name') == REPOSITORY, 'Repository identity mismatch.')
    repo_id = number(repo.get('id'))
    require(api.api(f'repos/{REPOSITORY}/commits/{tag}').get('sha') == source['source'], 'Tag source changed.')
    release = api.api(f'repos/{REPOSITORY}/releases/tags/{tag}')
    release_id = number(release.get('id'))
    require(release.get('tag_name') == tag and type(release.get('draft')) is bool and
            release.get('prerelease') is False, 'Not the exact stable draft/release.')
    if channel != 'native':
        require(release['draft'] is False, 'Channel proof requires public immutable release URLs; draft rehearsal is insufficient.')
        timestamp(release.get('published_at'))
    assets = api.pages(f'repos/{REPOSITORY}/releases/{release_id}/assets')
    by_name = {}
    for asset in assets:
        meta = metadata(asset)
        require(meta['name'] not in by_name, 'Duplicate release asset name.')
        by_name[meta['name']] = asset
    require(set(hashes) | {'SHA256SUMS', report_name} <= by_name.keys(), 'Missing release assets or native attestation.')
    # Manifest bytes were signature-verified by the asset gate. API bytes must still match.
    require(sha(download(api, by_name['SHA256SUMS'], MAX_REPORT)) == manifest_sha, 'Published manifest changed.')
    for name, hashed in hashes.items():
        asset = by_name[name]
        require(asset['size'] == (directory / name).stat().st_size, 'Signed asset size changed.')
        require(asset.get('digest') == 'sha256:' + hashed, 'Signed asset digest missing or changed.')
    report_asset = by_name[report_name]
    operator = role(api, report_asset.get('uploader'))
    report_bytes = download(api, report_asset, MAX_REPORT)
    report = strict_json(report_bytes)
    exact(report, ('schema', 'kind', 'operator', 'repository', 'release_id', 'tag', 'source',
                   'manifest_sha256', 'image', 'artifacts', 'logs', 'platforms'), 'native readiness')
    require(type(report['schema']) is int and report['schema'] == 1 and
            report['kind'] == kind, 'Synthetic/unknown report cannot authorize publication.')
    exact(report['operator'], ('id', 'login'), 'operator')
    require(type(report['operator']['id']) is int and report['operator'] ==
            {key: operator[key] for key in ('id', 'login')}, 'Attestor is not authenticated uploader.')
    require(report['repository'] == {'id': repo_id, 'name': REPOSITORY} and
            type(report['repository'].get('id')) is int and type(report['release_id']) is int and
            report['release_id'] == release_id and report['tag'] == tag and report['source'] == source['source'] and
            report['manifest_sha256'] == manifest_sha and report['image'] == image and report['artifacts'] == hashes,
            'Attestation does not bind all current signed software.')
    require(type(report['logs']) is list and 0 < len(report['logs']) <= MAX_LOGS, 'Invalid log count.')
    logs = {}
    total = 0
    for log in report['logs']:
        exact(log, ('id', 'name', 'size', 'sha256'), 'evidence log')
        identifier = number(log['id']); number(log['size']); digest(log['sha256'])
        require(type(log['name']) is str and re.fullmatch(r'native-evidence-[A-Za-z0-9_-]+\.txt', log['name']), 'Invalid evidence log name.')
        require(identifier not in logs and log['name'] in by_name and log['name'] not in hashes, 'Duplicate/missing log.')
        asset = by_name[log['name']]
        require(asset['id'] == identifier and asset['size'] == log['size'], 'Log asset binding mismatch.')
        total += log['size']
        require(total <= MAX_LOG_TOTAL, 'Cumulative log byte limit exceeded.')
        data = download(api, asset, MAX_LOG)
        require(sha(data) == log['sha256'], 'Evidence log digest mismatch.')
        try:
            decoded = data.decode('utf-8')
        except UnicodeError as error:
            raise Refused('Evidence logs must be UTF-8 text.') from error
        require(decoded.strip() and '\x00' not in decoded, 'Empty/binary evidence log.')
        logs[identifier] = metadata(asset)
    exact(report['platforms'], routes, 'platform matrix')
    prior = previous_release(api, tag, release_id)
    earliest = max(timestamp(by_name[name]['created_at']) for name in hashes)
    if channel != 'native': earliest = max(earliest, timestamp(release['published_at']))
    latest = timestamp(report_asset['created_at'])
    require(earliest <= latest <= datetime.now(timezone.utc), 'Evidence upload chronology invalid.')
    used_logs = set()
    for route, (_, extra) in routes.items():
        platform = report['platforms'][route]
        exact(platform, ('os', 'host', 'checks'), route)
        text(platform['os']); text(platform['host'])
        exact(platform['checks'], common | extra, route + ' observations')
        for name, observation in platform['checks'].items():
            fields = {'result', 'observed_at', 'observation', 'logs'}
            if name == 'host_reboot': fields |= {'boot_before', 'boot_after'}
            if name == 'pre_login_readiness': fields |= {'ready_at', 'first_interactive_login_at'}
            if name == 'signed_template_stack': fields |= {'region', 'architecture'}
            exact(observation, fields, route + '/' + name)
            result = observation['result']
            require(result == 'passed' or (name == 'prior_version_upgrade' and not prior and
                    result == 'not_applicable:first_release'), 'Required native observation not passed.')
            require(earliest <= timestamp(observation['observed_at']) <= latest, 'Observation predates software or follows attestation.')
            text(observation['observation'], 4096)
            references = observation['logs']
            require(type(references) is list and 0 < len(references) <= MAX_LOGS and
                    all(type(item) is int and item in logs for item in references) and
                    len(references) == len(set(references)), 'Observation lacks bound logs.')
            used_logs.update(references)
            if name == 'signed_template_stack':
                require(observation['region'] == 'ap-northeast-1' and observation['architecture'] == 'arm64',
                        'AWS channel requires the Tokyo arm64 template entrypoint.')
            if name == 'host_reboot':
                require(text(observation['boot_before']) != text(observation['boot_after']), 'Actual reboot IDs must differ.')
            if name == 'pre_login_readiness':
                require(earliest <= timestamp(observation['ready_at']) < timestamp(observation['first_interactive_login_at'])
                        <= timestamp(observation['observed_at']), 'Windows readiness must precede interactive login.')
    require(used_logs == set(logs), 'Unreferenced evidence assets.')
    watched = {name: metadata(by_name[name]) for name in set(hashes) | {'SHA256SUMS', report_name} |
               {log['name'] for log in report['logs']}}
    # Prevent a moving upload/tag/role from being treated as a stable attestation.
    for name, original in watched.items():
        current = api.api(f'repos/{REPOSITORY}/releases/assets/{original["id"]}')
        require(metadata(current) == original, 'Release asset changed during verification.')
    require(role(api, report_asset['uploader']) == operator, 'Attestor authority changed.')
    current = api.api(f'repos/{REPOSITORY}/releases/tags/{tag}')
    require(current.get('id') == release_id and current.get('tag_name') == tag and
            current.get('draft') == release['draft'] and current.get('prerelease') is False and
            current.get('published_at') == release.get('published_at') and
            api.api(f'repos/{REPOSITORY}/commits/{tag}').get('sha') == source['source'], 'Release/tag changed during verification.')
    return {'channel': channel, 'tag': tag, 'source': source['source'], 'release_id': release_id, 'draft': release['draft'],
            'manifest_sha256': manifest_sha, 'image': image, 'operator': operator,
            'report_sha256': sha(report_bytes), 'assets': watched}


def promote(api, tag, directory):
    # Authenticate the actual token principal, not its environment-variable name.
    actor = role(api, api.api('user'))
    expected = strict_json((directory / '.native-readiness-verified.json').read_bytes())
    current = verify(api, tag, directory)
    require(current == expected and current['draft'] is True, 'Promotion requires the unchanged verified draft.')
    require(role(api, api.api('user')) == actor, 'Promoter identity/authority changed.')
    command(['gh', 'release', 'edit', tag, '--repo', REPOSITORY, '--draft=false'], limit=MAX_API)
    print('Published the verified draft using identified human CLI authority; inspect the publish workflow result.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('verify', 'promote'))
    parser.add_argument('tag')
    parser.add_argument('directory', type=Path)
    parser.add_argument('--channel', choices=tuple(CHANNELS), default='native')
    args = parser.parse_args()
    api = GitHub()
    if args.mode == 'promote':
        require(args.channel == 'native', 'Only the native gate promotes the Guard draft.')
        promote(api, args.tag, args.directory)
    else:
        if args.channel != 'native':
            # The Actions artifact came from the full gate. Recheck native proof
            # and current signed bindings before this channel's independent gate.
            verify(api, args.tag, args.directory)
        snapshot = verify(api, args.tag, args.directory, args.channel)
        (args.directory / ('.' + args.channel + '-readiness-verified.json')).write_text(json.dumps(snapshot, sort_keys=True) + '\n')
        print('Accepted operator-attested ' + args.channel + ' observations by ' + snapshot['operator']['login'] +
              ' for ' + args.tag + '; report SHA256 ' + snapshot['report_sha256'] + '. Not automated native proof.')


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        print('Native readiness refused: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
