#!/usr/bin/env python3
"""Public-authored operation adapters. Admitted private bytes are data, never imports/hooks.

The public controller must call its exact admission reader again immediately before writes.
No CLI/environment destination override exists here; policies come from protected public source.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import urllib.request
import uuid
from email.parser import BytesParser
from email.policy import default as email_policy

HERE = Path(__file__).resolve().parent
AUTHORITY = HERE.parent
PUBLIC_REPO = 'zunderlabs/zunder-guard'
PROJECTS = {'website-preview': ('preview', 'zunder-design-preview', 'https://zunder-design-preview.pages.dev'),
            'website-staging': ('staging', 'zunder-testnet-journey', 'https://staging.zunderlabs.com'),
            'website-production': ('production', 'zunderlabs', 'https://zunderlabs.com')}
WORKER = 'zunder-waitlist'
STATUS = 'https://zunderlabs.com/api/licence/status'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()


def checked_payload(pin, payload):
    """Repeat the admitted inventory check; use the admission reader's returned data mapping."""
    require(isinstance(payload, dict) and payload, 'Admitted data mapping required')
    files = []
    for name in sorted(payload, key=lambda item: item.split('/')):
        require(re.fullmatch(r'[A-Za-z0-9_.@+ /-]+', name) and not name.startswith('/')
                and all(part not in {'', '.', '..'} for part in name.split('/'))
                and type(payload[name]) is bytes, 'Payload path/type refused')
        files.append({'path': name, 'size': len(payload[name]), 'sha256': sha(payload[name])})
    require(sha(compact(files)) == pin['inventorySha256'], 'Payload changed after admission')
    for field in ['config', 'releasePin']:
        item = pin[field]
        if item is not None:
            require(item['path'] in payload and sha(payload[item['path']]) == item['sha256'], 'Admitted data binding changed')
    return files


def reviewed_policy(target):
    require(target in PROJECTS or target == 'customer-worker-production', 'Operation target refused')
    file = HERE / 'targets' / (target + '.json')
    require(file.is_file() and not file.is_symlink(), 'Reviewed public target policy not installed')
    value = json.loads(file.read_bytes())
    require(value.get('schema') == 1 and value.get('target') == target
            and re.fullmatch(r'[a-f0-9]{32}', value.get('accountId', '')), 'Public target policy differs')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Cloudflare:
    def __init__(self, token):
        require(bool(token), 'Scoped Cloudflare grant required')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def raw(self, method, endpoint, data=None, content_type=None):
        require(method in {'GET', 'PUT'} and endpoint.startswith(('/accounts/', '/zones/'))
                and not any(c in endpoint for c in ['\r', '\n']), 'Provider operation refused')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': '*/*'}
        if content_type:
            headers['Content-Type'] = content_type
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + endpoint,
                                         data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=45) as response:
                body = response.read(16_000_001)
                require(len(body) <= 16_000_000, 'Provider response too large')
                return body, dict((k.lower(), v) for k, v in response.headers.items())
        except Exception:
            raise RuntimeError('Provider operation failed; reconcile applied state before retrying') from None

    def request(self, method, endpoint, data=None, content_type=None):
        body, _ = self.raw(method, endpoint, data, content_type)
        result = json.loads(body)
        require(result.get('success') is True and not result.get('errors'), 'Provider refused operation')
        return result.get('result')


def public_read(url, headers=None):
    require(url.startswith('https://'), 'HTTPS public read required')
    try:
        request = urllib.request.Request(url, headers=headers or {}, method='GET')
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            body = response.read(2_000_001)
            require(len(body) <= 2_000_000, 'Public response too large')
            return body, dict((k.lower(), v) for k, v in response.headers.items())
    except Exception:
        raise RuntimeError('Public runtime/channel read failed') from None


def trusted_run(args, cwd, env):
    # No shell; cwd and args are controller-owned. Never echo a private CLI error body.
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, timeout=600, check=False)
    require(result.returncode == 0 and len(result.stdout) < 8_388_608 and len(result.stderr) < 8_388_608,
            'Trusted tool failed; reconcile state before retrying')
    return result.stdout


def parse_release(pin):
    require(set(pin) == {'schema', 'version', 'sourceCommit', 'published', 'publishedAt', 'releaseId',
                        'releaseUrl', 'assetsUrl', 'signedAssetManifest', 'image', 'assets', 'channels'}, 'Release pin shape differs')
    version = pin['version']
    require(pin['schema'] == 1 and re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version)
            and pin['published'] is True and re.fullmatch(r'[a-f0-9]{40}', pin['sourceCommit'] or '')
            and type(pin['releaseId']) is int and pin['releaseId'] > 0
            and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', pin['publishedAt'] or ''), 'Accepted release identity required')
    base = 'https://github.com/' + PUBLIC_REPO
    assets_url = base + '/releases/download/v' + version
    require(pin['releaseUrl'] == base + '/releases/tag/v' + version and pin['assetsUrl'] == assets_url, 'Release origin differs')
    signed = pin['signedAssetManifest']
    require(set(signed) == {'url', 'sha256', 'sigstoreBundleUrl', 'provenanceUrl'}
            and signed['url'] == assets_url + '/SHA256SUMS'
            and signed['sigstoreBundleUrl'] == assets_url + '/SHA256SUMS.sigstore.json'
            and signed['provenanceUrl'] == assets_url + '/zunder-guard-v' + version + '.intoto.jsonl'
            and re.fullmatch(r'[a-f0-9]{64}', signed['sha256'] or ''), 'Signed release origin differs')
    require(type(pin['assets']) is dict and 0 < len(pin['assets']) <= 256, 'Complete signed inventory required')
    for name, asset in pin['assets'].items():
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', name)
                and set(asset) == {'url', 'sha256'} and asset['url'] == assets_url + '/' + name
                and re.fullmatch(r'[a-f0-9]{64}', asset['sha256']), 'Release subject differs')
    image = pin['image']
    require(type(image) is dict and set(image) == {'reference', 'descriptorAsset'}
            and re.fullmatch(r'ghcr.io/zunderlabs/zunder-guard@sha256:[a-f0-9]{64}', image['reference'])
            and image['descriptorAsset'] == 'zunder-guard-v' + version + '.image.txt'
            and image['descriptorAsset'] in pin['assets'], 'Signed image identity required')
    channels = pin['channels']
    require(set(channels) == {'unixInstallerUrl', 'windowsInstallerUrl', 'awsTemplateUrl', 'homebrewReady'}
            and type(channels['homebrewReady']) is bool, 'Release channel shape differs')
    expected = {'unixInstallerUrl': ('https://zunderlabs.com/i', 'i'),
                'windowsInstallerUrl': ('https://zunderlabs.com/i.ps1', 'i.ps1'),
                'awsTemplateUrl': ('https://zunder-guard-releases-313260780004-ap-northeast-1.s3.ap-northeast-1.amazonaws.com/guard/v'
                                   + version + '/cloudformation.yaml', 'cloudformation.yaml')}
    for key, (url, name) in expected.items():
        require(channels[key] is None or channels[key] == url and name in pin['assets'], 'Release channel origin differs')
    require(not channels['homebrewReady'] or 'zunder-guard.rb' in pin['assets'], 'Homebrew signed subject absent')
    return pin


def bind_release(pin, sums, source, native, release, image):
    tag = 'v' + pin['version']
    require(source.get('tag') == tag and source.get('source') == pin['sourceCommit']
            and native.get('tag') == tag and native.get('source') == pin['sourceCommit']
            and native.get('manifest_sha256') == sha(sums) == pin['signedAssetManifest']['sha256']
            and native.get('release_id') == pin['releaseId'] and native.get('draft') is False
            and native.get('image') == image == pin['image']['reference']
            and release.get('id') == pin['releaseId'] and release.get('tag_name') == tag
            and release.get('draft') is False and release.get('prerelease') is False
            and release.get('published_at') == pin['publishedAt'], 'Full verifier result differs from admitted release pin')
    subjects = {}
    for line in sums.decode().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,199})', line)
        require(match and match[2] not in subjects, 'Authenticated checksum subject malformed')
        subjects[match[2]] = match[1]
    require(subjects == {name: item['sha256'] for name, item in pin['assets'].items()}, 'Full signed inventory differs')


def complete_release_gate(value, public_token, read=public_read, run=trusted_run):
    pin = parse_release(value)
    for name in ['verify-release.sh', 'verify-release-assets.sh', 'native-readiness.py', 'machine-evidence-policy.json']:
        file = AUTHORITY / name
        require(file.is_file() and not file.is_symlink(), 'Current integrated public full verifier required')
    require(bool(public_token), 'Public release read identity required')
    env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
    env.update({'GH_TOKEN': public_token, 'GITHUB_REPOSITORY': PUBLIC_REPO})
    tag = 'v' + pin['version']
    with tempfile.TemporaryDirectory(prefix='zunder-public-release-gate-') as temporary:
        output = Path(temporary) / 'verified'
        run(['bash', str(AUTHORITY / 'verify-release.sh'), tag, str(output)], AUTHORITY.parents[2], env)
        load = lambda name: json.loads((output / name).read_bytes())
        sums = (output / 'SHA256SUMS').read_bytes()
        source, native = load('.verified-release-source.json'), load('.native-readiness-verified.json')
        image = (output / pin['image']['descriptorAsset']).read_text().strip()
        release_args = ['gh', 'api', 'repos/' + PUBLIC_REPO + '/releases/tags/' + tag]
        release = json.loads(run(release_args, AUTHORITY.parents[2], env))
        bind_release(pin, sums, source, native, release, image)
        for enabled, channel in [(pin['channels']['homebrewReady'], 'homebrew'), (pin['channels']['awsTemplateUrl'], 'aws')]:
            if enabled:
                run(['python3', '-B', str(AUTHORITY / 'native-readiness.py'), 'verify', tag, str(output), '--channel', channel], AUTHORITY.parents[2], env)
                proof = load('.' + channel + '-readiness-verified.json')
                require(proof.get('channel') == channel and all(proof.get(key) == native.get(key) for key in ['tag', 'source', 'release_id', 'draft', 'manifest_sha256', 'image']), 'Channel evidence differs')
        for key, name in [('unixInstallerUrl', 'i'), ('windowsInstallerUrl', 'i.ps1'), ('awsTemplateUrl', 'cloudformation.yaml')]:
            url = pin['channels'][key]
            if url:
                require(sha(read(url)[0]) == pin['assets'][name]['sha256'], 'Published channel bytes differ')
        if pin['channels']['homebrewReady']:
            require(sha(read('https://raw.githubusercontent.com/zunderlabs/homebrew-tap/main/Formula/zunder-guard.rb')[0])
                    == pin['assets']['zunder-guard.rb']['sha256'], 'Homebrew channel bytes differ')
        bind_release(pin, sums, source, native, json.loads(run(release_args, AUTHORITY.parents[2], env)), image)
        require(run(['gh', 'api', 'repos/' + PUBLIC_REPO + '/commits/' + tag, '--jq', '.sha'], AUTHORITY.parents[2], env).decode().strip()
                == pin['sourceCommit'], 'Public release tag changed')
    return pin


def prepare_pages(admission, payload, policy):
    checked_payload(admission, payload)
    target = admission['target']
    require(target in PROJECTS and admission['kind'] == 'website' and policy['target'] == target, 'Pages admission target differs')
    folder, project, origin = PROJECTS[target]
    require(policy.get('project') == project and re.fullmatch(r'[A-Za-z0-9._/-]+', policy.get('branch', ''))
            and re.fullmatch(r'[a-f0-9]{32}', policy.get('accountId', '')), 'Reviewed Pages destination required')
    require(admission['releasePin']['path'] == folder + '/release-pin.json', 'Selected release pin differs')
    pin = parse_release(json.loads(payload[folder + '/release-pin.json']))
    profile = json.loads(payload[folder + '/deployment-profile.json'])
    require(profile.get('profile') == ('staging' if folder == 'staging' else 'production')
            and profile.get('releasePublished') is True and profile.get('releaseVersion') == pin['version'], 'Published target profile differs')
    if folder == 'staging':
        merchant = policy.get('stagingMerchant')
        state = json.loads(payload[folder + '/staging-payment-profile.json'])
        require(set(state) == {'schema', 'merchant', 'stagingFixtureOnly'} and state['schema'] == 1
                and state['stagingFixtureOnly'] is False and state['merchant'] == merchant
                and re.fullmatch(r'0x[0-9a-f]{40}', merchant or '')
                and merchant not in {'0x' + '3' * 40, '0x' + '0' * 40}, 'Real isolated staging merchant handoff required')
    files = {name[len(folder) + 1:]: data for name, data in payload.items() if name.startswith(folder + '/')}
    require(files and 'index.html' in files and not any(name.startswith(('functions/', '_worker.js/')) or name == '_worker.bundle'
            or any(part in {'node_modules', '.git', '.wrangler'} for part in name.split('/'))
            or Path(name).name in {'package.json', 'wrangler.toml', 'wrangler.json', 'wrangler.jsonc', '.DS_Store'} for name in files),
            'Pages data only; build/functions/config hooks refused')
    require(policy.get('requireAccess') is (target != 'website-production'), 'Reviewed preview/staging Access requirement needed')
    return {'target': target, 'folder': folder, 'project': project, 'origin': origin, 'pin': pin, 'files': files, 'requireAccess': policy['requireAccess']}


def pages_target(info, plan, policy):
    require(info.get('name') == plan['project'] and info.get('production_branch') == policy['branch'], 'Pages project branch differs')
    config = info.get('deployment_configs', {}).get('production', {})
    # Provider GET contract is services; Wrangler's service_bindings is not an alias.
    require(type(config) is dict and 'service_bindings' not in config, 'Unknown Pages service configuration shape')
    services = config.get('services', {})
    require(type(services) is dict, 'Pages services metadata unavailable')
    def service(name, expected):
        binding = services.get(name)
        return type(binding) is dict and set(binding) == {'service', 'environment'} \
            and binding['service'] == expected and type(binding['environment']) is str and binding['environment'] in {'', 'production'}
    # Empty environment is the observed vendor default production environment.
    # Named/unknown entrypoints are not the reviewed default fetch handler.
    if plan['target'] == 'website-preview':
        require(set(services) == {'CUSTOMER_API'} and service('CUSTOMER_API', WORKER), 'Preview customer service binding differs')
    if plan['target'] == 'website-staging':
        variables = config.get('env_vars', {})
        require(variables.get('DEPLOYMENT_PROFILE', {}).get('value') == 'staging'
                and variables.get('TESTNET_SITE_ENABLED', {}).get('value') == 'explicitly-provisioned'
                and set(services) == {'TESTNET_JOURNEY_API', 'TESTNET_INBOX'}
                and service('TESTNET_JOURNEY_API', 'zunder-testnet-journey-api')
                and service('TESTNET_INBOX', 'zunder-testnet-journey-inbox'), 'Isolated staging Pages handoff differs')


def pages_smoke(plan, access, read=public_read):
    require(not plan.get('requireAccess') or bool(access), 'Authenticated preview/staging smoke grant required')
    require(not access or plan['target'] != 'website-production'
            and set(access) == {'CF-Access-Client-Id', 'CF-Access-Client-Secret'} and all(access.values()), 'Preview/staging-only complete Access grant required')
    for name in ['release-pin.json', 'deployment-profile.json']:
        require(read(plan['origin'] + '/' + name, access)[0] == plan['files'][name], 'Applied Pages identity bytes differ')
    profile = 'staging' if plan['target'] == 'website-staging' else 'production'
    for route in ['/', '/connect', '/pricing', '/licence', '/approve', '/docs']:
        html = read(plan['origin'] + route, access)[0].decode()
        require(re.search(r'<main[\s>]', html) and 'name="zunder-deployment-profile" content="' + profile + '"' in html, 'Pages runtime route/profile failed')
    return {'target': plan['target'], 'runtimeObserved': True, 'accessAuthenticated': bool(access), 'accessPolicyProof': False, 'paymentMailLicenceProof': False}


def publish_pages(admission, payload, policy, api, public_token, cf_token, access, recheck, read=public_read, run=trusted_run, gate=complete_release_gate):
    plan = prepare_pages(admission, payload, policy)
    # Full gate receives public GitHub read authority only, never publisher/reader/Access secrets.
    gate(plan['pin'], public_token)
    endpoint = '/accounts/' + policy['accountId'] + '/pages/projects/' + plan['project']
    pages_target(api.request('GET', endpoint), plan, policy)
    tool = HERE / 'pages-upload.mjs'
    require(tool.is_file() and not tool.is_symlink()
            and json.loads((HERE / 'tools/node_modules/@noble/hashes/package.json').read_bytes()).get('version') == '2.0.1', 'Public locked permissive hash tool required')
    with tempfile.TemporaryDirectory(prefix='zunder-public-pages-') as directory:
        root = Path(directory)
        output = root / 'payload'
        output.mkdir(mode=0o700)
        for name, data in plan['files'].items():
            file = output / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
            file.chmod(0o600)
        # No config/build hooks in controller-owned cwd, no private package or Node preload env.
        env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
        env.update({'CLOUDFLARE_API_TOKEN': cf_token})
        recheck()  # Trusted public admission/API producer reread, immediately before write.
        pages_target(api.request('GET', endpoint), plan, policy)
        inventory = sha(compact([{'path': name, 'sha256': sha(data)} for name, data in sorted(plan['files'].items())]))
        receipt = json.loads(run(['node', str(tool), str(output), policy['accountId'], plan['project'], policy['branch'],
                                 admission['sourceCommit'], inventory], root, env))
        require(set(receipt) == {'deploymentId', 'sourceCommit', 'project'}
                and re.fullmatch(r'[a-f0-9-]{36}', receipt['deploymentId'])
                and receipt['sourceCommit'] == admission['sourceCommit'] and receipt['project'] == plan['project'], 'Pages uploader identity differs')
    applied = api.request('GET', endpoint)
    pages_target(applied, plan, policy)
    require(applied.get('canonical_deployment', {}).get('id') == receipt['deploymentId'], 'Canonical Pages deployment differs')
    result = pages_smoke(plan, access, read)
    require(api.request('GET', endpoint).get('canonical_deployment', {}).get('id') == receipt['deploymentId'], 'Canonical Pages deployment changed around smoke')
    return dict(result, deploymentId=receipt['deploymentId'], sourceCommit=admission['sourceCommit'])


def prepare_worker(admission, payload, policy):
    checked_payload(admission, payload)
    require(admission['target'] == policy['target'] == 'customer-worker-production'
            and admission['kind'] == 'customer-worker' and admission['config']['path'] == 'wrangler.toml', 'Worker admission target differs')
    require(policy.get('worker') == WORKER and policy.get('migrations') == 'none'
            and re.fullmatch(r'[a-f0-9]{32}', policy.get('accountId', ''))
            and re.fullmatch(r'[a-f0-9]{32}', policy.get('zoneId', '')), 'Reviewed existing Worker target/no-migration policy required')
    config = tomllib.loads(payload['wrangler.toml'].decode())
    require(config.get('name') == WORKER and config.get('main') == 'bundle/index.js'
            and not any(key in config for key in ['build', 'env', 'assets', 'site', 'unsafe'])
            and not re.search(r'TESTNET_|DB_INBOX_TESTNET', payload['wrangler.toml'].decode()), 'Private configuration hooks/testnet settings refused')
    require(config.get('compatibility_date') == policy['compatibilityDate']
            and config.get('compatibility_flags', []) == policy.get('compatibilityFlags', []) == []
            and config.get('vars') == policy['vars'] and policy['vars'].get('DEPLOYMENT_PROFILE') == 'production'
            and policy['vars'].get('ENVIRONMENT') == 'production' and policy['vars'].get('LICENCE_CHAIN') == 'mainnet'
            and policy['vars'].get('SITE_URL') == 'https://zunderlabs.com' and policy['vars'].get('SALES_EVM_NETWORKS') == 'arbitrum,base',
            'Reviewed production Worker public metadata differs')
    require(re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', policy.get('databaseId', '')), 'Reviewed D1 UUID required')
    require(config.get('d1_databases') and len(config['d1_databases']) == 1
            and config['d1_databases'][0].get('binding') == 'DB'
            and config['d1_databases'][0].get('database_id') == policy['databaseId'], 'Production D1 identity differs')
    modules = {name[7:]: data for name, data in payload.items() if name.startswith('bundle/') and name not in {'bundle/README.md', 'bundle/index.js.map'}}
    require('index.js' in modules and all(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and name not in {'.', '..'} for name in modules), 'Worker flat module inventory required')
    require(all(Path(name).suffix in {'.js', '.mjs', '.gif', '.wasm'} for name in modules), 'Unsupported Worker module type')
    return {'modules': modules, 'configSha256': sha(payload['wrangler.toml']), 'policy': policy}


def worker_routes(routes):
    require(type(routes) is list, 'Worker routes unavailable')
    expected = {'zunderlabs.com/api/waitlist*', 'zunderlabs.com/api/contact', 'zunderlabs.com/api/licence*'}
    own = {route.get('pattern') for route in routes if route.get('script') == WORKER}
    require(own == expected, 'Existing Worker route ownership differs')
    matches = []
    for route in routes:
        pattern = route.get('pattern')
        require(type(pattern) is str, 'Unknown Worker route shape')
        url = pattern if '://' in pattern else 'https://' + pattern
        if re.fullmatch(re.escape(url).replace(r'\*', '.*'), STATUS, re.I):
            matches.append(route)
    require(len(matches) == 1 and matches[0].get('pattern') == 'zunderlabs.com/api/licence*'
            and matches[0].get('script') == WORKER, 'Overlapping production licence route refused')
    return sha(compact(sorted(({'id': r.get('id'), 'pattern': r['pattern'], 'script': r.get('script')} for r in routes if r.get('script') == WORKER), key=lambda x: x['pattern'])))


def worker_bindings(resources, policy):
    runtime = resources.get('script_runtime', {})
    require(runtime.get('compatibility_date') == policy['compatibilityDate'] and runtime.get('compatibility_flags') == [], 'Active Worker runtime differs')
    bindings = resources.get('bindings')
    require(type(bindings) is list and len({b.get('name') for b in bindings}) == len(bindings)
            and all(type(b.get('name')) is str and not re.search(r'TESTNET_|DB_INBOX_TESTNET', b['name']) for b in bindings), 'Ambiguous/testnet runtime binding')
    for name, value in policy['vars'].items():
        require(any(b.get('name') == name and b.get('type') == 'plain_text' and b.get('text') == value for b in bindings), 'Active public Worker var differs')
    require(any(b.get('name') == 'DB' and b.get('type') == 'd1' and b.get('id') == policy['databaseId'] for b in bindings), 'Active production database differs')
    return sorted({b['type'] for b in bindings})


def worker_snapshot(api, plan, check_modules=True):
    policy = plan['policy']
    zone = api.request('GET', '/zones/' + policy['zoneId'])
    require(zone.get('name') == 'zunderlabs.com' and zone.get('account', {}).get('id') == policy['accountId'], 'Worker zone/account differs')
    base = '/accounts/' + policy['accountId'] + '/workers/scripts/' + WORKER
    deployments = api.request('GET', base + '/deployments').get('deployments', [])
    require(deployments and deployments[0].get('strategy') == 'percentage' and len(deployments[0].get('versions', [])) == 1
            and deployments[0]['versions'][0].get('percentage') == 100, 'Single fully active Worker version required')
    version = deployments[0]['versions'][0]['version_id']
    require(re.fullmatch(r'[a-f0-9-]{36}', version), 'Active version identity absent')
    details = api.request('GET', base + '/versions/' + version)
    require(details.get('id') == version, 'Version response differs')
    types = worker_bindings(details.get('resources', {}), policy)
    etag = details.get('resources', {}).get('script', {}).get('etag')
    require(type(etag) is str and etag and not etag.startswith('W/'), 'Active script ETag absent')
    etag = etag.strip('"')
    content, headers = api.raw('GET', base + '/content/v2')
    require(headers.get('etag', '').strip('"') == etag and not headers.get('etag', '').startswith('W/')
            and headers.get('cf-entrypoint') == 'index.js' and headers.get('content-type', '').startswith('multipart/'), 'Raw content identity join unknown')
    message = BytesParser(policy=email_policy).parsebytes(('Content-Type: ' + headers['content-type'] + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + content)
    modules = {}
    require(message.is_multipart(), 'Module response malformed')
    for part in message.iter_parts():
        name = part.get_param('name', header='content-disposition')
        require(type(name) is str and name not in modules and part.get_filename() == name, 'Module identity ambiguous')
        modules[name] = part.get_payload(decode=True)
    hashes = {name: sha(data) for name, data in modules.items()}
    if check_modules:
        require(hashes == {name: sha(data) for name, data in plan['modules'].items()}, 'Active bundle differs from admitted modules')
    routes = worker_routes(api.request('GET', '/zones/' + policy['zoneId'] + '/workers/routes'))
    return {'deploymentId': deployments[0]['id'], 'versionId': version, 'etag': etag, 'modulesHash': sha(compact(hashes)), 'routesHash': routes, 'bindingTypes': types, 'bindingsHash': sha(compact(sorted(details['resources']['bindings'], key=lambda b: b['name'])))}


def multipart_modules(plan, binding_types):
    boundary = 'zunder_' + uuid.uuid4().hex
    metadata = {'main_module': 'index.js', 'compatibility_date': plan['policy']['compatibilityDate'],
                'compatibility_flags': [], 'bindings': [], 'keep_bindings': binding_types}
    parts = [(b'metadata', None, 'application/json', compact(metadata))]
    for name, data in plan['modules'].items():
        mime = 'application/javascript+module' if name.endswith(('.js', '.mjs')) else 'application/wasm' if name.endswith('.wasm') else 'application/octet-stream'
        parts.append((name.encode(), name, mime, data))
    body = b''
    for name, filename, mime, data in parts:
        disposition = 'Content-Disposition: form-data; name="' + name.decode() + '"'
        if filename:
            disposition += '; filename="' + filename + '"'
        body += ('--' + boundary + '\r\n' + disposition + '\r\nContent-Type: ' + mime + '\r\n\r\n').encode() + data + b'\r\n'
    return body + ('--' + boundary + '--\r\n').encode(), 'multipart/form-data; boundary=' + boundary


def publish_worker(admission, payload, policy, api, recheck, read=public_read):
    plan = prepare_worker(admission, payload, policy)
    before = worker_snapshot(api, plan, check_modules=False)
    # Existing bindings are kept by TYPE, including secret types; values are never fetched/set.
    # No D1 query/migration API, route mutation, server allocation or private tool is invoked.
    body, content_type = multipart_modules(plan, before['bindingTypes'])
    recheck()
    require(worker_snapshot(api, plan, check_modules=False) == before, 'Worker target changed before upload')
    api.request('PUT', '/accounts/' + policy['accountId'] + '/workers/scripts/' + WORKER, body, content_type)
    applied = worker_snapshot(api, plan)
    require(applied['bindingsHash'] == before['bindingsHash'] and applied['routesHash'] == before['routesHash'], 'Worker bindings/routes changed across upload')
    runtime, headers = read(STATUS + '?delivery_smoke=' + uuid.uuid4().hex, {'Cache-Control': 'no-cache'})
    require(re.search(r'(?:^|,)\s*no-store\s*(?:,|$)', headers.get('cache-control', ''), re.I) and int(headers.get('age', '0')) == 0 and headers.get('cf-cache-status', '').upper() not in {'HIT', 'STALE', 'UPDATING', 'REVALIDATED'}, 'Uncached Worker runtime required')
    status = json.loads(runtime)
    require(status.get('ok') is True and status.get('open') is True and status.get('chain') == 'mainnet'
            and status.get('message') is None and status.get('networks') == ['hyperliquid', 'arbitrum', 'base'], 'Production readonly checkout status failed')
    require(worker_snapshot(api, plan) == applied, 'Worker identity changed around runtime smoke')
    return {'target': 'customer-worker-production', 'versionId': applied['versionId'], 'deploymentId': applied['deploymentId'],
            'configSha256': plan['configSha256'], 'runtimeObserved': True, 'responseVersionIdentity': False,
            'paymentMailLicenceProof': False, 'migrationsApplied': False}
