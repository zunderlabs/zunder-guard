#!/usr/bin/env python3
"""Publish the exact verified release loaders on their canonical Cloudflare routes.

Run only from the signature/provenance-gated release publication job. Credentials are read
from environment, never printed. --render-only validates/generates without API access.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

HOST = 'zunderlabs.com'
SCRIPT = 'zunder-guard-installers'
OWNER_TAG = 'zunder-guard-canonical-installers-v1'
PATHS = {'/i': 'i', '/i.ps1': 'i.ps1'}
API = 'https://api.cloudflare.com/client/v4'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_assets(directory, tag):
    if not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise ValueError('Expected a stable vMAJOR.MINOR.PATCH release tag')
    checksums = directory / 'SHA256SUMS'
    if checksums.is_symlink() or not checksums.is_file():
        raise ValueError('Missing regular SHA256SUMS')
    sums = {}
    for line in checksums.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](\S+)', line)
        if not match:
            raise ValueError('Malformed checksum manifest')
        name = match[2]
        if name in sums:
            raise ValueError('Duplicate checksum entry')
        sums[name] = match[1].lower()
    assets = {}
    for route, name in PATHS.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing regular loader asset')
        data = path.read_bytes()
        if not data or len(data) > 1024 * 1024 or sha(data) != sums.get(name):
            raise ValueError('Loader asset checksum or size mismatch')
        content = data.decode('utf-8')
        if tag not in content:
            raise ValueError('Loader does not identify the expected release')
        assets[route] = {'body': content, 'sha256': sha(data)}
    return assets


def render_worker(assets, tag):
    return ('const assets = ' + json.dumps(assets, ensure_ascii=True) + ';\n'
            'const version = ' + json.dumps(tag) + ';\n'
            'export default { fetch(request) {\n'
            ' const url = new URL(request.url);\n'
            ' if (url.hostname !== "zunderlabs.com" || !Object.hasOwn(assets, url.pathname)) return new Response("Not found", {status:404});\n'
            ' if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method not allowed", {status:405, headers:{Allow:"GET, HEAD"}});\n'
            ' const asset = assets[url.pathname];\n'
            ' return new Response(request.method === "HEAD" ? null : asset.body, {headers:{"Content-Type":"text/plain; charset=utf-8", "X-Content-Type-Options":"nosniff", "Cache-Control":"no-store", "X-Zunder-Release":version, "X-Zunder-SHA256":asset.sha256}});\n'
            '} };\n').encode()


class Cloudflare:
    def __init__(self, token):
        self.token = token

    def request(self, method, endpoint, data=None, content_type='application/json'):
        body = json.dumps(data).encode() if isinstance(data, dict) else data
        req = urllib.request.Request(API + endpoint, data=body, method=method,
                                     headers={'Authorization': 'Bearer ' + self.token,
                                              'Content-Type': content_type})
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                payload = json.load(response)
        except (urllib.error.URLError, ValueError):
            # API error bodies may echo request details; don't propagate them into CI logs.
            raise RuntimeError('Cloudflare request failed; inspect the protected deployment account') from None
        if not payload.get('success'):
            raise RuntimeError('Cloudflare refused the request')
        return payload.get('result')


def identifiers(account, zone):
    if not all(re.fullmatch(r'[0-9a-f]{32}', value or '') for value in [account, zone]):
        raise ValueError('Set valid CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_ZONE_ID')


def route_preflight(routes):
    expected = {HOST + p for p in PATHS}
    found = {}
    for route in routes:
        pattern = route.get('pattern')
        if route.get('script') == SCRIPT and pattern not in expected:
            raise RuntimeError('Installer Worker also owns an unrelated route; no changes made')
        if pattern in expected:
            if pattern in found or route.get('script') != SCRIPT:
                raise RuntimeError('Canonical installer route already has another owner; no changes made')
            found[pattern] = route
    return found


def publish(client, account, zone, source):
    identifiers(account, zone)
    zone_info = client.request('GET', '/zones/' + zone)
    if zone_info.get('name') != HOST or zone_info.get('account', {}).get('id') != account:
        raise ValueError('Cloudflare zone/account does not match the canonical website')
    routes = client.request('GET', f'/zones/{zone}/workers/routes')
    found = route_preflight(routes)
    # A free route does not prove the reserved script name is unused: a Worker can
    # already serve workers.dev, a custom domain, or a route in another zone.
    scripts = client.request('GET', f'/accounts/{account}/workers/scripts')
    if not isinstance(scripts, list) or any(not isinstance(item, dict) for item in scripts):
        raise RuntimeError('Could not establish installer Worker ownership; no changes made')
    existing = [item for item in scripts if item.get('id') == SCRIPT]
    if len(existing) > 1:
        raise RuntimeError('Ambiguous installer Worker ownership; no changes made')
    if existing:
        settings = client.request('GET', f'/accounts/{account}/workers/scripts/{SCRIPT}/settings')
        if (not isinstance(settings, dict) or settings.get('tags') != [OWNER_TAG]
                or settings.get('bindings') or settings.get('tail_consumers') or settings.get('logpush')):
            raise RuntimeError('Existing Worker is not the managed installer; no changes made')
    boundary = 'zunder_loader_' + sha(source)[:32]
    metadata = json.dumps({'main_module': 'worker.mjs', 'compatibility_date': '2026-10-01',
                           'tags': [OWNER_TAG], 'bindings': [], 'tail_consumers': [], 'logpush': False}).encode()
    parts = []
    for name, filename, content_type, data in [('metadata', None, 'application/json', metadata),
                                                ('worker.mjs', 'worker.mjs', 'application/javascript+module', source)]:
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            disposition += f'; filename="{filename}"'
        parts.append((f'--{boundary}\r\n{disposition}\r\nContent-Type: {content_type}\r\n\r\n').encode() + data + b'\r\n')
    body = b''.join(parts) + f'--{boundary}--\r\n'.encode()
    client.request('PUT', f'/accounts/{account}/workers/scripts/{SCRIPT}', body,
                   'multipart/form-data; boundary=' + boundary)
    for route in [HOST + p for p in PATHS]:
        if route not in found:
            client.request('POST', f'/zones/{zone}/workers/routes', {'pattern': route, 'script': SCRIPT})


def require_latest(tag):
    req = urllib.request.Request('https://api.github.com/repos/zunderlabs/zunder-guard/releases/latest',
                                 headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'zunder-release'})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            release = json.load(response)
    except (urllib.error.URLError, ValueError):
        raise RuntimeError('Could not verify the latest stable release; no publication') from None
    if release.get('tag_name') != tag or release.get('draft') or release.get('prerelease'):
        raise RuntimeError('Refusing to publish loaders for a release other than latest stable')


def verify_public(assets):
    for route, asset in assets.items():
        matched = False
        for attempt in range(6):
            try:
                req = urllib.request.Request('https://' + HOST + route, headers={'Cache-Control': 'no-cache'})
                with urllib.request.urlopen(req, timeout=20) as response:
                    matched = response.status == 200 and sha(response.read(1024 * 1024 + 1)) == asset['sha256']
            except urllib.error.URLError:
                matched = False
            if matched:
                break
            if attempt != 5:
                time.sleep(5)
        if not matched:
            raise RuntimeError('Canonical loader did not match signed release bytes after publication')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--render-only', type=Path)
    args = parser.parse_args()
    assets = load_assets(args.release_dir, args.tag)
    source = render_worker(assets, args.tag)
    if args.render_only:
        args.render_only.write_bytes(source)
        print('Validated loaders and rendered Worker; no network changes')
        return
    token = os.environ.get('CLOUDFLARE_API_TOKEN')
    if not token:
        raise ValueError('Set the scoped CLOUDFLARE_API_TOKEN')
    require_latest(args.tag)
    publish(Cloudflare(token), os.environ.get('CLOUDFLARE_ACCOUNT_ID'), os.environ.get('CLOUDFLARE_ZONE_ID'), source)
    verify_public(assets)
    print('Both canonical loaders match the signed release assets')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        # Only fixed/local error messages; never print API response bodies or credentials.
        print('Installer publication failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
