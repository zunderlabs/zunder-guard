#!/usr/bin/env python3
"""Private signed-binary TESTNET MCP journey. Prepared only; parent executes.

Never reads an API-wallet key. Guard directly inherits dedicated stdin. No
mainnet, transfer, withdrawal, approval, raw exchange or kill-all operation.
"""
import argparse
from collections import deque
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN, ROUND_UP
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
from urllib.request import Request, build_opener, HTTPRedirectHandler

INFO = 'https://api.hyperliquid-testnet.xyz/info'
SAFE = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C.UTF-8')


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def decimal(value, *, positive=False):
    need(isinstance(value, str) and len(value) <= 128 and re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?', value), 'Invalid Decimal string.')
    result = Decimal(value)
    need(not positive or result > 0, 'Expected positive Decimal.')
    return result


def private(path, *, directory=False):
    need(path.is_absolute() and '..' not in path.parts, 'Absolute private path required.')
    for parent in reversed(path.parents):
        parent_info = parent.lstat()
        mode = stat.S_IMODE(parent_info.st_mode)
        # A root-owned sticky temporary ancestor protects an owned child from
        # another user's rename; every subsequent directory must be trusted too.
        sticky_root = parent_info.st_uid == 0 and bool(mode & stat.S_ISVTX)
        need(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid in (0, os.geteuid())
             and (not mode & 0o022 or sticky_root), 'Unsafe or symlink private ancestor.')
    info = path.lstat()
    need(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077,
         'Private owned path required.')
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
         'Regular non-symlink private path required.')


def binding(args):
    need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.tag) and re.fullmatch('[0-9a-f]{40}', args.source)
         and re.fullmatch('0x[0-9a-fA-F]{40}', args.account), 'Final source/testnet account required.')
    need(isinstance(getattr(args, 'api_wallet', None), str)
         and re.fullmatch('0x[0-9a-fA-F]{40}', args.api_wallet), 'Explicit approved public API-wallet address required.')
    private(args.assets, directory=True)
    private(args.binary)
    private(args.pause)
    private(args.assets / '.verified-release-source.json')
    private(args.assets / 'SHA256SUMS')
    marker = json.loads((args.assets / '.verified-release-source.json').read_text())
    need(marker == dict(tag=args.tag, source=args.source), 'Root verified source marker differs.')
    manifest = args.assets / 'SHA256SUMS'
    need(digest(manifest) == args.manifest_sha256, 'Manifest differs from independently verified bytes.')
    entries = {}
    for line in manifest.read_text().splitlines():
        parts = line.split()
        need(len(parts) == 2 and re.fullmatch('[0-9a-f]{64}', parts[0])
             and re.fullmatch('[A-Za-z0-9_-][A-Za-z0-9._-]*', parts[1]) and parts[1] not in entries, 'Malformed manifest.')
        entries[parts[1]] = parts[0]
    machine = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64'}.get(os.uname().machine)
    system = {'Darwin': 'darwin', 'Linux': 'linux'}.get(os.uname().sysname)
    archive = args.assets / f'zunder-guard-{args.tag}-{system}-{machine}.tar.gz'
    private(archive)
    need(archive.name in entries and digest(archive) == entries[archive.name], 'Supported authentic signed archive required.')
    with tarfile.open(archive, 'r:gz') as source:
        member = source.getmember('zunder-guard')
        need(member.isfile() and 0 < member.size <= 256 * 1024 * 1024, 'Invalid archive binary member.')
        with source.extractfile(member) as stream: expected = hashlib.file_digest(stream, 'sha256').hexdigest()
    need(digest(args.binary) == expected, 'Executable differs from actual signed archive; source builds forbidden.')
    pause = json.loads(args.pause.read_text())
    now = time.time()
    observed = datetime.fromisoformat(pause['observed_at'].replace('Z', '+00:00')).timestamp()
    expiry = datetime.fromisoformat(pause['expires_at'].replace('Z', '+00:00')).timestamp()
    need(pause.get('tag') == args.tag and pause.get('source') == args.source
         and pause.get('account_sha256') == hashlib.sha256(args.account.lower().encode()).hexdigest()
         and pause.get('runner_stopped_confirmed') is True and pause.get('exclusive_account_confirmed') is True
         and pause.get('testnet_orders_approved') is True and pause.get('max_notional_usdc') == '40'
         and 0 <= now - observed <= 900 and 120 < expiry - now <= 1800,
         'Fresh parent runner-pause/exclusive-account/approval receipt required.')
    need(not args.work.exists() and args.work.is_absolute(), 'Fresh absolute work directory required; no existing state adoption.')
    args.binary_hash, args.expiry = expected, expiry
    args.work.mkdir(mode=0o700)
    private(args.work, directory=True)
    return dict(tag=args.tag, source=args.source, manifest_sha256=args.manifest_sha256,
                binary_sha256=expected, archive_sha256=entries[archive.name], platform=f'{system}-{machine}',
                account_sha256=hashlib.sha256(args.account.lower().encode()).hexdigest())


def bind_public_api_wallet(args, home):
    """Add only the approved public address to our fresh keyless config before run."""
    need(isinstance(getattr(args, 'api_wallet', None), str)
         and re.fullmatch('0x[0-9a-fA-F]{40}', args.api_wallet), 'Explicit approved public API-wallet address required.')
    private(home, directory=True)
    path = home / 'guard.toml'
    private(path)
    def validate(config):
        clients = config.get('auth', {}).get('clients')
        need(config.get('mode') == 'testnet' and config.get('network') == 'testnet'
             and config.get('allow_mainnet', False) is False and config.get('account') == args.account
             and config.get('listen') == '127.0.0.1:' + str(args.port)
             and isinstance(clients, list) and len(clients) == 1
             and isinstance(clients[0], str) and re.fullmatch('0x[0-9a-fA-F]{40}', clients[0])
             and not (home / 'api-wallet-key').exists(), 'Fresh keyless testnet setup differs.')
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and not stat.S_IMODE(info.st_mode) & 0o077 and 0 < info.st_size <= 128 * 1024,
             'Private fresh config refused.')
        raw = stream.read(128 * 1024 + 1)
        before = tomllib.loads(raw)
        validate(before)
        need('api_wallet' not in before, 'Fresh config already binds an API wallet; never overwrite it.')
        expected = dict(before, api_wallet=args.api_wallet)
        stream.seek(0)
        stream.write('api_wallet = ' + json.dumps(args.api_wallet) + '\n' + raw)
        stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        stream.seek(0)
        after = tomllib.loads(stream.read(128 * 1024 + 128))
        validate(after)
        need(after == expected and after['api_wallet'] == args.api_wallet,
             'Public API-wallet config readback differs.')
    return after


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise RuntimeError('Redirect refused.')


MAX_DEXES = 512
READ_WEIGHTS = {
    'perpDexs': 20, 'userAbstraction': 20, 'clearinghouseState': 2,
    'frontendOpenOrders': 20, 'meta': 20, 'allMids': 2, 'orderStatus': 2,
    # Official maximum 2000 fills: reserve base20 + ceil(2000/20).
    # No refund after small responses, so untrusted response size cannot
    # cause an undercharge. openOrders is20 in the official documentation.
    'userFillsByTime': 120,
}


def json_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def timestamp(value):
    need(isinstance(value, str) and value.endswith('Z') and len(value) <= 40,
         'UTC evidence timestamp required.')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(parsed.utcoffset().total_seconds() == 0, 'UTC evidence timestamp required.')
    return parsed.timestamp()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


class WeightedReads:
    """Initially empty 10weight/s bucket plus strict rolling600/60s ceiling.

    The rolling window closes the extra burst allowance of a plain token
    bucket. Requests are charged before transmission, including failures.
    Sequential caller only; this is not a thread-safe shared IP governor.
    """
    def __init__(self, clock=None, sleep=None):
        self.clock, self.sleep = clock or time.monotonic, sleep or time.sleep
        self.last, self.tokens = self.clock(), 0.0
        self.sent, self.total = deque(), 0

    def acquire(self, weight, deadline=None):
        need(type(weight) is int and 0 < weight <= 120, 'Unsupported bounded read weight.')
        while True:
            now = self.clock()
            self.tokens = min(120.0, self.tokens + max(0, now - self.last) * 10.0)
            self.last = now
            while self.sent and self.sent[0][0] <= now - 60.0:
                _, old = self.sent.popleft(); self.total -= old
            waits = [max(0.0, (weight - self.tokens) / 10.0)]
            if self.total + weight > 600:
                releasing = self.total
                for observed, old in self.sent:
                    releasing -= old
                    if releasing + weight <= 600:
                        waits.append(max(0.0, observed + 60.0 - now) + 0.000001)
                        break
            wait = max(waits)
            need(deadline is None or now + wait + 10 <= deadline,
                 'Bounded public read deadline exhausted; no incomplete flat credit.')
            if wait > 0.000000001:
                self.sleep(wait); continue
            self.tokens -= weight
            self.sent.append((now, weight)); self.total += weight
            return


def dex_inventory(values):
    need(isinstance(values, list) and values and values[0] is None
         and len(values) <= MAX_DEXES, 'Complete bounded dex inventory required.')
    names = ['']
    for value in values[1:]:
        need(isinstance(value, dict) and isinstance(value.get('name'), str)
             and 0 < len(value['name']) <= 128 and value['name'].isprintable()
             and not any(char.isspace() for char in value['name']), 'Invalid dex inventory.')
        names.append(value['name'])
    need(len(names) == len(set(names)), 'Duplicate dex inventory.')
    return names


class Reads:
    def __init__(self, account, *, deadline=None):
        self.account, self.deadline = account, deadline
        self.opener = build_opener(NoRedirect)
        self.budget = WeightedReads()
        self.flat_observation = None

    def json(self, url, payload=None):
        request = Request(url, data=None if payload is None else json.dumps(payload).encode(),
                          headers={'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=10) as response: raw = response.read(1024 * 1024 + 1)
        need(len(raw) <= 1024 * 1024, 'Oversized public response.')
        return json.loads(raw)

    def info(self, kind, **fields):
        need(kind in READ_WEIGHTS and 'type' not in fields, 'Unsupported read.')
        self.budget.acquire(READ_WEIGHTS[kind], self.deadline)
        return self.json(INFO, dict(type=kind, **fields))

    def holdings(self, dex='', *, evidence=False):
        fields = dict(user=self.account, **({'dex': dex} if dex else {}))
        state = self.info('clearinghouseState', **fields)
        orders = self.info('frontendOpenOrders', **fields)
        need(isinstance(state, dict) and isinstance(state.get('assetPositions'), list)
             and isinstance(state.get('marginSummary'), dict) and isinstance(orders, list),
             'Unreadable holdings.')
        positions = []
        for item in state['assetPositions']:
            need(isinstance(item, dict) and isinstance(item.get('position'), dict)
                 and isinstance(item['position'].get('coin'), str)
                 and item['position']['coin'], 'Unreadable position.')
            position = item['position']
            if decimal(position.get('szi')) != 0: positions.append(position)
        equity = decimal(state['marginSummary'].get('accountValue'))
        if evidence:
            return positions, orders, equity, dict(
                dex=dex, observed_at=utc_now(), positions=len(positions),
                open_orders=len(orders), positive_equity=equity > 0,
                clearinghouse_sha256=json_hash(state), frontend_open_orders_sha256=json_hash(orders))
        return positions, orders, equity

    def flat_all(self):
        self.flat_observation = None
        started = utc_now()
        need(self.info('userAbstraction', user=self.account) == 'disabled', 'Standard testnet account required.')
        before = self.info('perpDexs')
        dexes = dex_inventory(before)
        observations = []
        for dex in dexes:
            positions, orders, equity, observation = self.holdings(dex, evidence=True)
            need(not positions and not orders, 'Account not flat; unrelated state is never repaired.')
            if not dex: need(equity > 0, 'Positive existing main-dex testnet equity required; no funding action.')
            observations.append(observation)
        after = self.info('perpDexs')
        need(dex_inventory(after) == dexes, 'Dex inventory changed during flat scan; no incomplete flat credit.')
        self.flat_observation = dict(started_at=started, finished_at=utc_now(),
                                     user_abstraction='disabled', dexes=dexes,
                                     inventory_sha256=json_hash(dexes),
                                     inventory_before_sha256=json_hash(before),
                                     inventory_after_sha256=json_hash(after), observations=observations)
        return True


def parent_flat(args):
    """Adopt ONLY a root's complete first scan, hash-bound by fresh pause.

    This does not replace either the immediate pre-entry scan or final cleanup
    scan, and is not a cryptographic proof of the parent's observations.
    """
    path = getattr(args, 'preflight_flat', None)
    if path is None: return False
    private(path)
    need(path.stat().st_size <= 512 * 1024, 'Oversized parent flat receipt.')
    pause = json.loads(args.pause.read_text())
    need(pause.get('complete_flat_receipt_sha256') == digest(path), 'Parent flat receipt not bound by pause.')
    value = json.loads(path.read_text())
    expected = {'schema', 'kind', 'network', 'tag', 'source', 'manifest_sha256', 'account_sha256',
                'runner_stop_receipt_sha256', 'started_at', 'finished_at', 'user_abstraction', 'dexes',
                'inventory_sha256', 'inventory_before_sha256', 'inventory_after_sha256', 'observations'}
    need(isinstance(value, dict) and set(value) == expected and type(value['schema']) is int
         and value['schema'] == 1 and value['kind'] == 'actual-complete-testnet-flat'
         and value['network'] == 'testnet' and value['tag'] == args.tag and value['source'] == args.source
         and value['manifest_sha256'] == args.manifest_sha256
         and value['account_sha256'] == hashlib.sha256(args.account.lower().encode()).hexdigest()
         and value['user_abstraction'] == 'disabled', 'Parent flat receipt scope differs.')
    for name in ('runner_stop_receipt_sha256', 'inventory_sha256', 'inventory_before_sha256', 'inventory_after_sha256'):
        need(isinstance(value[name], str) and re.fullmatch('[0-9a-f]{64}', value[name]), 'Parent receipt digest malformed.')
    need(pause.get('runner_stop_receipt_sha256') == value['runner_stop_receipt_sha256'],
         'Parent stopped-runner receipt differs from fresh pause.')
    names = value['dexes']
    need(isinstance(names, list) and names and names[0] == '', 'Complete parent dex inventory required.')
    need(dex_inventory([None] + [dict(name=name) for name in names[1:]]) == names
         and json_hash(names) == value['inventory_sha256'], 'Parent dex inventory differs.')
    now = time.time(); started = timestamp(value['started_at']); finished = timestamp(value['finished_at'])
    paused = timestamp(pause['observed_at'])
    need(0 <= now - finished <= 120 and 0 <= finished - started <= 720
         and 0 <= now - started <= 900 and finished <= paused <= now,
         'Parent flat scan is stale or not before fresh pause.')
    observations = value['observations']
    need(isinstance(observations, list) and len(observations) == len(names), 'Incomplete parent flat observations.')
    previous = started
    for name, row in zip(names, observations):
        need(isinstance(row, dict) and set(row) == {'dex', 'observed_at', 'positions', 'open_orders',
             'positive_equity', 'clearinghouse_sha256', 'frontend_open_orders_sha256'}
             and row['dex'] == name and type(row['positions']) is int and row['positions'] == 0
             and type(row['open_orders']) is int and row['open_orders'] == 0
             and type(row['positive_equity']) is bool and (name != '' or row['positive_equity']),
             'Parent flat observations are incomplete or not flat.')
        observed = timestamp(row['observed_at'])
        need(previous <= observed <= finished, 'Parent observations not bounded in scan order.')
        previous = observed
        for field in ('clearinghouse_sha256', 'frontend_open_orders_sha256'):
            need(isinstance(row[field], str) and re.fullmatch('[0-9a-f]{64}', row[field]), 'Parent response hash malformed.')
    return True


def adopted_pre_entry(reads, args):
    """Fresh main-dex/inventory check backed by the recently completed full scan.

    This is not a second full all-dex scan. Only the existing exclusive stopped
    runner/adopted parent scan permits it, with that receipt revalidated after
    Guard startup and again after these fresh public reads.
    """
    need(parent_flat(args), 'A recent complete parent scan is mandatory for adopted pre-entry.')
    pause_hash, flat_hash = digest(args.pause), digest(args.preflight_flat)
    value = json.loads(args.preflight_flat.read_text())
    names = value['dexes']
    started = utc_now()
    need(reads.info('userAbstraction', user=args.account) == 'disabled', 'Standard testnet account required before entry.')
    before = reads.info('perpDexs')
    need(dex_inventory(before) == names, 'Dex inventory changed after complete parent scan.')
    positions, orders, equity, main = reads.holdings(evidence=True)
    need(not positions and not orders and equity > 0, 'Fresh main dex must remain flat with positive existing equity.')
    after = reads.info('perpDexs')
    need(dex_inventory(after) == names, 'Dex inventory changed during fresh main-dex check.')
    need(digest(args.pause) == pause_hash and digest(args.preflight_flat) == flat_hash
         and parent_flat(args), 'Parent scan/pause changed or expired during pre-entry revalidation.')
    # Preserve the original full scan duration/count for conservative cleanup
    # reservation. These times describe the parent scan, not a new all-dex scan.
    reads.flat_observation = dict(dexes=names, started_at=value['started_at'], finished_at=value['finished_at'])
    return dict(kind='adopted-complete-parent-scan-plus-fresh-main-dex-and-inventory',
                parent_complete_flat_receipt_sha256=flat_hash, parent_scan_started_at=value['started_at'],
                parent_scan_finished_at=value['finished_at'], started_at=started, finished_at=utc_now(),
                dex_count=len(names), inventory_sha256=json_hash(names),
                fresh_main_dex=main, second_full_scan_performed=False)


def cleanup_reservation(observed):
    need(isinstance(observed, dict) and isinstance(observed.get('dexes'), list), 'Complete pre-entry inventory required.')
    scan_seconds = (60 + 22 * len(observed['dexes'])) / 10
    if 'finished_at' in observed and 'started_at' in observed:
        elapsed = timestamp(observed['finished_at']) - timestamp(observed['started_at'])
        need(elapsed >= 0, 'Invalid complete scan duration.')
        scan_seconds = max(scan_seconds, elapsed)
    return scan_seconds + 120


class MCP:
    def __init__(self, args, url, client):
        need(digest(args.binary) == args.binary_hash, 'Signed binary changed.')
        self.child = subprocess.Popen([str(args.binary), '--home', str(args.work / 'home'), 'mcp',
                                       '--network', 'testnet', '--guard-url', url, '--key-file', str(client)],
                                      env=SAFE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, start_new_session=True)
        self.sequence = 0
        self.buffer = b''
        try:
            self.call('initialize', dict(protocolVersion='2025-11-25', capabilities={}, clientInfo=dict(name='private-release-check', version='1')))
        except (Exception, KeyboardInterrupt):
            self.stop()
            raise

    def call(self, method, params):
        self.sequence += 1
        wire = dict(jsonrpc='2.0', id=self.sequence, method=method, params=params)
        self.child.stdin.write(json.dumps(wire).encode() + b'\n')
        self.child.stdin.flush()
        end = time.monotonic() + 45
        with selectors.DefaultSelector() as selected:
            selected.register(self.child.stdout, selectors.EVENT_READ)
            while time.monotonic() < end:
                if b'\n' in self.buffer:
                    raw, self.buffer = self.buffer.split(b'\n', 1)
                    value = json.loads(raw)
                    need(value.get('id') == self.sequence and 'error' not in value, 'MCP protocol failure.')
                    return value['result']
                need(self.child.poll() is None, 'MCP process stopped.')
                if selected.select(timeout=1):
                    chunk = os.read(self.child.stdout.fileno(), 65536)
                    need(chunk, 'MCP stream closed.')
                    self.buffer += chunk
                    need(len(self.buffer) <= 1024 * 1024, 'MCP response too large.')
        raise RuntimeError('MCP deadline; no entry retry permitted.')

    def tool(self, name, arguments=None):
        need(name in {'account_overview', 'limits', 'preview_order', 'place_order', 'close_position', 'cancel_order'}, 'Unsupported tool.')
        value = self.call('tools/call', dict(name=name, arguments=arguments or {}))
        return value['structuredContent'], value.get('isError', False)

    def stop(self):
        if self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGTERM)
            try: self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.child.pid, signal.SIGKILL); self.child.wait(timeout=5)
        self.child.stdin.close(); self.child.stdout.close()


def entry_plan(meta, mids):
    rows = [(i, x) for i, x in enumerate(meta['universe']) if x.get('name') == 'BTC']
    need(len(rows) == 1 and rows[0][1].get('isDelisted', False) is False, 'Active BTC market required.')
    asset, market = rows[0]
    places = market['szDecimals']
    need(type(places) is int and 0 <= places <= 6, 'BTC quantity precision refused.')
    mid = decimal(mids['BTC'], positive=True)
    price = (mid * Decimal('1.002')).to_integral_value(rounding=ROUND_DOWN)
    stop = (mid * Decimal('0.98')).to_integral_value(rounding=ROUND_DOWN)
    size = (Decimal('15') / price).quantize(Decimal(1).scaleb(-places), rounding=ROUND_DOWN)
    need(0 < stop < mid <= price and Decimal('10') <= size * price <= Decimal('40'), 'Bounded executable entry unavailable.')
    return asset, dict(coin='BTC', side='buy', stop='guard_policy', size=format(size, 'f'), limit_price=str(price))


def venue_oids(value):
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ('filled', 'resting') and isinstance(item, dict) and type(item.get('oid')) is int:
                result.add(item['oid'])
            result.update(venue_oids(item))
    elif isinstance(value, list):
        for item in value: result.update(venue_oids(item))
    return result


def ownership(events, client, asset, plan):
    decisions = [e for e in events if e.get('kind') == 'decision' and e.get('client', '').lower() == client.lower()
                 and e.get('action') == 'order' and any(o.get('r') is False for o in (e.get('request') or {}).get('orders', []))]
    need(len(decisions) == 1, 'One durable owned entry decision required; never infer ownership from account alone.')
    decision = decisions[0]
    orders = decision['request']['orders']
    entries = [o for o in orders if o.get('r') is False]
    need(len(entries) == 1, 'Exactly one owned entry required.')
    order = entries[0]
    need(order.get('a') == asset and order.get('b') is True and decimal(order['s']) == decimal(plan['size'])
         and decimal(order['p']) == decimal(plan['limit_price']) and re.fullmatch('0x7a6d[0-9a-f]{28}', order.get('c', '')),
         'Durable entry does not match the bounded request.')
    serving = {decision['seq']} | {e['seq'] for e in events if e.get('kind') == 'intent' and e.get('of') == decision['seq']}
    sent = [e for e in events if e.get('kind') == 'sent' and e.get('decision') in serving]
    oids = set().union(*(venue_oids(e.get('reply')) for e in sent)) if sent else set()
    return order['c'], oids


def owned_position(positions, fills, entry_oid, plan):
    matches = [x for x in fills if x.get('oid') == entry_oid]
    need(matches and all(x.get('coin') == 'BTC' and x.get('side') == 'B' for x in matches), 'Actual owned buy fill required.')
    qty = sum((decimal(x['sz'], positive=True) for x in matches), Decimal(0))
    cost = sum((decimal(x['sz'], positive=True) * decimal(x['px'], positive=True) for x in matches), Decimal(0))
    need(qty <= decimal(plan['size']) and cost <= Decimal('40'), 'Owned fill exceeds approved bound.')
    need(len(positions) <= 1 and all(x.get('coin') == 'BTC' and Decimal('0') < decimal(x['szi']) <= qty for x in positions),
         'Position includes unrelated or unbounded exposure; no broad close permitted.')
    return qty


def price_grid(value, sz_decimals, *, up):
    # Exact independently computed counterpart of InstrumentRules::round_price:
    # max(0,min(6-szDecimals,4-floor_log10(price))) decimals, no float money.
    need(type(sz_decimals) is int and 0 <= sz_decimals <= 6 and value > 0, 'Invalid stop price grid.')
    places = max(0, min(6 - sz_decimals, 4 - value.adjusted()))
    return value.quantize(Decimal(1).scaleb(-places), rounding=ROUND_UP if up else ROUND_DOWN)


def durable_stop(events, client, asset, plan, qty, sz_decimals, mark):
    cloid, owned = ownership(events, client, asset, plan)
    decisions = [e for e in events if e.get('kind') == 'decision' and e.get('client', '').lower() == client.lower()
                 and any(o.get('c') == cloid for o in (e.get('request') or {}).get('orders', []))]
    need(len(decisions) == 1, 'One exact durable stop decision required.')
    decision = decisions[0]
    forwarded = decision.get('forward') or {}
    need(forwarded.get('type') == 'order' and forwarded.get('grouping') == 'normalTpsl', 'Durable protected entry group required.')
    opening = [o for o in forwarded.get('orders', []) if o.get('r') is False]
    wires = [o for o in forwarded.get('orders', []) if o.get('r') is True]
    need(len(opening) == 1 and opening[0].get('c') == cloid and len(wires) == 1,
         'Exactly one durable opening and attached protective stop required.')
    need(opening[0].get('a') == asset and opening[0].get('b') is True
         and decimal(opening[0].get('p'), positive=True) == decimal(plan['limit_price'], positive=True),
         'Forwarded entry differs from the durable bounded asset, side or limit.')
    wire = wires[0]
    trigger = (wire.get('t') or {}).get('trigger') or {}
    need(wire.get('a') == asset and wire.get('b') is False and wire.get('r') is True
         and trigger.get('tpsl') == 'sl' and trigger.get('isMarket') is True
         and re.fullmatch('0x7a67[0-9a-f]{28}', wire.get('c', '')),
         'Durable protection is not the owned sell stop-market SL.')
    size, stop, limit = decimal(wire.get('s'), positive=True), decimal(trigger.get('triggerPx'), positive=True), decimal(wire.get('p'), positive=True)
    need(size == decimal(opening[0].get('s'), positive=True) and qty <= size <= decimal(plan['size'], positive=True),
         'Durable stop size does not match its bounded opening and actual fill.')
    # Current source journals the exact fresh reference it used to attach the
    # default stop. Treat this string strictly as numeric evidence, never advice.
    attachment = [re.fullmatch(r'a reduce-only stop at ([0-9]+(?:\.[0-9]+)?) \(2% from ([0-9]+(?:\.[0-9]+)?)\) is attached', text)
                  for text in decision.get('changes', []) if isinstance(text, str)]
    attachment = [match for match in attachment if match]
    need(len(attachment) == 1, 'Exact unchanged two-percent default-stop reference required.')
    recorded_stop, reference = (decimal(value, positive=True) for value in attachment[0].groups())
    need(recorded_stop == stop == price_grid(reference * Decimal('0.98'), sz_decimals, up=True)
         and limit == price_grid(stop * Decimal('0.90'), sz_decimals, up=False)
         and reference <= decimal(opening[0]['p'], positive=True)
         <= price_grid(reference * Decimal('1.005'), sz_decimals, up=False)
         and stop < reference and stop < mark and stop < decimal(opening[0]['p'], positive=True),
         'Durable stop differs from unchanged default, execution limit or losing-side direction.')
    return wire, owned


def validate_stop_order(order, wire):
    trigger = wire['t']['trigger']
    size, stop, limit = decimal(wire['s'], positive=True), decimal(trigger['triggerPx'], positive=True), decimal(wire['p'], positive=True)
    need(type(order.get('oid')) is int and order['oid'] > 0 and order.get('cloid') == wire['c']
         and order.get('coin') == 'BTC' and order.get('side') == 'A'
         and order.get('isTrigger') is True and order.get('reduceOnly') is True
         and order.get('orderType') == 'Stop Market'
         and decimal(order.get('sz'), positive=True) == size
         and decimal(order.get('triggerPx'), positive=True) == stop
         and decimal(order.get('limitPx'), positive=True) == limit,
         'Venue OID/cloid/type/side/quantity/trigger/limit do not match its exact durable SL.')
    if 'triggerCondition' in order:
        direction = re.fullmatch(r'Price below ([0-9]+(?:\.[0-9]+)?)', order['triggerCondition'])
        need(direction and decimal(direction[1], positive=True) == stop, 'Venue trigger direction differs.')


def protected_ack(events, client, asset, plan, entry_oid, stop_oid, *, cleanup=False, resting_only=False):
    """Require the one acknowledged protected entry, including deferred stop ack."""
    cloid, unused = ownership(events, client, asset, plan)
    decisions = [e for e in events if e.get('kind') == 'decision' and e.get('client', '').lower() == client.lower()
                 and any(o.get('c') == cloid for o in (e.get('request') or {}).get('orders', []))]
    need(len(decisions) == 1, 'One acknowledged protected decision required.')
    serving = {decisions[0]['seq']} | {e['seq'] for e in events if e.get('kind') == 'intent' and e.get('of') == decisions[0]['seq']}
    sent = [e for e in events if e.get('kind') == 'sent' and e.get('decision') in serving
            and (e.get('reply') or {}).get('response', {}).get('type') == 'order']
    need(len(sent) == 1 and sent[0].get('ok') is True and sent[0]['reply'].get('status') == 'ok',
         'One successful raw protected order acknowledgement required.')
    statuses = sent[0]['reply']['response'].get('data', {}).get('statuses')
    need(isinstance(statuses, list) and len(statuses) == 2 and isinstance(statuses[0], dict)
         and (set(statuses[0]) == {'filled'} or cleanup and set(statuses[0]) == {'resting'}),
         'Exact owned entry and attached-stop acknowledgement required.')
    need(not resting_only or set(statuses[0]) == {'resting'}, 'Unfilled cleanup requires the exact resting-entry acknowledgement.')
    filled = statuses[0].get('filled', statuses[0].get('resting'))
    need(isinstance(filled, dict) and type(filled.get('oid')) is int and filled['oid'] == entry_oid
         and ('cloid' not in filled or filled['cloid'] == cloid), 'Acknowledged entry OID/cloid differs.')
    stop_ack = statuses[1]
    need(stop_ack == 'waitingForTrigger' or cleanup and stop_ack == 'waitingForFill' or (isinstance(stop_ack, dict) and set(stop_ack) == {'resting'}
         and isinstance(stop_ack['resting'], dict) and type(stop_ack['resting'].get('oid')) is int
         and stop_ack['resting']['oid'] == stop_oid), 'Attached-stop acknowledgement is partial, unknown or inconsistent.')


def protective_stop(events, client, asset, plan, venue_orders, qty, sz_decimals, mark, *, stop_status=None, entry_oid=None, cleanup=False):
    wire, owned = durable_stop(events, client, asset, plan, qty, sz_decimals, mark)
    matches = [order for order in venue_orders if order.get('cloid') == wire['c']]
    need(len(matches) == 1, 'Exactly one actual venue order for the durable stop cloid required.')
    order = matches[0]
    validate_stop_order(order, wire)
    if stop_status is not None:
        need(stop_status.get('status') == 'order' and isinstance(stop_status.get('order'), dict)
             and stop_status['order'].get('status') == 'open'
             and isinstance(stop_status['order'].get('order'), dict), 'Fresh durable stop-cloid lookup must be open.')
        resolved = stop_status['order']['order']
        validate_stop_order(resolved, wire)
        need(resolved['oid'] == order['oid'], 'Stop-cloid lookup OID differs from actual frontend stop.')
        protected_ack(events, client, asset, plan, entry_oid, order['oid'], cleanup=cleanup)
        owned.add(order['oid'])
    need(order['oid'] in owned, 'Stop OID lacks acknowledged or freshly resolved durable ownership.')
    return order


def resolved_ownership(reads, args, events, client, asset, plan, started_ms, sz_decimals, *, cleanup=False):
    """One shared fresh ownership proof for the journey and every cleanup action.

    A waitingForTrigger acknowledgement carries no stop OID. The exact durable
    wire cloid is queried, then its open order and frontend fields are independently
    checked against the unchanged policy wire before adding that OID to ownership.
    """
    cloid, unused = ownership(events, client, asset, plan)
    lookup = reads.info('orderStatus', user=args.account, oid=cloid)
    need(lookup.get('status') == 'order' and isinstance(lookup.get('order'), dict)
         and isinstance(lookup['order'].get('order'), dict), 'Owned entry outcome unknown; no account-wide repair.')
    entry_oid = lookup['order']['order'].get('oid')
    need(type(entry_oid) is int and entry_oid > 0, 'Invalid owned entry OID.')
    fills = reads.info('userFillsByTime', user=args.account, startTime=started_ms)
    positions, orders, unused_equity = reads.holdings()
    matches = [fill for fill in fills if fill.get('oid') == entry_oid]
    if not matches:
        need(cleanup and not positions, 'No proved owned fill; only exact resting-entry cancellation is permitted.')
        wire, unused = durable_stop(events, client, asset, plan, Decimal('0'), sz_decimals, decimal(plan['limit_price'], positive=True))
        decisions = [event for event in events if event.get('kind') == 'decision' and event.get('client', '').lower() == client.lower()
                     and any(order.get('c') == cloid for order in (event.get('request') or {}).get('orders', []))]
        opening = [order for order in decisions[0]['forward']['orders'] if order.get('r') is False][0]
        candidate = lookup['order']['order']
        need(lookup['order'].get('status') == 'open' and len(orders) == 1 and orders[0].get('oid') == entry_oid,
             'Unfilled entry must be the sole exact open venue order.')
        for observed in (candidate, orders[0]):
            need(observed.get('oid') == entry_oid and type(observed['oid']) is int
                 and observed.get('cloid') == cloid and observed.get('coin') == 'BTC' and observed.get('side') == 'B'
                 and observed.get('reduceOnly') is False and observed.get('isTrigger') is False
                 and observed.get('orderType') == 'Limit'
                 and decimal(observed.get('sz'), positive=True) == decimal(opening['s'], positive=True)
                 and decimal(observed.get('limitPx'), positive=True) == decimal(opening['p'], positive=True),
                 'Resting entry does not match exact durable wire/readbacks; no cancellation.')
        # No stop OID is claimed from a deferred acknowledgement. Only the exact
        # proved opening can be cancelled; a racing fill is reconciled again.
        protected_ack(events, client, asset, plan, entry_oid, None, cleanup=True, resting_only=True)
        return cloid, {entry_oid}, entry_oid, Decimal('0'), positions, orders
    qty = owned_position(positions, fills, entry_oid, plan)
    owned = {entry_oid}
    if positions or orders:
        # A flat position may leave its owned stop briefly resting after a close.
        # The immutable journal reference still validates its losing-side wire;
        # the frontend/status readbacks prove exact remaining order ownership.
        mark = abs(decimal(positions[0]['positionValue'], positive=True) / decimal(positions[0]['szi'], positive=True)) if positions else decimal(plan['limit_price'], positive=True)
        wire, unused = durable_stop(events, client, asset, plan, qty, sz_decimals, mark)
        need(cleanup or qty == decimal(wire['s'], positive=True), 'Partial entry fill is not a complete journey proof.')
        stop_status = reads.info('orderStatus', user=args.account, oid=wire['c'])
        stop = protective_stop(events, client, asset, plan, orders, qty, sz_decimals, mark,
                               stop_status=stop_status, entry_oid=entry_oid, cleanup=cleanup)
        owned.add(stop['oid'])
    need(all(type(order.get('oid')) is int and order['oid'] in owned for order in orders),
         'Unrelated order observed; no cancellation or broad cleanup.')
    return cloid, owned, entry_oid, qty, positions, orders


def status(reads, url, args):
    value = reads.json(url + '/guard/status')
    now = int(time.time() * 1000)
    need(value.get('mode') == 'testnet' and value.get('network') == 'testnet'
         and value.get('account', '').lower() == args.account.lower() and value.get('version') == args.tag[1:]
         and value.get('risk', {}).get('state') == 'active' and value['risk'].get('journal_ready') is True
         and value.get('killed') is None and value.get('journal_broken') is False and value.get('last_error') is None
         and type(value.get('last_sync_ms')) is int and type(value.get('started_at_ms')) is int
         and 0 < value['started_at_ms'] <= value['last_sync_ms'] <= now
         and now - value['last_sync_ms'] <= 60000 and decimal(value.get('equity'), positive=True) > 0,
         'Signed current-process synchronized testnet Guard required.')
    return value


def main(args):
    proof = binding(args)
    reads, guard, mcp = Reads(args.account), None, None
    attempted, flat, success, plan, asset = False, False, False, None, None
    home, client = args.work / 'home', args.work / 'client.key'
    home.mkdir(mode=0o700)
    url = 'http://127.0.0.1:' + str(args.port)
    env = dict(SAFE, HOME=str(args.work), ZUNDER_GUARD_HOME=str(home))
    report = dict(kind='actual-signed-testnet-subset', **proof, release_ready=False, cleanup_complete=False,
                  mainnet_actions=False, production_builder_fee_proven=False, api_wallet_key_read_by_runner=False)
    def save():
        target = args.work / 'receipt.json'
        staging = args.work / 'receipt.pending'
        staging.write_text(json.dumps(report, indent=2) + '\n'); staging.chmod(0o600); staging.replace(target)
    save()
    stage = 'preflight_flat'
    try:
        report['parent_complete_flat_adopted'] = parent_flat(args)
        if report['parent_complete_flat_adopted']: report['parent_complete_flat_receipt_sha256'] = digest(args.preflight_flat)
        if not report['parent_complete_flat_adopted']: reads.flat_all()
        save()
        stage = 'signed_init'
        need(digest(args.binary) == args.binary_hash, 'Signed binary changed before init.')
        result = subprocess.run([str(args.binary), '--home', str(home), 'init', '--non-interactive', '--no-key',
                                 '--network', 'testnet', '--rules', 'zr1_eyJ2IjoxfQ', '--account', args.account,
                                 '--listen', '127.0.0.1:' + str(args.port), '--client-key-out', str(client)],
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=60)
        need(result.returncode == 0, 'Signed testnet init failed; output deliberately discarded.')
        private(client)
        config = bind_public_api_wallet(args, home)
        report['public_api_wallet_config_bound'] = True; save()
        client_address = config['auth']['clients'][0]
        started_ms = int(time.time() * 1000)
        guard = subprocess.Popen([str(args.binary), '--home', str(home), 'run', '--network', 'testnet', '--key-stdin'],
                                 env=env, stdin=sys.stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        report['guard_pid'] = guard.pid; save()
        stage = 'guard_readiness'
        end = time.monotonic() + 90
        while time.monotonic() < end:
            need(guard.poll() is None, 'Signed Guard refused its testnet startup.')
            try:
                value = status(reads, url, args)
                need(value['started_at_ms'] >= started_ms, 'Guard status predates this owned process.')
                break
            except (RuntimeError, OSError, ValueError): time.sleep(1)
        else: raise RuntimeError('Signed Guard readiness deadline.')
        stage = 'mcp_prerequisites'
        mcp = MCP(args, url, client)
        for name in ('account_overview', 'limits'):
            body, error = mcp.tool(name); need(not error and body.get('ok') is True, 'MCP read prerequisite failed.')
        stage = 'pre_entry_flat'
        if report['parent_complete_flat_adopted']:
            report['pre_entry_observation'] = adopted_pre_entry(reads, args)
            save()
        else:
            reads.flat_all()  # Non-adopted path retains the complete pre-entry scan.
        stage = 'entry_quote_and_preview'
        metadata = reads.info('meta')
        asset, plan = entry_plan(metadata, reads.info('allMids'))
        sz_decimals = metadata['universe'][asset]['szDecimals']
        preview, error = mcp.tool('preview_order', plan)
        need(not error and preview['preview']['verdict'] in ('allow', 'resize'), 'Risk preview refused bounded entry.')
        cleanup_seconds = cleanup_reservation(reads.flat_observation)
        report['full_all_dex_cleanup_reservation_seconds'] = cleanup_seconds
        need(time.time() < args.expiry - cleanup_seconds, 'Insufficient complete all-dex cleanup margin; no entry.')
        stage = 'entry_submission'
        report['entry_attempted'] = attempted = True; save()
        entry, error = mcp.tool('place_order', plan)  # Never retry opening, even after timeout.
        need(not error and entry.get('sent') is True, 'Actual entry not confirmed; cleanup still runs.')
        report['entry_tool_sent'] = True
        need(any(x.get('status') == 'filled' for x in entry.get('venue_statuses', [])),
             'Entry did not fill immediately; cancel owned resting entry in cleanup.')
        stage = 'entry_readback'
        time.sleep(2)
        events = reads.json(url + '/guard/events?since=0')
        stage = 'resolved_stop_ownership'
        cloid, owned, entry_oid, qty, positions, orders = resolved_ownership(
            reads, args, events, client_address, asset, plan, started_ms, sz_decimals)
        need(positions and positions[0]['leverage']['type'] == 'isolated', 'Actual isolated filled position required.')
        report.update(actual_owned_entry_fill=True, actual_isolated_margin=True, actual_owned_resting_stop=True,
                      signed_guard_and_mcp=True, entry_notional_bounded_40=True)
        success = True
    except (Exception, KeyboardInterrupt):
        report['failure_stage'] = stage
        report['failure_code'] = 'journey_' + stage
        raise
    finally:
        # A second ordinary interrupt must not skip the bounded owned cleanup.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup_stage = 'cleanup_start'
        try:
            if attempted:
                # Stop a hung MCP before cleanup; its sole entry has <=20s request TTL.
                if mcp: mcp.stop(); mcp = None
                time.sleep(25)
                mcp = MCP(args, url, client)
                events = reads.json(url + '/guard/events?since=0')
                cleanup_stage = 'resolve_owned_protection'
                cloid, owned, entry_oid, qty, positions, orders = resolved_ownership(
                    reads, args, events, client_address, asset, plan, started_ms, sz_decimals, cleanup=True)
                cleanup_stage = 'cancel_owned_entry'
                for order in orders:
                    if order.get('reduceOnly') is not True:
                        _, error = mcp.tool('cancel_order', dict(coin='BTC', order_id=order['oid']))
                        need(not error, 'Owned resting entry cancel failed.')
                positions, remaining_orders, _ = reads.holdings()
                need(all(o.get('oid') in owned for o in remaining_orders), 'Unrelated order appeared during owned cleanup.')
                fills = reads.info('userFillsByTime', user=args.account, startTime=started_ms)
                cleanup_stage = 'close_owned_position'
                if positions:
                    cloid, owned, entry_oid, qty, positions, remaining_orders = resolved_ownership(
                        reads, args, events, client_address, asset, plan, started_ms, sz_decimals, cleanup=True)
                    owned_position(positions, fills, entry_oid, plan)
                    _, error = mcp.tool('close_position', dict(coin='BTC'))
                    need(not error, 'Owned reduce-only close was not confirmed.')
                for _ in range(5):
                    positions, orders, _ = reads.holdings()
                    if not positions: break
                    time.sleep(1)
                need(not positions, 'Owned position remains; keep protection and parent intervention required.')
                need(all(o.get('oid') in owned for o in orders), 'Unrelated stop observed; never cancel it.')
                cleanup_stage = 'cancel_owned_orphan_stop'
                if orders:
                    cloid, owned, entry_oid, qty, positions, orders = resolved_ownership(
                        reads, args, events, client_address, asset, plan, started_ms, sz_decimals, cleanup=True)
                    need(not positions, 'Position changed before orphan-stop cancellation; retain protection.')
                for order in orders:
                    _, error = mcp.tool('cancel_order', dict(coin='BTC', order_id=order['oid']))
                    need(not error, 'Owned orphan stop cancel failed.')
            cleanup_stage = 'final_all_dex_flat'
            flat = reads.flat_all()
            report['account_flat_after'] = True
        except (Exception, KeyboardInterrupt):
            report['cleanup_blocked_requires_parent'] = True
            report['cleanup_failure_stage'] = cleanup_stage
            report['cleanup_failure_code'] = 'cleanup_' + cleanup_stage
        if mcp: mcp.stop()
        if guard and (flat or not attempted):
            if guard.poll() is None:
                os.killpg(guard.pid, signal.SIGTERM)
                try: guard.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(guard.pid, signal.SIGKILL); guard.wait(timeout=5)
            report['owned_guard_stopped'] = True
        # Incomplete ownership/flat proof leaves Guard running with protection;
        # parent must reconcile privately, never kill it simply to claim cleanup.
        report.update(cleanup_complete=bool(flat and (guard is None or guard.poll() is not None)),
                      journey_passed=bool(success and flat and (guard is None or guard.poll() is not None)))
        save()
    need(report['journey_passed'], 'Journey or cleanup incomplete.')


if __name__ == '__main__':
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'binary', 'pause', 'work'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('tag', 'source', 'manifest-sha256', 'account', 'api-wallet'): parser.add_argument('--' + name, required=True)
    parser.add_argument('--preflight-flat', type=Path)
    parser.add_argument('--port', type=int, default=18547)
    arguments = parser.parse_args()
    need(1024 <= arguments.port <= 65535, 'Unprivileged loopback port required.')
    def interrupted(*unused): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try: main(arguments)
    except (Exception, KeyboardInterrupt):
        print('Signed testnet journey incomplete; inspect the private redacted receipt and reconcile owned exposure.', file=sys.stderr)
        sys.exit(1)
