#!/usr/bin/env python3
"""Public TESTNET flat scanner; never reads keys or sends orders."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import journey as j


def scan(args):
    j.need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.tag) and re.fullmatch('[0-9a-f]{40}', args.source)
           and re.fullmatch('[0-9a-f]{64}', args.manifest_sha256)
           and re.fullmatch('0x[0-9a-fA-F]{40}', args.account), 'Exact release and public account required.')
    j.private(args.runner_stop)
    j.need(args.runner_stop.stat().st_size <= 64 * 1024, 'Oversized stopped-runner receipt.')
    stop_bytes = args.runner_stop.read_bytes()
    stop_digest = hashlib.sha256(stop_bytes).hexdigest()
    stop = json.loads(stop_bytes)
    j.need(j.digest(args.runner_stop) == stop_digest, 'Stopped-runner receipt changed during admission.')
    account_hash = hashlib.sha256(args.account.lower().encode()).hexdigest()
    j.need(isinstance(stop, dict) and stop.get('schema') == 1
           and stop.get('kind') == 'actual-testnet-runner-stop' and stop.get('network') == 'testnet'
           and stop.get('tag') == args.tag and stop.get('source') == args.source
           and stop.get('account_sha256') == account_hash
           and stop.get('runner_stopped_confirmed') is True and stop.get('exclusive_account_confirmed') is True
           and stop.get('service') == 'zunder-exec-testnet'
           and isinstance(stop.get('instance_id'), str) and re.fullmatch('i-[0-9a-f]{17}', stop['instance_id'])
           and 0 <= time.time() - j.timestamp(stop.get('observed_at')) <= 120,
           'Fresh root-observed stopped/exclusive testnet runner required.')
    j.need(args.receipt.is_absolute() and not args.receipt.exists(), 'Fresh absolute receipt path required.')
    j.private(args.receipt.parent, directory=True)
    reads = j.Reads(args.account, deadline=time.monotonic() + 720)
    reads.flat_all()
    j.private(args.runner_stop)
    j.need(j.digest(args.runner_stop) == stop_digest, 'Stopped-runner receipt changed during scan.')
    value = dict(schema=1, kind='actual-complete-testnet-flat', network='testnet', tag=args.tag,
                 source=args.source, manifest_sha256=args.manifest_sha256, account_sha256=account_hash,
                 runner_stop_receipt_sha256=stop_digest, **reads.flat_observation)
    # Create only after every DEX passed and the second inventory was unchanged.
    fd = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(value, indent=2) + '\n'); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps(dict(result='complete-flat', dex_count=len(value['dexes']),
                          receipt_sha256=j.digest(args.receipt), finished_at=value['finished_at'])))


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runner-stop', 'receipt'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('tag', 'source', 'manifest-sha256', 'account'): parser.add_argument('--' + name, required=True)
    try: scan(parser.parse_args())
    except (Exception, KeyboardInterrupt):
        print('Complete testnet flat scan failed; no passing receipt produced. Root must retain the runner pause.', file=sys.stderr)
        sys.exit(1)
