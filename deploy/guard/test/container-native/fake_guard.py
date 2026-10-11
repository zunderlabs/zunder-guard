"""Synthetic process fixture: reads stdin, serves local health; cannot access a venue."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
from pathlib import Path
import sys

ACCOUNT = '0x' + 'b' * 40
KEY_HASH = hashlib.sha256(b'ab' * 32).hexdigest()
STATE = Path('/data/state.json')
STARTS = Path('/data/starts.jsonl')


def check_key():
    text = sys.stdin.buffer.readline(256).strip()
    if hashlib.sha256(text).hexdigest() != KEY_HASH:
        raise SystemExit('fixture credential refused')


def clean_shutdown(_signal, _frame):
    # Match production Guard: SIGTERM drains its work and returns success.
    raise SystemExit(0)


def main():
    args = sys.argv[1:]
    state = json.loads(STATE.read_text())
    if state['account'] != ACCOUNT or state['mode'] != 'mainnet':
        raise SystemExit('fixture state refused')
    if args == ['config', 'get', 'mode']:
        print('mainnet')
    elif args == ['config', 'get', 'account']:
        print(ACCOUNT)
    elif args == ['check-config']:
        pass
    elif args == ['key', 'check', '--key-stdin']:
        check_key()
        print('0x' + 'c' * 40)
    elif args == ['run', '--network', 'mainnet', '--key-stdin']:
        signal.signal(signal.SIGTERM, clean_shutdown)
        if os.environ.get('ZUNDER_MAINNET_CONFIRM') != ACCOUNT:
            raise SystemExit('fixture confirmation refused')
        check_key()
        seq = len(STARTS.read_text().splitlines()) + 1 if STARTS.exists() else 1
        record = dict(sequence=seq, key_sha256=KEY_HASH, account=ACCOUNT,
                      state_sha256=hashlib.sha256(STATE.read_bytes()).hexdigest(), uid=os.getuid())
        with STARTS.open('a') as stream:
            stream.write(json.dumps(record) + '\n')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                if self.path == '/crash':
                    os._exit(23)
                body = json.dumps(record).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        HTTPServer(('0.0.0.0', 8547), Handler).serve_forever()
    else:
        raise SystemExit('unexpected fixture command')


if __name__ == '__main__':
    main()
