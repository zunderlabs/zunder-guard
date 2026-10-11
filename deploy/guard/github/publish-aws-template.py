#!/usr/bin/env python3
"""Publish an already signature-verified release template, never checkout's template.

The publish workflow verifies SHA256SUMS with the release workflow's Sigstore identity.
This second check requires exactly one signed entry for this asset, uses conditional S3
creation, and checks both authenticated and anonymous downloads before reporting a URL.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request


def checked_template(directory):
    checksums = directory / 'SHA256SUMS'
    if checksums.is_symlink() or not checksums.is_file():
        raise ValueError('Checksums must be a regular release file')
    with checksums.open('rb') as stream:
        inventory = stream.read(65537)
    if not 0 < len(inventory) <= 65536:
        raise ValueError('Checksum inventory exceeds release bound')
    entries = []
    for line in inventory.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]cloudformation\.yaml', line)
        if match:
            entries.append(match.group(1).lower())
    if len(entries) != 1:
        raise ValueError('Signed SHA256SUMS must contain exactly one cloudformation.yaml entry')
    template = directory / 'cloudformation.yaml'
    if template.is_symlink() or not template.is_file():
        raise ValueError('Template must be a regular release file')
    with template.open('rb') as stream:
        captured = stream.read(1024 * 1024 + 1)
    if not 0 < len(captured) <= 1024 * 1024:
        raise ValueError('Template exceeds release size bound')
    digest = hashlib.sha256(captured).hexdigest()
    if digest != entries[0]:
        raise ValueError('Template differs from signed release checksum')
    return captured, digest


def publish(directory, tag, bucket, region, *, staging=False):
    pattern = r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
    if staging:
        pattern += r'(?:-rc\.[1-9][0-9]*)?'
    if not re.fullmatch(pattern, tag):
        raise ValueError('Expected stable release tag, or -rc.N with explicit staging')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', bucket):
        raise ValueError('Use a DNS-compatible S3 bucket name without dots')
    if not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]+', region):
        raise ValueError('Invalid commercial AWS region')
    captured, digest = checked_template(directory)
    key = f'guard/{tag}/cloudformation.yaml'
    checksum = base64.b64encode(bytes.fromhex(digest)).decode('ascii')
    common = ['aws', '--region', region, '--no-cli-pager', 's3api']
    with tempfile.TemporaryDirectory(prefix='guard-template-') as temporary:
        # Upload the exact captured/checksummed bytes, never reopen the replaceable source.
        template = Path(temporary) / 'subject.yaml'
        with template.open('xb') as stream:
            template.chmod(0o600)
            stream.write(captured)
        result = subprocess.run(common + [
            'put-object', '--bucket', bucket, '--key', key, '--body', str(template),
            '--if-none-match', '*', '--checksum-algorithm', 'SHA256',
            '--checksum-sha256', checksum, '--content-type', 'application/yaml',
            '--cache-control', 'public,max-age=31536000,immutable',
        ], capture_output=True, text=True, check=False, timeout=60)
        if result.returncode and '(PreconditionFailed)' not in result.stderr:
            # AWS diagnostics can contain request details; never propagate them to CI logs.
            raise RuntimeError('S3 conditional upload failed; inspect protected publisher logs')
        # A retry may reuse identical bytes, but cannot overwrite a published version.
        downloaded = Path(temporary) / 'cloudformation.yaml'
        subprocess.run(common + ['get-object', '--bucket', bucket, '--key', key,
                                  str(downloaded)], check=True, capture_output=True, timeout=60)
        with downloaded.open('rb') as stream:
            stored = stream.read(1024 * 1024 + 1)
        if hashlib.sha256(stored).hexdigest() != digest:
            raise ValueError('Versioned S3 key contains different bytes; refusing overwrite')
    url = f'https://{bucket}.s3.{region}.amazonaws.com/{key}'
    with urllib.request.urlopen(url, timeout=30) as response:
        public_bytes = response.read(1024 * 1024 + 1)
    if hashlib.sha256(public_bytes).hexdigest() != digest:
        raise ValueError('Anonymous S3 download differs from signed release template')
    # Success means this URL is accessible without publisher credentials.
    print(url)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as output:
            output.write(f'### AWS template published\n\n[{tag} CloudFormation template]({url})\n\n'
                         f'SHA256: `{digest}`. Authenticated and public bytes verified.\n'
                         'Website launch controls remain gated on the separate release checks.\n')
    return url


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, required=True)
    parser.add_argument('--staging', action='store_true',
                        help='Allow RC tags at their immutable version key; no canonical change')
    args = parser.parse_args()
    publish(args.release_dir, os.environ.get('TAG', ''),
            os.environ.get('AWS_TEMPLATE_BUCKET', ''),
            os.environ.get('AWS_REGION', 'ap-northeast-1'), staging=args.staging)
