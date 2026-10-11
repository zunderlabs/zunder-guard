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
    entries = []
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]cloudformation\.yaml', line)
        if match:
            entries.append(match.group(1).lower())
    if len(entries) != 1:
        raise ValueError('Signed SHA256SUMS must contain exactly one cloudformation.yaml entry')
    template = directory / 'cloudformation.yaml'
    digest = hashlib.sha256(template.read_bytes()).hexdigest()
    if digest != entries[0]:
        raise ValueError('Template differs from signed release checksum')
    return template, digest


def publish(directory, tag, bucket, region):
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('Only stable vX.Y.Z release tags may publish templates')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', bucket):
        raise ValueError('Use a DNS-compatible S3 bucket name without dots')
    if not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]+', region):
        raise ValueError('Invalid commercial AWS region')
    template, digest = checked_template(directory)
    key = f'guard/{tag}/cloudformation.yaml'
    checksum = base64.b64encode(bytes.fromhex(digest)).decode('ascii')
    common = ['aws', '--region', region, '--no-cli-pager', 's3api']
    result = subprocess.run(common + [
        'put-object', '--bucket', bucket, '--key', key, '--body', str(template),
        '--if-none-match', '*', '--checksum-algorithm', 'SHA256',
        '--checksum-sha256', checksum, '--content-type', 'application/yaml',
        '--cache-control', 'public,max-age=31536000,immutable',
    ], capture_output=True, text=True, check=False)
    if result.returncode and '(PreconditionFailed)' not in result.stderr:
        raise RuntimeError('S3 conditional upload failed: ' + result.stderr.strip())
    # A retry may reuse identical bytes, but may never overwrite a published version.
    with tempfile.TemporaryDirectory(prefix='guard-template-') as temporary:
        downloaded = Path(temporary) / 'cloudformation.yaml'
        subprocess.run(common + ['get-object', '--bucket', bucket, '--key', key,
                                  str(downloaded)], check=True, stdout=subprocess.DEVNULL)
        if hashlib.sha256(downloaded.read_bytes()).hexdigest() != digest:
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
    args = parser.parse_args()
    publish(args.release_dir, os.environ.get('TAG', ''),
            os.environ.get('AWS_TEMPLATE_BUCKET', ''),
            os.environ.get('AWS_REGION', 'ap-northeast-1'))
