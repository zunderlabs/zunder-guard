#!/usr/bin/env python3
"""Trusted public Cloudflare controller; private artifact bytes remain inert data."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


admit = module('delivery_admission', 'admit.py')
cloud = module('delivery_cloud', 'cloud_delivery.py')


def boundary(identifier, target, environment):
    admit.require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', identifier)
                  and target in cloud.PROJECTS | {'customer-worker-production': None}
                  and environment.get('GITHUB_REPOSITORY') == admit.PUBLIC_REPOSITORY
                  and environment.get('GITHUB_REF') == 'refs/heads/main'
                  and environment.get('GITHUB_REF_TYPE') == 'branch'
                  and environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Public dispatch required')
    path = HERE / 'admissions' / (identifier + '.json')
    admit.require(path.is_file() and not path.is_symlink(), 'Installed admission required')
    return admit.load_pin(json.loads(path.read_bytes()), identifier, target)


def deliver(pin, policy, github, public_token, publish, environment):
    payload = admit.acquire(pin, github, public_token)
    cloud.checked_payload(pin, payload)
    target = pin['target']
    if not publish:
        if target in cloud.PROJECTS:
            plan = cloud.prepare_pages(pin, payload, policy)
            cloud.complete_release_gate(plan['pin'], public_token)
        else:
            cloud.prepare_worker(pin, payload, policy)
        return {'schema': 1, 'admission': pin['id'], 'target': target,
                'sourceCommit': pin['sourceCommit'], 'inventorySha256': pin['inventorySha256'], 'applied': False}

    def recheck():
        # Re-read immutable archive, API metadata/latest attempt and current public main.
        admit.require(admit.acquire(pin, github, public_token) == payload, 'Candidate changed before write')

    token = environment.get('CLOUDFLARE_API_TOKEN')
    admit.require(bool(token), 'Scoped publisher grant required')
    api = cloud.Cloudflare(token)
    if target in cloud.PROJECTS:
        access = None
        if target != 'website-production':
            access = {'CF-Access-Client-Id': environment.get('ACCESS_CLIENT_ID'),
                      'CF-Access-Client-Secret': environment.get('ACCESS_CLIENT_SECRET')}
            admit.require(all(access.values()), 'Authenticated preview/staging smoke required')
        result = cloud.publish_pages(pin, payload, policy, api, public_token, token, access, recheck)
    else:
        result = cloud.publish_worker(pin, payload, policy, api, recheck)
    return {'schema': 1, 'admission': pin['id'], 'applied': True, **result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('admission_id')
    parser.add_argument('target', choices=[*cloud.PROJECTS, 'customer-worker-production'])
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    pin = boundary(args.admission_id, args.target, os.environ)
    public_token, private_token = os.environ.get('GITHUB_TOKEN'), os.environ.get('PRIVATE_ARTIFACT_READ_TOKEN')
    admit.require(bool(public_token) and bool(private_token), 'Separate public/private read grants required')
    print(json.dumps(deliver(pin, cloud.reviewed_policy(args.target), admit.GitHub(private_token),
                             public_token, args.publish, os.environ)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Hosted delivery stopped; reconcile the admitted target before retrying. Provider and private details withheld.', file=sys.stderr)
        sys.exit(1)
