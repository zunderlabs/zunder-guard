#!/usr/bin/env python3
"""Render configuration into a new output directory; never calls AWS or GitHub."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
REPO = 'zunderlabs/zunder-guard'
ACCOUNT = '436632189317'
REGION = 'eu-central-1'


def render(commit, wallet, kms_key_arn, destination):
    assert re.fullmatch('[0-9a-f]{40}', commit)
    assert re.fullmatch('0x[0-9a-f]{40}', wallet) and wallet != '0x' + '0' * 40
    assert kms_key_arn == 'alias/aws/ssm' or re.fullmatch(r'arn:aws:kms:eu-central-1:436632189317:key/[0-9a-f-]{36}', kms_key_arn)
    assert destination.is_absolute() and not destination.exists()
    destination.mkdir(mode=0o700)
    def write(name, value):
        text = value if isinstance(value, str) else json.dumps(value, indent=2)+'\n'
        (destination/name).write_text(text); (destination/name).chmod(0o600)
    for name in ('release-e2e.yml', 'release-e2e-run.yml'):
        template = ROOT.parents[2]/'.github/workflows/release-e2e-run.yml' if name == 'release-e2e-run.yml' else ROOT/(name+'.in')
        write(name, template.read_text().replace('AUTOMATION_COMMIT', commit))
    predicate = 'repo:zunderlabs@338317604/zunder-guard@1409357189:environment:release-testnet-e2e'
    trust = dict(Version='2012-10-17', Statement=[dict(Effect='Allow', Principal={'Federated': 'arn:aws:iam::'+ACCOUNT+':oidc-provider/token.actions.githubusercontent.com'},
        Action='sts:AssumeRoleWithWebIdentity', Condition={'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com', 'token.actions.githubusercontent.com:sub': predicate}})])
    write('aws-trust-policy.json', trust)
    statements = [
        dict(Sid='ExactTestnetKey', Effect='Allow', Action=['ssm:GetParameter'], Resource=['arn:aws:ssm:'+REGION+':'+ACCOUNT+':parameter/zunder/testnet/api-wallet-key']),
        dict(Sid='FixedDocument', Effect='Allow', Action=['ssm:SendCommand'], Resource=['arn:aws:ssm:'+REGION+':'+ACCOUNT+':document/ZunderReleaseTestnetControl', 'arn:aws:ec2:'+REGION+':'+ACCOUNT+':instance/i-0ca66c349ad743928']),
        dict(Sid='CommandReadback', Effect='Allow', Action=['ssm:GetCommandInvocation'], Resource='*', Condition={'StringEquals': {'aws:RequestedRegion': REGION}}),
        dict(Sid='DenySecretMutationAndOtherSecrets', Effect='Deny', Action=['ssm:PutParameter', 'ssm:DeleteParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath', 'ssm:GetParameterHistory', 'secretsmanager:*'], Resource='*'),
        dict(Sid='DenyMainnetParameter', Effect='Deny', Action=['ssm:GetParameter'], NotResource=['arn:aws:ssm:'+REGION+':'+ACCOUNT+':parameter/zunder/testnet/api-wallet-key'])
    ]
    if kms_key_arn != 'alias/aws/ssm':
        statements.append(dict(Sid='DecryptExactTestnetKeyOnly', Effect='Allow', Action=['kms:Decrypt'], Resource=[kms_key_arn],
            Condition={'StringEquals': {'kms:ViaService':'ssm.'+REGION+'.amazonaws.com','kms:EncryptionContext:PARAMETER_ARN':'arn:aws:ssm:'+REGION+':'+ACCOUNT+':parameter/zunder/testnet/api-wallet-key'}}))
    write('aws-permissions-policy.json', dict(Version='2012-10-17', Statement=statements))
    write('oidc-expected-claims.json',dict(use_default=True,use_immutable_subject=True,
          audience='sts.amazonaws.com',subject=predicate,aws_credential_trust_scope='canonical-repository-and-environment',
          evidence_workflow_ref=REPO+'/.github/workflows/release-e2e-run.yml@'+commit,
          evidence_policy_commit=commit))
    files = ['orchestrator.py','journey.py','scan.py','verify-release-assets.sh','actions-artifacts.py','staged-subjects.py']
    p = dict(schema=1, automation_commit_source='authenticated-reusable-workflow-claim',
             aws_credential_trust_scope='canonical-repository-and-environment',approved_public_api_wallet=wallet,
             ssm_document_sha256=hashlib.sha256((ROOT/'ssm-document.json').read_bytes()).hexdigest(),
             files={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files})
    write('policy.json',p)
    write('host-policy.json',dict(unit='zunder-exec-testnet.service',
          lease_path='/var/lib/zunder-release-e2e/lease.json',
          dropin_path='/etc/systemd/system/zunder-exec-testnet.service.d/release-lease.conf',
          dropin_sha256=hashlib.sha256((ROOT/'runner-lease.conf').read_bytes()).hexdigest(),
          host_control_sha256=hashlib.sha256((ROOT/'host-control.py').read_bytes()).hexdigest(),
          journey_sha256=p['files']['journey.py']))


if __name__ == '__main__':
    os.umask(0o077)
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--automation-commit',required=True);a.add_argument('--public-api-wallet',required=True)
    a.add_argument('--kms-key-arn',required=True);a.add_argument('--destination',type=Path,required=True)
    x=a.parse_args();render(x.automation_commit,x.public_api_wallet,x.kms_key_arn,x.destination)
