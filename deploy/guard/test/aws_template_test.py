#!/usr/bin/env python3
"""Exercise the actual CloudFormation bootstrap with isolated external-command fakes."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import yaml

class CfnLoader(yaml.SafeLoader):
    pass

def intrinsic(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag: value}

CfnLoader.add_multi_constructor('!', intrinsic)
TEMPLATE = Path(__file__).resolve().parents[1] / 'templates/cloudformation.yaml'
DOC = yaml.load(TEMPLATE.read_text(), Loader=CfnLoader)
RULES = 'zr1_eyJ2IjoxfQ'
ACCOUNT = '0x' + '1' * 40

class AwsTemplate(unittest.TestCase):
    def test_public_ingress_is_one_valid_ipv4_only(self):
        pattern = DOC['Parameters']['AllowedCidr']['AllowedPattern']
        for value in ['192.0.2.1/32', '255.255.255.255/32', '1.2.3.4/32']:
            self.assertIsNotNone(re.fullmatch(pattern, value), value)
        for value in ['0.0.0.0/0', '1.2.3.4/0', '10.0.0.0/8', '256.1.1.1/32', '1.2.3.4/33']:
            self.assertIsNone(re.fullmatch(pattern, value), value)
        self.assertEqual(DOC['Parameters']['ExposePort']['Default'], 'no')

    def test_own_network_and_retained_encrypted_tagged_disk(self):
        resources = DOC['Resources']
        self.assertEqual(resources['Instance']['Properties']['SubnetId'], {'Ref': 'Subnet'})
        self.assertEqual(resources['SecurityGroup']['Properties']['VpcId'], {'Ref': 'Vpc'})
        self.assertEqual(set(resources['Instance']['DependsOn']), {'InternetRoute', 'SubnetRoute'})
        launch = resources['LaunchTemplate']['Properties']['LaunchTemplateData']
        disk = launch['BlockDeviceMappings'][0]['Ebs']
        self.assertTrue(disk['Encrypted'])
        self.assertFalse(disk['DeleteOnTermination'])
        self.assertEqual(launch['TagSpecifications'][0]['ResourceType'], 'volume')
        self.assertEqual(launch['MetadataOptions']['HttpTokens'], 'required')

    def test_instance_can_signal_own_stack_and_open_sessions_but_not_read_parameters(self):
        role = DOC['Resources']['Role']['Properties']
        self.assertNotIn('ManagedPolicyArns', role)
        statements = [s for p in role['Policies'] for s in p['PolicyDocument']['Statement']]
        actions = {a for s in statements for a in ([s['Action']] if isinstance(s['Action'], str) else s['Action'])}
        self.assertEqual(actions, {'ssm:UpdateInstanceInformation', 'ssmmessages:CreateControlChannel',
            'ssmmessages:CreateDataChannel', 'ssmmessages:OpenControlChannel',
            'ssmmessages:OpenDataChannel', 'cloudformation:SignalResource'})
        signal = next(s for s in statements if s['Action'] == 'cloudformation:SignalResource')
        self.assertEqual(signal['Resource'], {'Ref': 'AWS::StackId'})

    def test_bootstrap_signals_success_only_after_healthy_paper_install(self):
        script = DOC['Resources']['Instance']['Properties']['UserData']['Fn::Base64']['Sub'][0]
        for name, value in {'AWS::Region': 'ap-northeast-1', 'AWS::StackId': 'test-stack',
                            'Rules': RULES, 'Account': ACCOUNT, 'ListenArg': ''}.items():
            script = script.replace('${' + name + '}', value)
        for failure in ['', 'download', 'sh', 'systemctl', 'health', 'aws', 'apt-get']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                tmp = Path(directory)
                wrapper = tmp / 'fake'
                wrapper.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['AWS_TEST_LOG'], 'a') as log:
    log.write(json.dumps([name] + args) + '\\n')
operation = ('download' if '-o' in args else 'health') if name == 'curl' else name
if name == 'sh':
    print('FIXTURE-PAIRING-CREDENTIAL')
    print('FIXTURE-PAIRING-CREDENTIAL-STDERR', file=sys.stderr)
if operation == os.environ['AWS_TEST_FAIL']:
    sys.exit(17)
if operation == 'download':
    pathlib.Path(args[args.index('-o') + 1]).write_text('# fake installer')
''')
                wrapper.chmod(0o755)
                for command in ['apt-get', 'curl', 'sh', 'systemctl', 'aws']:
                    (tmp / command).symlink_to(wrapper)
                log = tmp / 'calls.jsonl'
                env = dict(os.environ, PATH=str(tmp) + os.pathsep + os.environ['PATH'],
                           AWS_TEST_LOG=str(log), AWS_TEST_FAIL=failure)
                result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, timeout=10)
                self.assertNotIn('FIXTURE-PAIRING-CREDENTIAL', result.stdout + result.stderr)
                diagnostic = re.search(r'root-only file (\S+);', result.stdout)
                if diagnostic:
                    private_log = Path(diagnostic.group(1))
                    self.assertEqual(private_log.stat().st_mode & 0o777, 0o600)
                    private_log.unlink()
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                signals = [call for call in calls if call[0] == 'aws']
                if failure == 'apt-get':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(signals, [])  # CloudFormation times out if dependencies cannot install.
                    continue
                self.assertEqual(len(signals), 1)
                self.assertEqual(signals[0][-1], 'FAILURE' if failure and failure != 'aws' else 'SUCCESS')
                self.assertEqual(result.returncode == 0, not failure, result.stderr)
                if not failure:
                    install = next(call for call in calls if call[0] == 'sh')
                    self.assertEqual(install[2:], ['--non-interactive', '--network', 'paper', '--rules', RULES, '--account', ACCOUNT])
                    self.assertLess(next(i for i,c in enumerate(calls) if c[0] == 'systemctl'), len(calls)-1)

if __name__ == '__main__':
    unittest.main(verbosity=2)
