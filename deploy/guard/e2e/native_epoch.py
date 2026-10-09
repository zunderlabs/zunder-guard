"""Encrypted, source-bound native Testnet custody; no operation on import.

An approved fresh API signer is necessary for the shipped daemon. This lane never
places venue orders. Owner approval/revocation belongs to the root controller,
never to a native host. Timestamp metadata is neither deletion nor revocation.
"""
import json
import logging
import re
import time
from release_flow import need
OWNER = '0x0d708cfc4316b58f4ab00ee641a54baacc89cb14'
KMS = 'arn:aws:kms:eu-central-1:436632189317:key/20d7fdda-950b-4101-a391-b3749f892939'
PREFIX = '/zunder/testnet/e2e/epochs/'
REGION = 'eu-central-1'
ACCOUNT = '436632189317'
SCOPE = 'native-key-custody-zero-orders'
FIELDS = {'run_id', 'attempt', 'source', 'agent', 'owner', 'started_ms',
          'approval_until_ms', 'cleanup_until_ms', 'scope', 'agent_approved'}


def binding(value, now=None, cleanup=False):
    now = int(time.time()*1000) if now is None else now
    need(type(value) is dict and set(value) == FIELDS, 'Exact native custody epoch required')
    need(type(value['run_id']) is int and value['run_id'] > 0
         and type(value['attempt']) is int and 1 <= value['attempt'] <= 100,
         'Exact native run/attempt required')
    need(type(value['source']) is str and re.fullmatch('[0-9a-f]{40}', value['source'])
         and type(value['agent']) is str and re.fullmatch('0x[0-9a-f]{40}', value['agent'])
         and value['agent'] not in (OWNER, '0x'+'0'*40) and value['owner'] == OWNER
         and value['scope'] == SCOPE and value['agent_approved'] is True,
         'Approved native zero-order agent identity differs')
    need(all(type(value[name]) is int for name in ('started_ms', 'approval_until_ms', 'cleanup_until_ms'))
         and 0 <= value['started_ms'] <= now
         and value['approval_until_ms'] == value['started_ms']+3600000
         and value['cleanup_until_ms'] == value['started_ms']+4500000,
         'Native approval must be exactly 60 minutes with absolute 75-minute cleanup')
    if not cleanup:
        need(now < value['approval_until_ms'], 'Native custody admission expired; cleanup only')
    return dict(value)


def name_for(value):
    return PREFIX+str(value['run_id'])+'-'+str(value['attempt'])+'/api-agent'


def envelope(value, key):
    need(type(key) is str and re.fullmatch('0x[0-9a-f]{64}', key)
         and key != '0x'+'0'*64, 'Memory-only native signer required')
    return json.dumps({'schema': 1, 'binding': value, 'api_private_key': key},
                      sort_keys=True, separators=(',', ':'))


def tags(value):
    return [{'Key': key, 'Value': text} for key, text in sorted({
        'Scope': SCOPE, 'Owner': OWNER, 'Run': str(value['run_id']), 'Attempt': str(value['attempt']),
        'Source': value['source'], 'Agent': value['agent'],
        'Expires': str(value['approval_until_ms']), 'CleanupUntil': str(value['cleanup_until_ms'])}.items())]


def metadata(client, value):
    name = name_for(value)
    response = client.describe_parameters(ParameterFilters=[{'Key': 'Name', 'Option': 'Equals', 'Values': [name]}])
    entries = response.get('Parameters')
    need(type(entries) is list and len(entries) == 1 and 'NextToken' not in response
         and entries[0].get('Name') == name and entries[0].get('Type') == 'SecureString'
         and type(entries[0].get('Version')) is int and entries[0]['Version'] == 1
         and entries[0].get('Tier') == 'Standard'
         and entries[0].get('KeyId') in (KMS, KMS.rsplit('/', 1)[1]), 'Original native epoch metadata differs')
    observed = client.list_tags_for_resource(ResourceType='Parameter', ResourceId=name).get('TagList')
    need(type(observed) is list and all(type(row) is dict and set(row) == {'Key', 'Value'} for row in observed)
         and sorted(observed, key=lambda row: row['Key']) == tags(value), 'Original native epoch tags differ')


def private_diagnostics():
    # Child SDK loggers may override a safe parent. Inspect every existing
    # descendant, and recheck immediately before each secret-bearing call.
    for name in ('', 'boto3', 'botocore', 'urllib3'):
        need(logging.getLogger(name).getEffectiveLevel() >= logging.WARNING,
             'AWS private SDK diagnostics refused')
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and any(name.startswith(prefix+'.') for prefix in ('boto3','botocore','urllib3')):
            need(logger.getEffectiveLevel() >= logging.WARNING, 'AWS private SDK descendant diagnostics refused')


def sdk_client(session):
    """Caller supplies existing authenticated session; no credentials are emitted."""
    from botocore.config import Config
    # Botocore DEBUG captures request bodies. Refuse rather than silently disable
    # an inherited diagnostic handler before any private request is made.
    private_diagnostics()
    config = Config(region_name=REGION, retries={'total_max_attempts': 1, 'mode': 'standard'},
                    connect_timeout=10, read_timeout=15, proxies={})
    sts = session.client('sts', region_name=REGION, endpoint_url='https://sts.eu-central-1.amazonaws.com', config=config)
    identity = sts.get_caller_identity()
    need(identity.get('Account') == ACCOUNT and type(identity.get('Arn')) is str,
         'Exact native AWS account required')
    client = session.client('ssm', region_name=REGION,
                            endpoint_url='https://ssm.eu-central-1.amazonaws.com', config=config)
    private_diagnostics()
    return client


def put(client, value, key, derive_address):
    value = binding(value)
    need(derive_address(key).lower() == value['agent'], 'Parent-derived native API identity differs')
    private_diagnostics()
    name = name_for(value); payload = envelope(value, key)
    try:
        reply = client.put_parameter(Name=name, Value=payload, Type='SecureString', KeyId=KMS,
                                     Tier='Standard', Overwrite=False, Tags=tags(value))
    except Exception:
        raise RuntimeError('Native epoch write unknown/refused; reconcile exact original name, never retry under a new name') from None
    finally:
        payload = None
    need(type(reply.get('Version')) is int and reply['Version'] == 1,
         'Native epoch version differs; reconcile exact original name')
    metadata(client, value)
    return {'schema': 1, 'kind': 'actual-encrypted-native-epoch-write', 'name': name, 'version': 1,
            'binding': value, 'tags': tags(value), 'cleanup_complete': False, 'release_ready': False}


def get(client, value, derive_address):
    value = binding(value); name = name_for(value)
    try:
        metadata(client, value)  # Public identity/tags checked before decryption.
        private_diagnostics()
        result = client.get_parameter(Name=name+':1', WithDecryption=True).get('Parameter', {})
        need(result.get('Name') == name and result.get('ARN') == 'arn:aws:ssm:'+REGION+':'+ACCOUNT+':parameter'+name
             and result.get('Type') == 'SecureString' and type(result.get('Version')) is int and result['Version'] == 1,
             'Exact native epoch custody identity differs')
        data = json.loads(result['Value']); result.clear()
        need(type(data) is dict and set(data) == {'schema', 'binding', 'api_private_key'}
             and type(data['schema']) is int and data['schema'] == 1 and data['binding'] == value,
             'Native epoch payload binding differs')
        key = data.pop('api_private_key'); data.clear(); envelope(value, key)
        need(derive_address(key).lower() == value['agent'], 'Native provider derived address differs')
        binding(value)  # Retrieval may have crossed the admission deadline.
        return key
    except Exception:
        raise RuntimeError('Native epoch read refused; never substitute another key or owner custody') from None


def delete_after_cleanup(client, value, actual_cleanup, actual_revocation):
    # After absolute75min, recovery still removes custody; it never admits a new
    # signer or retroactively turns a missed deadline into successful readiness.
    value = binding(value, cleanup=True)
    need(type(actual_cleanup) is dict and actual_cleanup.get('complete') is True
         and actual_cleanup.get('owned_resources_removed') is True
         and type(actual_cleanup.get('uncertain_writes')) is int and actual_cleanup['uncertain_writes'] == 0
         and all(actual_cleanup.get(name) == value[name] for name in ('run_id', 'attempt', 'source')),
         'Actual native credential/resource cleanup required before epoch deletion')
    need(type(actual_revocation) is dict and actual_revocation.get('accepted') is True
         and actual_revocation.get('agent_absent') is True and actual_revocation.get('owner') == OWNER
         and actual_revocation.get('agent') == value['agent'] and actual_revocation.get('source') == value['source']
         and type(actual_revocation.get('uncertain_writes')) is int and actual_revocation['uncertain_writes'] == 0,
         'Actual root owner revocation and public absence required before epoch deletion')
    name = name_for(value)
    try:
        metadata(client, value)
        client.delete_parameter(Name=name)
        try:
            client.get_parameter(Name=name, WithDecryption=False)
        except client.exceptions.ParameterNotFound:
            return {'schema': 1, 'kind': 'actual-native-epoch-removal', 'name': name, 'binding': value,
                    'removed': True, 'cleanup_complete': True,
                    'within_cleanup_deadline': int(time.time()*1000) < value['cleanup_until_ms']}
        raise RuntimeError('Native epoch remains after deletion')
    except Exception:
        raise RuntimeError('Native epoch cleanup unknown; retain reconciliation state and do not claim readiness') from None
