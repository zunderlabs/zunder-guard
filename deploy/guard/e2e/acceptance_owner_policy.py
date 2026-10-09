"""Fixed funded-Testnet owner role; render only, never apply AWS changes."""
from acceptance_admission import ROLE,trust_policy
from native_epoch import ACCOUNT,REGION,KMS,OWNER

OWNER_PARAMETER='/zunder/testnet/e2e/owner-private-key'
OWNER_ARN=f'arn:aws:ssm:{REGION}:{ACCOUNT}:parameter'+OWNER_PARAMETER


def documents(control_source):
    # Resource ARNs identify the parameter; the immutable producer independently
    # checks Standard/SecureString/KMS/version1 before fetching :1. IAM has no
    # advertised GetParameter version-number condition and is not claimed to.
    return {'schema':1,'role':ROLE,'max_session_seconds':7200,'trust':trust_policy(control_source),
        'permissions':{'Version':'2012-10-17','Statement':[
            {'Effect':'Allow','Action':'ssm:DescribeParameters','Resource':'*'},
            {'Effect':'Allow','Action':'ssm:GetParameter','Resource':OWNER_ARN},
            {'Effect':'Deny','Action':'ssm:GetParameter','NotResource':OWNER_ARN},
            {'Effect':'Deny','Action':['ssm:GetParameters','ssm:GetParametersByPath','ssm:GetParameterHistory',
                'ssm:PutParameter','ssm:DeleteParameter','ssm:AddTagsToResource','ssm:RemoveTagsFromResource'],'Resource':'*'},
            {'Effect':'Allow','Action':'kms:Decrypt','Resource':KMS,'Condition':{'StringEquals':{
                'kms:ViaService':'ssm.'+REGION+'.amazonaws.com','kms:EncryptionContext:PARAMETER_ARN':OWNER_ARN}}},
            {'Effect':'Deny','Action':'kms:Decrypt','NotResource':KMS},
            {'Effect':'Deny','Action':'kms:Decrypt','Resource':KMS,'Condition':{'StringNotEquals':{
                'kms:EncryptionContext:PARAMETER_ARN':OWNER_ARN}}}]},
        'native_hosts_receive_owner_key':False,'mainnet':False,'live_applied':False,'release_ready':False}
