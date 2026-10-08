# Publishing the AWS launch template

The public `zunderlabs/zunder-guard` repository owns the release pipeline. A published,
stable release can copy its signed `cloudformation.yaml` asset into S3 at
`guard/vX.Y.Z/cloudformation.yaml`. No template is uploaded from checkout HEAD, no mutable
`latest` object is created, and publishing does not enable the website's release switch.

The optional `aws-template` job in `publish.yml` uses GitHub OIDC for a 15-minute AWS
session. Its prerequisite job requires successful CI and release runs for the tagged commit,
checks all assets and their SLSA provenance, and verifies the release's Sigstore signature against
`.github/workflows/release.yml@refs/tags/vX.Y.Z`; the publisher checks that the exact
asset has one matching entry in those signed checksums. An existing version is reused
only if its downloaded bytes match. Both authenticated and anonymous downloads must
match before the job reports the template URL.

## One-time configuration

Use a dedicated distribution bucket in a commercial AWS region, preferably Tokyo
(`ap-northeast-1`). Its name must not contain dots. Enable bucket-owner-enforced object
ownership and default SSE-S3 encryption; no ACL permissions or KMS permissions are
needed. The narrowly scoped template prefix must already support anonymous `GetObject`
for customers across AWS accounts. Public access is a distribution-infrastructure
prerequisite, separate from this publisher: **the workflow does not create buckets,
change bucket/account public-access settings, or change any ACL/policy.** A blocked
public read fails the job even if the authenticated upload succeeded. Do not disable an
organisation's account-level public-access protections to make a rehearsal pass; use
an approved distribution account/bucket.

Add GitHub's OIDC identity provider (`https://token.actions.githubusercontent.com`,
audience `sts.amazonaws.com`) to the distribution AWS account. Create a dedicated role
with this trust policy, replacing `ACCOUNT_ID`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:zunderlabs/zunder-guard:environment:aws-template-publish"
    }}
  }]
}
```

Create the GitHub environment `aws-template-publish`, restrict deployment to release
**tags** `v*` (no branches), and require a release maintainer to approve it. Protect
release tags against replacement. The standard environment OIDC subject scopes the
role to that repository/environment; it does not itself restrict a workflow filename.
Environment protection and reviewed workflow changes are therefore part of the trust
boundary. Do not grant forks, pull requests, branches, or another repository access.

Attach only the following role policy, replacing `BUCKET_NAME`. Conditional writes are
required in IAM as well as by the script. Do not add broad bucket or administrator
permissions through another policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/guard/v*/cloudformation.yaml",
      "Condition": {"Null": {"s3:if-none-match": "false"}}
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/guard/v*/cloudformation.yaml"
    }
  ]
}
```

There is no `ListBucket`, delete, policy, ACL, EC2, CloudFormation or IAM permission.
A bucket policy may separately grant anonymous `s3:GetObject` on that same template
resource pattern; it must not grant anonymous write/list access. Lifecycle rules must
not expire versioned launch templates while release links remain supported. The
publisher never deletes/replaces them. This is publisher-enforced immutability, not
S3 Object Lock against an administrator.

Configure these repository variables (the enable switch must be repository-scoped so
GitHub can evaluate the job condition before entering its environment):

| Variable | Value |
| --- | --- |
| `AWS_TEMPLATE_PUBLISH` | `enabled`, only once distribution prerequisites are ready |
| `AWS_TEMPLATE_ROLE_ARN` | ARN of the restricted OIDC role |
| `AWS_TEMPLATE_BUCKET` | Existing distribution bucket |
| `AWS_TEMPLATE_REGION` | Optional; defaults to `ap-northeast-1` |

No AWS access-key secret is needed. Publication is triggered by a person publishing a
release; draft and prerelease events cannot upload templates. Re-run a failed published
release job after fixing configuration. Existing identical objects are accepted;
different bytes at the same release key fail and require a new release version.

## Customer launch link and release gate

The successful job summary contains the verified S3 URL, for example:
`https://BUCKET_NAME.s3.ap-northeast-1.amazonaws.com/guard/v1.0.0/cloudformation.yaml`.
Use it as URL-encoded `templateURL` in the website's AWS quick-create link, alongside
`stackName` and `param_Rules` / `param_Account`. Default the console region to
`ap-northeast-1`; customers may change it. The distribution bucket region does not lock
the region of their deployed stack. Do not put credentials or private keys in links.

Run the separate release gates first: published installer and binary assets, real AWS
bootstrap/SSM/health rehearsal, and licence/customer-journey verification. A signed,
public template alone is not evidence that installation or licence delivery works.
The website launch flag/config is updated explicitly only after those gates pass.

Local checks (no AWS calls):

```sh
python3 deploy/guard/github/test_publish_aws_template.py
actionlint deploy/guard/github/workflows/publish.yml
```

References: [AWS conditional-write policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html),
[GitHub OIDC with AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws),
[AWS quick-create links](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html).
