"""Exact signed CloudFormation stack lifecycle; always remove this run's owned resources."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import shlex
import tempfile
import time
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from guard_harness.native_release import Release
from guard_harness.runner import RunResult, run
from guard_harness.testnet_run import ROOT


class AwsError(RuntimeError):
    """Incomplete sandbox lifecycle; diagnostics deliberately exclude physical IDs."""


class AWS:
    def __init__(self, region: str, work: Path) -> None:
        if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region) is None:
            raise AwsError("explicit region required")
        self.region, self.work, self.sequence = region, work, 0

    def request(
        self, words: list[str], *, body: dict[str, Any] | None = None, timeout: float = 60
    ) -> dict[str, Any]:
        self.sequence += 1
        if "--cli-input-json" in words:
            raise AwsError("controller owns the private CLI JSON input path")
        argv = ["aws", "--region", self.region, "--no-cli-pager", "--output", "json", *words]

        def execute(arguments: list[str]) -> RunResult:
            return run(
                arguments,
                log=self.work / f"aws-{self.sequence}.log",
                timeout=timeout,
                sensitive_output=True,
            )

        if body is None:
            result = execute(argv)
        else:
            # AWS CLI v2 does not accept file:///dev/stdin; no IDs or payload in argv.
            with tempfile.NamedTemporaryFile(
                mode="w", dir=self.work, prefix="aws-input-", encoding="utf-8"
            ) as input_file:
                os.chmod(input_file.name, 0o600)
                json.dump(body, input_file)
                input_file.flush()
                result = execute(argv + ["--cli-input-json", "file://" + input_file.name])
        if not result.output.strip():
            return {}
        value = json.loads(result.output)
        if not isinstance(value, dict):
            raise AwsError("AWS response is not a structured object")
        return value


def template_url(release: Release) -> str:
    build = json.loads((release.assets / "release-manifest.json").read_bytes())
    url = build["distribution"]["aws_template"]["url"]
    if (
        not isinstance(url, str)
        or not url.startswith("https://")
        or not url.endswith(f"/guard/{release.tag}/cloudformation.yaml")
    ):
        raise AwsError("immutable public template URL required")
    with urlopen(Request(url), timeout=45) as response:
        if response.status != 200 or response.geturl() != url:
            raise AwsError("template URL redirect/status refused")
        captured = response.read(1024 * 1024 + 1)
    if captured != release.asset("cloudformation.yaml"):
        raise AwsError("served template differs from authenticated signed release")
    return url


def payload(current: Release, previous: Release) -> bytes:
    """Public checked-out harness subset only; no operator files, environment or credentials."""
    members = (
        "__init__.py",
        "runner.py",
        "cli.py",
        "paper_bot.py",
        "paper_roundtrip.py",
        "aws_paper.py",
        "mainnet_terminal.py",
    )
    captured = io.BytesIO()
    with zipfile.ZipFile(captured, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for name in members:
            source = ROOT / "harness/src/guard_harness" / name
            if source.is_symlink() or not source.is_file():
                raise AwsError("public harness source member refused")
            output.writestr("guard_harness/" + name, source.read_bytes())
        output.writestr("candidate-i", current.asset("i"))
        output.writestr("previous-i", previous.asset("i"))
    if len(captured.getvalue()) > 48 * 1024:
        raise AwsError("SSM payload exceeds bounded command envelope")
    return captured.getvalue()


class Stack:
    def __init__(
        self, aws: AWS, *, marker: str, pause: Callable[[float], None] = time.sleep
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{32}", marker) is None:
            raise AwsError("fresh run marker required")
        self.aws, self.marker, self.pause = aws, marker, pause
        self.name = "zunder-e2e-" + marker
        self.stack_id = ""
        self.instance_id = ""
        self.armed = False

    def inventory(self) -> list[dict[str, Any]]:
        response = self.aws.request(["cloudformation", "list-stacks"])
        records = response.get("StackSummaries")
        if not isinstance(records, list):
            raise AwsError("successful complete stack inventory required")
        return records

    def create(
        self, url: str, *, account: str, rules: str, execution_role: str, permissions_boundary: str
    ) -> dict[str, object]:
        validate_boundary(permissions_boundary, execution_role)
        if any(
            value.get("StackName") == self.name and value.get("StackStatus") != "DELETE_COMPLETE"
            for value in self.inventory()
        ):
            raise AwsError("fresh stack name already exists")
        self.armed = True  # Arm before a request whose outcome could be unknown.
        value = self.aws.request(
            ["cloudformation", "create-stack"],
            body={
                "StackName": self.name,
                "TemplateURL": url,
                "RoleARN": execution_role,
                "Capabilities": ["CAPABILITY_IAM"],
                "ClientRequestToken": self.marker,
                "OnFailure": "DO_NOTHING",
                "Parameters": [
                    {"ParameterKey": "Account", "ParameterValue": account},
                    {"ParameterKey": "Rules", "ParameterValue": rules},
                    {"ParameterKey": "InstanceType", "ParameterValue": "t4g.micro"},
                    {"ParameterKey": "ExposePort", "ParameterValue": "no"},
                    {"ParameterKey": "InstallerChannel", "ParameterValue": "staging"},
                    {
                        "ParameterKey": "PermissionsBoundaryArn",
                        "ParameterValue": permissions_boundary,
                    },
                ],
                "Tags": [
                    {"Key": "zunder-e2e", "Value": self.marker},
                    {"Key": "zunder:purpose", "Value": "release-e2e"},
                    {"Key": "zunder:run", "Value": self.marker},
                ],
            },
        )
        stack_id = value.get("StackId")
        if not isinstance(stack_id, str) or not stack_id.startswith("arn:"):
            raise AwsError("created stack identity missing")
        self.stack_id = stack_id
        self.aws.request(
            ["cloudformation", "wait", "stack-create-complete", "--stack-name", self.stack_id],
            timeout=1350,
        )
        record = self.owned()
        outputs = record.get("Outputs", [])
        values = [item["OutputValue"] for item in outputs if item.get("OutputKey") == "InstanceId"]
        if len(values) != 1 or re.fullmatch(r"i-[0-9a-f]{8,17}", values[0]) is None:
            raise AwsError("stack instance output missing/ambiguous")
        self.instance_id = values[0]
        self.online()
        return dict(
            channel="cloudformation",
            template_url=url,
            installer_channel="staging",
            stack_create_complete=True,
            instance_online=True,
        )

    def owned(self) -> dict[str, Any]:
        value = self.aws.request(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_id or self.name]
        )
        records = value.get("Stacks")
        if not isinstance(records, list) or len(records) != 1:
            raise AwsError("owned stack description ambiguous")
        record = records[0]
        if not isinstance(record, dict):
            raise AwsError("owned stack description malformed")
        tags = {item["Key"]: item["Value"] for item in record.get("Tags", [])}
        if (
            record.get("StackName") != self.name
            or tags.get("zunder-e2e") != self.marker
            or tags.get("zunder:run") != self.marker
            or tags.get("zunder:purpose") != "release-e2e"
        ):
            raise AwsError("stack ownership marker differs")
        self.stack_id = record["StackId"]
        return record

    def online(self) -> None:
        for _ in range(90):
            value = self.aws.request(
                [
                    "ssm",
                    "describe-instance-information",
                    "--filters",
                    json.dumps([{"Key": "InstanceIds", "Values": [self.instance_id]}]),
                ]
            )
            records = value.get("InstanceInformationList")
            if not isinstance(records, list):
                raise AwsError("SSM managed inventory missing")
            if any(
                item.get("InstanceId") == self.instance_id and item.get("PingStatus") == "Online"
                for item in records
            ):
                return
            self.pause(5)
        raise AwsError("instance SSM readiness deadline")

    def remote(self, script: str, *, timeout: int = 600) -> dict[str, Any]:
        response = self.aws.request(
            ["ssm", "send-command"],
            body={
                "InstanceIds": [self.instance_id],
                "DocumentName": "AWS-RunShellScript",
                "TimeoutSeconds": timeout,
                "Parameters": {"commands": [script], "executionTimeout": [str(timeout)]},
            },
        )
        command_id = response.get("Command", {}).get("CommandId")
        if not isinstance(command_id, str) or re.fullmatch(r"[0-9a-f-]{36}", command_id) is None:
            raise AwsError("SSM command identity missing")
        for _ in range(timeout // 5 + 12):
            value = self.aws.request(
                [
                    "ssm",
                    "list-command-invocations",
                    "--command-id",
                    command_id,
                    "--instance-id",
                    self.instance_id,
                    "--details",
                ]
            )
            records = value.get("CommandInvocations")
            if not isinstance(records, list) or len(records) > 1:
                raise AwsError("SSM command result ambiguous")
            if records:
                record = records[0]
                if record.get("Status") == "Success":
                    plugins = record.get("CommandPlugins")
                    if (
                        not isinstance(plugins, list)
                        or len(plugins) != 1
                        or plugins[0].get("ResponseCode") != 0
                    ):
                        raise AwsError("SSM success lacked successful execution positive control")
                    body = json.loads(plugins[0]["Output"])
                    if not isinstance(body, dict):
                        raise AwsError("SSM safe receipt missing")
                    return body
                if record.get("Status") not in ("Pending", "InProgress", "Delayed"):
                    raise AwsError("SSM native lifecycle failed; private output withheld")
            self.pause(5)
        raise AwsError("SSM execution result deadline")

    def cleanup(self) -> None:
        if not self.armed:
            return
        matches = [
            value
            for value in self.inventory()
            if value.get("StackName") == self.name and value.get("StackStatus") != "DELETE_COMPLETE"
        ]
        if matches:
            if len(matches) != 1:
                raise AwsError("cleanup ownership ambiguous")
            self.owned()
        elif not self.stack_id:
            return  # Positive successful inventory confirms no applied create.
        volumes = self.aws.request(
            [
                "ec2",
                "describe-volumes",
                "--filters",
                json.dumps([{"Name": "tag:zunder:stack", "Values": [self.stack_id]}]),
            ]
        ).get("Volumes")
        if not isinstance(volumes, list):
            raise AwsError("owned retained-volume inventory missing")
        captured = [item["VolumeId"] for item in volumes]
        if matches:
            self.aws.request(["cloudformation", "delete-stack", "--stack-name", self.stack_id])
            self.aws.request(
                ["cloudformation", "wait", "stack-delete-complete", "--stack-name", self.stack_id],
                timeout=900,
            )
        for volume_id in captured:
            self.aws.request(
                ["ec2", "wait", "volume-available", "--volume-ids", volume_id], timeout=300
            )
            value = self.aws.request(["ec2", "describe-volumes", "--volume-ids", volume_id])[
                "Volumes"
            ]
            if (
                len(value) != 1
                or value[0].get("State") != "available"
                or value[0].get("Attachments")
            ):
                raise AwsError("retained-volume deletion requires detached available owned volume")
            tags = {item["Key"]: item["Value"] for item in value[0].get("Tags", [])}
            if tags.get("zunder:stack") != self.stack_id:
                raise AwsError("retained-volume ownership changed")
            self.aws.request(["ec2", "delete-volume", "--volume-id", volume_id])
        for _ in range(12):
            remaining = self.aws.request(
                [
                    "ec2",
                    "describe-volumes",
                    "--filters",
                    json.dumps([{"Name": "tag:zunder:stack", "Values": [self.stack_id]}]),
                ]
            ).get("Volumes")
            if remaining == []:
                break
            if not isinstance(remaining, list):
                raise AwsError("retained-volume cleanup inventory missing")
            self.pause(5)
        else:
            raise AwsError("retained volumes survived sandbox cleanup")
        if any(
            item.get("StackName") == self.name and item.get("StackStatus") != "DELETE_COMPLETE"
            for item in self.inventory()
        ):
            raise AwsError("stack survived sandbox cleanup")


def copy_runtime_lock(stack: Stack) -> None:
    """Copy the checked-out lock in bounded SSM commands before dependency installation."""
    lock = ROOT / "harness/requirements-runtime.lock"
    if lock.is_symlink() or not lock.is_file():
        raise AwsError("public runtime dependency lock refused")
    captured = lock.read_bytes()
    if not captured or len(captured) > 256 * 1024:
        raise AwsError("public runtime dependency lock size refused")
    encoded = base64.b64encode(gzip.compress(captured, mtime=0)).decode()
    directory = "/opt/guard-install-e2e"
    chunks = [encoded[offset : offset + 24000] for offset in range(0, len(encoded), 24000)]
    for index, chunk in enumerate(chunks):
        script = "set -eu\numask 077\n"
        if index == 0:
            script += f"test ! -e {directory}\nmkdir -m 700 {directory}\n"
        script += f"printf %s {shlex.quote(chunk)} >>{directory}/runtime-lock.b64\n"
        if index == len(chunks) - 1:
            script += (
                f"base64 -d <{directory}/runtime-lock.b64 | gzip -d "
                f">{directory}/requirements-runtime.lock\n"
                f"printf '%s  %s\\n' {hashlib.sha256(captured).hexdigest()} "
                f"{directory}/requirements-runtime.lock | sha256sum -c - >/dev/null\n"
                f"rm {directory}/runtime-lock.b64\n"
            )
        script += "printf '%s\\n' '{\"stage\":\"runtime-lock-copied\"}'\n"
        if stack.remote(script, timeout=120) != {"stage": "runtime-lock-copied"}:
            raise AwsError("instance runtime dependency lock copy failed")


def validate_boundary(boundary: str, execution_role: str) -> None:
    if (
        re.fullmatch(r"arn:aws:iam::[0-9]{12}:policy/[A-Za-z0-9_+=,.@/-]+", boundary) is None
        or re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+", execution_role) is None
        or boundary.split(":")[4] != execution_role.split(":")[4]
    ):
        raise AwsError("explicit same-sandbox permissions boundary required")


def execute(
    current: Release,
    previous: Release,
    *,
    aws: AWS,
    account: str,
    rules: str,
    role: str,
    execution_role: str,
    permissions_boundary: str,
    work: Path,
) -> dict[str, object]:
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", account) or not re.fullmatch(
        r"zr1_[A-Za-z0-9_-]+", rules
    ):
        raise AwsError("explicit public funded paper account/rules required")
    if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+", role):
        raise AwsError("explicit sandbox role required")
    if (
        not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+", execution_role)
        or execution_role.split(":")[4] != role.split(":")[4]
    ):
        raise AwsError("same-sandbox CloudFormation execution role required")
    validate_boundary(permissions_boundary, execution_role)
    caller = aws.request(["sts", "get-caller-identity"])
    if caller.get("Account") != role.split(":")[4]:
        raise AwsError("current AWS identity is outside configured sandbox")
    template = template_url(current)
    captured = payload(current, previous)
    encoded = base64.b64encode(captured).decode()
    digest = hashlib.sha256(captured).hexdigest()
    current_digest = hashlib.sha256(current.binary("linux-arm64")).hexdigest()
    previous_digest = hashlib.sha256(previous.binary("linux-arm64")).hexdigest()
    stack = Stack(aws, marker=uuid.uuid4().hex)
    receipt: dict[str, object] = {
        "result": "failed",
        "cleanup_complete": False,
        "release_ready": False,
        "tag": current.tag,
        "commit": current.commit,
        "harness_commit": os.environ.get("GITHUB_SHA", ""),
        "diagnostic": os.environ.get("DIAGNOSTIC") == "true",
    }
    try:
        launch = stack.create(
            template,
            account=account,
            rules=rules,
            execution_role=execution_role,
            permissions_boundary=permissions_boundary,
        )
        receipt["template_launch"] = launch | {
            "template_sha256": hashlib.sha256(current.asset("cloudformation.yaml")).hexdigest()
        }
        copy_runtime_lock(stack)
        setup = (
            "set -eu\numask 077\napt-get update >/dev/null 2>&1\n"
            "apt-get install -y python3-venv unzip >/dev/null 2>&1\n"
            + "printf %s "
            + shlex.quote(encoded)
            + " | base64 -d >/opt/guard-install-e2e/payload.zip\n"
            + "printf '%s  %s\\n' "
            + shlex.quote(digest)
            + " /opt/guard-install-e2e/payload.zip | sha256sum -c - >/dev/null\n"
            + "unzip -q /opt/guard-install-e2e/payload.zip -d /opt/guard-install-e2e\n"
            + "python3 -m venv /opt/guard-install-e2e/venv\n"
            "/opt/guard-install-e2e/venv/bin/pip install --require-hashes --only-binary=:all: "
            "-r /opt/guard-install-e2e/requirements-runtime.lock >/dev/null 2>&1\n"
        )
        arguments = (
            " --version "
            + current.tag[1:]
            + " --previous-version "
            + previous.tag[1:]
            + " --binary-sha256 "
            + current_digest
            + " --previous-binary-sha256 "
            + previous_digest
        )
        invoke = (
            "cd /opt/guard-install-e2e\nPYTHONPATH=/opt/guard-install-e2e "
            "/opt/guard-install-e2e/venv/bin/python -m guard_harness.aws_paper"
        )
        setup += (
            "printf %s "
            + shlex.quote(json.dumps({"account": account, "rules": rules}))
            + " >/opt/guard-install-e2e/expected.json\n"
        )
        initial = stack.remote(setup + invoke + " --phase before" + arguments, timeout=900)
        if initial.get("stage") != "before-reboot":
            raise AwsError("instance lifecycle did not reach reboot boundary")
        aws.request(["ec2", "reboot-instances", "--instance-ids", stack.instance_id])
        stack.pause(30)
        stack.online()
        completed = stack.remote("set -eu\n" + invoke + " --phase after" + arguments, timeout=900)
        if completed.get("stage") != "passed" or completed.get("mode") != "paper":
            raise AwsError("instance lifecycle incomplete")
        receipt.update(result="passed", coverage=completed["coverage"])
        activation = stack.remote(
            "set -eu\nGITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "
            + invoke.replace("cd /opt/guard-install-e2e\n", "")
            + " --phase mainnet"
            + arguments,
            timeout=900,
        )
        if (
            activation.get("stage") != "refused"
            or activation.get("binary_sha256") != current_digest
        ):
            raise AwsError("protected stack activation did not refuse on the signed executable")
        for field in ("config_written", "credential_written", "service_enabled", "service_started"):
            if activation.get(field) is not False:
                raise AwsError("refused stack activation retained mainnet state")
        log_text = activation.get("log")
        code = activation.get("exit_code")
        if not isinstance(log_text, str) or "is not an API wallet of" not in log_text:
            raise AwsError("stack activation did not capture actual userRole refusal")
        if type(code) is not int or code == 0:
            raise AwsError("stack activation did not observe failed setup")
        target = work / "mainnet/M1"
        target.mkdir(parents=True, mode=0o700)
        log = target / "aws-template.log"
        log.write_text(log_text)
        activation_receipt = dict(
            schema=1,
            journey="M1",
            route="aws-template",
            tag=current.tag,
            commit=current.commit,
            harness_commit=os.environ.get("GITHUB_SHA", ""),
            diagnostic=os.environ.get("DIAGNOSTIC") == "true",
            result="passed",
            tier="e2e",
            manifest_sha256=hashlib.sha256(current.asset("release-manifest.json")).hexdigest(),
            binary_sha256=current_digest,
            coverage=["protected-setup-unapproved-wallet"],
            mode="mainnet",
            wallet_role="unapproved",
            exchange_requests=0,
            exit_code=code,
            expected_refusal="is not an API wallet of",
            log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
            config_written=False,
            credential_written=False,
            service_enabled=False,
            service_started=False,
        )
    finally:
        try:
            stack.cleanup()
            receipt["cleanup_complete"] = True
        except Exception:
            receipt["result"] = "failed"
            raise
        finally:
            (work / "aws.receipt.json").write_text(json.dumps(receipt) + "\n")
    if receipt["cleanup_complete"] is True:
        (target / "aws-template.json").write_text(json.dumps(activation_receipt) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "tag",
        "commit",
        "previous-tag",
        "previous-commit",
        "account",
        "rules",
        "role",
        "region",
        "execution-role",
        "permissions-boundary",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise AwsError("hosted disposable sandbox controller required")
    args.work.mkdir(mode=0o700)
    execute(
        Release(args.tag, args.commit, args.assets / "candidate/assets"),
        Release(args.previous_tag, args.previous_commit, args.assets / "previous/assets"),
        aws=AWS(args.region, args.work),
        account=args.account,
        rules=args.rules,
        role=args.role,
        execution_role=args.execution_role,
        permissions_boundary=args.permissions_boundary,
        work=args.work,
    )


if __name__ == "__main__":
    main()
