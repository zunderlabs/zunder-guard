import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

import guard_harness.aws_lifecycle as harness
from guard_harness.native_release import Release
from guard_harness.runner import RunResult


class Fake(harness.AWS):
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.marker = "a" * 32
        self.name = "zunder-e2e-" + self.marker
        self.stack_id = "arn:fixture:stack"
        self.exists = True
        self.volume = True
        self.foreign = False
        self.attached = False
        self.failed_inventory = False
        self.pending = 0
        self.result: dict[str, Any] = {
            "Status": "Success",
            "CommandPlugins": [{"ResponseCode": 0, "Output": '{"stage":"passed"}'}],
        }

    def request(
        self, words: list[str], *, body: dict[str, Any] | None = None, timeout: float = 60
    ) -> dict[str, Any]:
        self.calls.append(words)
        command = words[:2]
        if command == ["cloudformation", "list-stacks"]:
            if self.failed_inventory:
                raise RuntimeError("inaccessible")
            return {
                "StackSummaries": [{"StackName": self.name, "StackStatus": "CREATE_COMPLETE"}]
                if self.exists
                else []
            }
        if command == ["cloudformation", "describe-stacks"]:
            return {
                "Stacks": [
                    {
                        "StackName": self.name,
                        "StackId": self.stack_id,
                        "Tags": [
                            {
                                "Key": "zunder:run",
                                "Value": "foreign" if self.foreign else self.marker,
                            },
                            {"Key": "zunder:purpose", "Value": "release-e2e"},
                            {"Key": "zunder-e2e", "Value": self.marker},
                        ],
                    }
                ]
            }
        if command == ["ec2", "describe-volumes"]:
            return {
                "Volumes": [
                    {
                        "VolumeId": "volume-fixture",
                        "State": "available",
                        "Attachments": [{"owned": False}] if self.attached else [],
                        "Tags": [{"Key": "zunder:stack", "Value": self.stack_id}],
                    }
                ]
                if self.volume
                else []
            }
        if command == ["cloudformation", "delete-stack"]:
            self.exists = False
        if command == ["ec2", "delete-volume"]:
            self.volume = False
        if command == ["ssm", "send-command"]:
            assert body is not None and body["DocumentName"] == "AWS-RunShellScript"
            return {
                "Command": {
                    "CommandId": "b" * 8
                    + "-"
                    + "b" * 4
                    + "-"
                    + "b" * 4
                    + "-"
                    + "b" * 4
                    + "-"
                    + "b" * 12
                }
            }
        if command == ["ssm", "list-command-invocations"]:
            if self.pending:
                self.pending -= 1
                return {"CommandInvocations": []}
            return {"CommandInvocations": [self.result]}
        return {}


def owned(fake: Fake) -> harness.Stack:
    stack = harness.Stack(fake, marker=fake.marker, pause=lambda seconds: None)
    stack.stack_id = fake.stack_id
    stack.armed = True
    return stack


def test_cleanup_deletes_only_owned_stack_then_detached_retained_volume() -> None:
    fake = Fake()
    owned(fake).cleanup()
    assert fake.exists is False and fake.volume is False
    operations = [call[:2] for call in fake.calls]
    assert operations.index(["cloudformation", "delete-stack"]) < operations.index(
        ["ec2", "delete-volume"]
    )


@pytest.mark.parametrize("failure", ["ownership", "attached", "unknown-inventory"])
def test_cleanup_refuses_foreign_or_unobservable_resources(failure: str) -> None:
    fake = Fake()
    fake.foreign = failure == "ownership"
    fake.attached = failure == "attached"
    fake.failed_inventory = failure == "unknown-inventory"
    with pytest.raises((harness.AwsError, RuntimeError)):
        owned(fake).cleanup()
    assert not any(call[:2] == ["ec2", "delete-volume"] for call in fake.calls)
    if failure != "attached":
        assert not any(call[:2] == ["cloudformation", "delete-stack"] for call in fake.calls)


def test_pending_ssm_output_is_not_an_empty_pass() -> None:
    fake = Fake()
    fake.pending = 2
    stack = owned(fake)
    stack.instance_id = "instance-fixture"
    assert stack.remote("safe public command") == {"stage": "passed"}
    assert sum(call[:2] == ["ssm", "list-command-invocations"] for call in fake.calls) == 3


@pytest.mark.parametrize(
    "result",
    [
        {"Status": "Failed"},
        {"Status": "Success", "CommandPlugins": []},
        {"Status": "Success", "CommandPlugins": [{"ResponseCode": 1}]},
    ],
)
def test_ssm_success_requires_positive_execution_result(result: dict[str, Any]) -> None:
    fake = Fake()
    fake.result = result
    with pytest.raises(harness.AwsError):
        owned(fake).remote("safe public command")


def test_api_output_and_physical_identifiers_are_withheld(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flags: dict[str, Any] = {}

    def execute(words: list[str], **kwargs: Any) -> RunResult:
        flags.update(kwargs)
        return RunResult(0, '{"StackId":"opaque"}', tmp_path / "api.log")

    monkeypatch.setattr(harness, "run", execute)
    assert (
        harness.AWS("eu-west-1", tmp_path).request(["cloudformation", "list-stacks"])["StackId"]
        == "opaque"
    )
    assert flags["sensitive_output"] is True


def test_payload_contains_only_public_code_and_authenticated_loaders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPERATOR_SECRET", "must-not-be-in-payload")
    monkeypatch.setattr(Release, "asset", lambda self, name: b"authenticated release loader")
    release = Release("v1.0.0", "b" * 40, tmp_path)
    package = harness.payload(release, release)
    assert b"must-not-be-in-payload" not in package
    with zipfile.ZipFile(io.BytesIO(package)) as source:
        assert set(source.namelist()) == {
            "guard_harness/" + name
            for name in (
                "__init__.py",
                "runner.py",
                "cli.py",
                "paper_bot.py",
                "paper_roundtrip.py",
                "aws_paper.py",
                "mainnet_terminal.py",
            )
        } | {"candidate-i", "previous-i"}
        assert source.read("candidate-i") == b"authenticated release loader"
    assert len(package) < 48 * 1024


@pytest.mark.parametrize("failure", ["changed-bytes", "redirect"])
def test_template_requires_exact_authenticated_public_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    url = "https://example.invalid/guard/v1.0.0/cloudformation.yaml"
    (tmp_path / "release-manifest.json").write_text(
        json.dumps({"distribution": {"aws_template": {"url": url}}})
    )
    release = Release("v1.0.0", "b" * 40, tmp_path)
    monkeypatch.setattr(Release, "asset", lambda self, name: b"signed template")

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def geturl(self) -> str:
            return url + "/redirect" if failure == "redirect" else url

        def read(self, size: int) -> bytes:
            return b"changed template" if failure == "changed-bytes" else b"signed template"

    monkeypatch.setattr(harness, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(harness.AwsError):
        harness.template_url(release)


def test_create_passes_execution_role_and_owned_sandbox_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = Fake()
    captured: dict[str, Any] = {}

    def request(words: list[str], **kwargs: Any) -> dict[str, Any]:
        if words[:2] == ["cloudformation", "list-stacks"]:
            return {"StackSummaries": []}
        if words[:2] == ["cloudformation", "create-stack"]:
            captured.update(kwargs["body"])
            return {"StackId": "arn:fixture:stack"}
        return {}

    monkeypatch.setattr(fake, "request", request)
    stack = harness.Stack(fake, marker=fake.marker)
    monkeypatch.setattr(
        stack,
        "owned",
        lambda: {"Outputs": [{"OutputKey": "InstanceId", "OutputValue": "i-" + "1" * 17}]},
    )
    monkeypatch.setattr(stack, "online", lambda: None)
    account_id = "1" * 12
    role = f"arn:aws:iam::{account_id}:role/fixture-execution"
    boundary = f"arn:aws:iam::{account_id}:policy/fixture-boundary"
    stack.create(
        "https://example.invalid/template",
        account="0x" + "a" * 40,
        rules="zr1_fixture",
        execution_role=role,
        permissions_boundary=boundary,
    )
    assert captured["RoleARN"] == role
    assert captured["StackName"] == "zunder-e2e-" + fake.marker
    assert {"ParameterKey": "ExposePort", "ParameterValue": "no"} in captured["Parameters"]
    assert captured["Parameters"][-1] == {
        "ParameterKey": "PermissionsBoundaryArn",
        "ParameterValue": boundary,
    }
    assert {"Key": "zunder-e2e", "Value": fake.marker} in captured["Tags"]


@pytest.mark.parametrize(
    "boundary",
    ["", f"arn:aws:iam::{'2' * 12}:policy/boundary", f"arn:aws:iam::{'1' * 12}:role/not-policy"],
)
def test_boundary_refuses_before_any_cloud_call(boundary: str) -> None:
    fake = Fake()
    stack = harness.Stack(fake, marker=fake.marker)
    with pytest.raises(harness.AwsError, match="permissions boundary"):
        stack.create(
            "https://example.invalid/template",
            account="0x" + "a" * 40,
            rules="zr1_fixture",
            execution_role=f"arn:aws:iam::{'1' * 12}:role/execution",
            permissions_boundary=boundary,
        )
    assert fake.calls == []
    assert stack.armed is False
