import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

import guard_harness.aws_lifecycle as harness
from guard_harness.native_release import Release
from guard_harness.runner import RunResult
from guard_harness.testnet_run import ROOT


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


def test_copied_runtime_lock_reassembles_exact_bytes_in_bounded_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = owned(Fake())
    destination = tmp_path / "instance-runtime"
    scripts: list[str] = []

    def remote(script: str, *, timeout: int = 600) -> dict[str, Any]:
        scripts.append(script)
        assert len(script.encode()) < 25000
        assert timeout == 120
        result = subprocess.run(
            ["sh", "-c", script.replace("/opt/guard-install-e2e", str(destination))],
            check=True,
            capture_output=True,
            text=True,
        )
        value: dict[str, Any] = json.loads(result.stdout)
        return value

    monkeypatch.setattr(stack, "remote", remote)
    harness.copy_runtime_lock(stack)
    assert len(scripts) > 1
    assert (destination / "requirements-runtime.lock").read_bytes() == (
        ROOT / "harness/requirements-runtime.lock"
    ).read_bytes()
    assert not (destination / "runtime-lock.b64").exists()
    with pytest.raises(subprocess.CalledProcessError):
        harness.copy_runtime_lock(stack)


def test_runtime_lock_copy_failure_stops_before_installation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack = owned(Fake())
    monkeypatch.setattr(stack, "remote", lambda *args, **kwargs: {"stage": "failed"})
    with pytest.raises(harness.AwsError, match="lock copy failed"):
        harness.copy_runtime_lock(stack)


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
    launch = stack.create(
        "https://example.invalid/template",
        account="0x" + "a" * 40,
        rules="zr1_fixture",
        execution_role=role,
        permissions_boundary=boundary,
    )
    assert launch == dict(
        channel="cloudformation",
        template_url="https://example.invalid/template",
        installer_channel="staging",
        stack_create_complete=True,
        instance_online=True,
    )
    assert captured["RoleARN"] == role
    assert captured["StackName"] == "zunder-e2e-" + fake.marker
    assert {"ParameterKey": "ExposePort", "ParameterValue": "no"} in captured["Parameters"]
    assert {"ParameterKey": "InstallerChannel", "ParameterValue": "staging"} in captured[
        "Parameters"
    ]
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


@pytest.mark.parametrize("command", ["create-stack", "send-command"])
def test_cli_json_uses_private_regular_file_and_removes_it(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[Path] = []

    def execute(argv: list[str], **options: Any) -> RunResult:
        assert "file:///dev/stdin" not in argv and options.get("stdin") is None
        path = Path(argv[argv.index("--cli-input-json") + 1].removeprefix("file://"))
        assert path.is_file() and not path.is_symlink()
        assert path.stat().st_mode & 0o777 == 0o600
        assert json.loads(path.read_text()) == {"private_fixture": "never-in-argv"}
        assert "never-in-argv" not in str(argv)
        captured.append(path)
        return RunResult(0, "{}", tmp_path / "api.log")

    monkeypatch.setattr(harness, "run", execute)
    assert (
        harness.AWS("eu-west-1", tmp_path).request(
            ["cloudformation" if command == "create-stack" else "ssm", command],
            body={"private_fixture": "never-in-argv"},
        )
        == {}
    )
    assert len(captured) == 1 and not captured[0].exists()


@pytest.mark.parametrize(
    "failed_phase",
    [
        "system-dependencies",
        "authenticated-payload",
        "python-venv",
        "locked-dependencies",
        "expected-config",
        "paper-before",
        "mainnet-refusal",
        "mainnet-admission",
    ],
)
def test_failed_remote_substage_retains_safe_phase_and_cleanup_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_phase: str
) -> None:
    phases = [
        "system-dependencies",
        "authenticated-payload",
        "python-venv",
        "locked-dependencies",
        "expected-config",
        "paper-before",
        "paper-after",
        "mainnet-refusal",
    ]
    scripts: list[str] = []
    cleaned: list[bool] = []
    malformed_admission = failed_phase == "mainnet-admission"
    failed_phase = "mainnet-refusal" if malformed_admission else failed_phase
    fake = Fake()
    digits = "1" * 12
    monkeypatch.setattr(fake, "request", lambda *args, **kwargs: {"Account": digits})
    stack = owned(fake)
    monkeypatch.setattr(stack, "create", lambda *args, **kwargs: {"stack_create_complete": True})
    monkeypatch.setattr(stack, "cleanup", lambda: cleaned.append(True))
    monkeypatch.setattr(stack, "online", lambda: None)

    def remote(script: str, *, timeout: int = 600) -> dict[str, Any]:
        phase = phases[len(scripts)]
        scripts.append(script)
        assert script.startswith("set -eu\n") and timeout == 900
        if phase == failed_phase:
            if malformed_admission:
                return {
                    "stage": "refused",
                    "binary_sha256": hashlib.sha256(
                        b"signed released executable fixture"
                    ).hexdigest(),
                    "config_written": True,
                }
            # Model the production remote's bounded refusal, never its private output.
            raise harness.AwsError("SSM native lifecycle failed; private output withheld")
        if phase == "paper-before":
            return {"stage": "before-reboot"}
        if phase == "paper-after":
            return {"stage": "passed", "mode": "paper", "coverage": ["fixture"]}
        return {"stage": "setup-complete"}

    class Subjects(Release):
        def asset(self, name: str) -> bytes:
            assert name == "cloudformation.yaml"
            return b"signed template fixture"

        def binary(self, target: str) -> bytes:
            assert target == "linux-arm64"
            return b"signed released executable fixture"

    monkeypatch.setattr(stack, "remote", remote)
    monkeypatch.setattr(harness, "Stack", lambda *args, **kwargs: stack)
    monkeypatch.setattr(harness, "template_url", lambda *args: "https://example.invalid/template")
    monkeypatch.setattr(harness, "payload", lambda *args: b"public harness fixture")
    monkeypatch.setattr(harness, "copy_runtime_lock", lambda *args: None)
    account = "0x" + "a" * 40
    with pytest.raises(
        harness.AwsError,
        match="retained mainnet state" if malformed_admission else "private output withheld",
    ):
        harness.execute(
            Subjects("v1.0.0", "a" * 40, tmp_path),
            Subjects("v0.9.0", "b" * 40, tmp_path),
            aws=fake,
            account=account,
            rules="zr1_fixture",
            role=f"arn:aws:iam::{digits}:role/fixture",
            execution_role=f"arn:aws:iam::{digits}:role/fixture",
            permissions_boundary=f"arn:aws:iam::{digits}:policy/fixture",
            work=tmp_path,
        )
    body = (tmp_path / "aws.receipt.json").read_text()
    receipt = json.loads(body)
    assert receipt["active_phase"] == failed_phase
    assert receipt["completed_phase"] == (
        "runtime-lock-copy" if failed_phase == phases[0] else phases[phases.index(failed_phase) - 1]
    )
    assert receipt["result"] == "failed" and receipt["cleanup_complete"] is True
    assert receipt["release_ready"] is False
    assert not list(tmp_path.glob("mainnet/**/*.json"))
    assert cleaned == [True] and len(scripts) == phases.index(failed_phase) + 1
    assert account not in body and digits not in body and "CommandPlugins" not in body
    if failed_phase == "paper-before":
        assert "cd /opt/guard-install-e2e\nPYTHONPATH=/opt/guard-install-e2e" in scripts[-1]
        assert "apt-get" not in scripts[-1] and " --phase before" in scripts[-1]
        assert "--require-hashes --only-binary=:all:" in scripts[3]
        assert "sha256sum -c -" in scripts[1]


@pytest.mark.parametrize("response", [{"stage": "wrong"}, {}, {"stage": False}, [], None])
def test_phase_does_not_claim_completion_from_wrong_safe_receipt(
    monkeypatch: pytest.MonkeyPatch,
    response: Any,
) -> None:
    stack = owned(Fake())
    monkeypatch.setattr(stack, "remote", lambda *args, **kwargs: response)
    receipt: dict[str, object] = {}
    with pytest.raises(harness.AwsError, match="safe receipt"):
        harness.remote_phase(
            stack, receipt, "paper-before", "public script", expected_stage="before-reboot"
        )
    assert receipt == {"active_phase": "paper-before"}


def test_failed_ssm_plugin_output_never_enters_phase_diagnostic() -> None:
    fake = Fake()
    fake.result = {
        "Status": "Failed",
        "CommandPlugins": [{"ResponseCode": 1, "Output": "private-body-token=fixture"}],
    }
    receipt: dict[str, object] = {}
    with pytest.raises(harness.AwsError) as caught:
        harness.remote_phase(
            owned(fake), receipt, "paper-before", "public script", expected_stage="before-reboot"
        )
    assert "private-body-token" not in str(caught.value) + json.dumps(receipt)
    assert receipt == {"active_phase": "paper-before"}
