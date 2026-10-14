import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import linux_testnet_service, runner
from guard_harness.runner import RunError

# These are the complete fixed stderr sentences emitted by the released
# install-container.py Refused handler, including its prefix and final newline.
REFUSALS = [
    (
        "Container installation refused: "
        "Verified image signature admission failed before wallet input.\n",
        "container-image-signature",
    ),
    (
        "Container installation refused: Verified image pull failed before wallet input.\n",
        "container-image-pull",
    ),
    (
        "Container installation refused: "
        "Guard setup command failed; activation remains inhibited.\n",
        "container-guard-setup",
    ),
    (
        "Container installation refused: "
        "Encrypted supervisor installation failed; activation remains inhibited.\n",
        "container-supervisor",
    ),
    (
        "Container installation refused: "
        "Guard did not reach the expected healthy account/risk/licence state.\n",
        "container-readiness",
    ),
]


REFUSALS.extend(
    (
        "Container installation refused: Guard did not reach the expected healthy "
        f"account/risk/licence state. (predicate={predicate}).\n",
        "container-readiness-" + predicate,
    )
    for predicate in (
        "health-transport",
        "health-http",
        "status-transport",
        "status-http",
        "status-json",
        "account-mode",
        "risk",
        "fee",
        "licence",
        "builder-approval",
    )
)


@pytest.mark.parametrize("stderr,category", REFUSALS)
def test_failed_container_setup_exports_only_exact_stage_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stderr: str, category: str
) -> None:
    root = tmp_path / "synthetic-root"

    def mapped(value: str) -> Path:
        return root / value.lstrip("/")

    mapped("/run/systemd/system").mkdir(parents=True)
    marker = tmp_path / "marker"
    marker.write_text("a" * 32)
    key = b"b" * 64 + b"\n"
    private = "private-stdout-account-token-path"
    commands = []

    def failed(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        commands.append(argv)
        assert kwargs["input"] == key * 2
        assert key.decode().strip() not in repr(argv) + repr(kwargs["env"])
        assert "--container" in argv and "--key-stdin" in argv
        assert argv[argv.index("--ip-share") + 1] == "1"
        assert argv[argv.index("--equity-cap") + 1] == "40"
        return subprocess.CompletedProcess(argv, 1, private.encode(), stderr.encode())

    monkeypatch.setattr(linux_testnet_service, "Path", mapped)
    monkeypatch.setattr(linux_testnet_service, "MARKER", marker)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(linux_testnet_service, "authenticated_file", lambda *args: None)
    monkeypatch.setattr(subprocess, "run", failed)
    service = linux_testnet_service.TestnetService(
        tmp_path / "install.sh",
        "c" * 64,
        "0x" + "d" * 40,
        "synthetic-rules",
        8547,
        tmp_path,
        "a" * 32,
        container=True,
    )
    with pytest.raises(RunError) as caught:
        service.setup(key)
    assert len(commands) == 1  # Refusal stops before custody/volume/readiness observations.
    assert str(caught.value) == "command failed with exit 1; failure category: " + category
    log = (tmp_path / "testnet-service-install.log").read_text()
    assert log == "[sensitive command output withheld]\nfailure category: " + category + "\n"
    assert private not in log + str(caught.value)
    assert key.decode().strip() not in log + str(caught.value)
    assert stderr not in log + str(caught.value)


@pytest.mark.parametrize(
    "mutation",
    [
        "prefix",
        "suffix",
        "second-line",
        "duplicate",
        "missing-newline",
        "crlf",
        "leading-space",
        "traceback",
        "private-account",
        "private-arn",
        "redacted-key",
        "oversized",
    ],
)
def test_private_ambiguous_or_nonexact_refusal_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    valid = REFUSALS[2][0]
    private = "private-token-fixture"
    bodies = {
        "prefix": private + valid,
        "suffix": valid.rstrip("\n") + private + "\n",
        "second-line": valid + private + "\n",
        "duplicate": valid * 2,
        "missing-newline": valid.rstrip("\n"),
        "crlf": valid.replace("\n", "\r\n"),
        "leading-space": " " + valid,
        "traceback": "Traceback (most recent call last):\n" + valid,
        "private-account": valid + "0x" + "e" * 40,
        "private-arn": valid + "arn:aws:fixture:private-resource",
        "redacted-key": valid + "[REDACTED]",
        "oversized": valid + "x" * 65537,
    }

    def failed(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, private.encode(), bodies[mutation].encode())

    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(RunError) as caught:
        runner.run(
            ["synthetic-installer"],
            log=tmp_path / "log",
            timeout=1,
            sensitive_output=True,
            failure_classifier=linux_testnet_service.container_install_failure_category,
        )
    assert str(caught.value) == "command failed with exit 1; failure category: unknown"
    assert (tmp_path / "log").read_text() == (
        "[sensitive command output withheld]\nfailure category: unknown\n"
    )


def test_string_subclass_cannot_supply_a_recognized_refusal() -> None:
    class PrivateOutput(str):
        def __eq__(self, other: object) -> bool:
            raise AssertionError("private exception must never be evaluated")

    assert linux_testnet_service.container_install_failure_category(PrivateOutput("private")) == (
        "unknown"
    )


def test_installer_timeout_cannot_export_partial_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timed_out(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(argv, 1, b"private", REFUSALS[2][0].encode())

    monkeypatch.setattr(subprocess, "run", timed_out)
    with pytest.raises(RunError, match="exit 124; failure category: unknown"):
        runner.run(
            ["synthetic-installer"],
            log=tmp_path / "log",
            timeout=1,
            sensitive_output=True,
            failure_classifier=linux_testnet_service.container_install_failure_category,
        )
    assert (tmp_path / "log").read_text() == (
        "[sensitive command output withheld]\nfailure category: unknown\n"
    )


@pytest.mark.parametrize(
    "message,category",
    [
        ("missing protected testnet key frame", "native-key-frame"),
        ("systemd-creds could not encrypt the key", "native-credential-encryption"),
        ("the key was refused; nothing was stored", "native-key-refused"),
        ("managed software path is not a real directory", "native-software-directory"),
        ("managed software directory is not root-owned", "native-software-owner"),
        ("managed software directory mode is invalid", "native-software-mode"),
        ("managed software directory has unsafe permissions", "native-software-permissions"),
        (
            "managed software parent is not publicly traversable",
            "native-software-parent-traversal",
        ),
        (
            "Guard did not become healthy; see the log above (journalctl -u zunder-guard-testnet)",
            "native-readiness",
        ),
    ],
)
def test_native_fixed_terminal_refusal_withholds_all_prior_private_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, message: str, category: str
) -> None:
    def failed(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv,
            1,
            b"private-stdout",
            ("private-token/account/path\ninstall.sh: " + message + "\n").encode(),
        )

    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(RunError, match="failure category: " + category) as caught:
        runner.run(
            ["synthetic-native"],
            log=tmp_path / "log",
            timeout=1,
            sensitive_output=True,
            failure_classifier=linux_testnet_service.native_install_failure_category,
        )
    assert (tmp_path / "log").read_text() == (
        "[sensitive command output withheld]\nfailure category: " + category + "\n"
    )
    assert "private" not in str(caught.value)


@pytest.mark.parametrize(
    "output",
    [
        "install.sh: missing protected testnet key frame",  # incomplete line
        "install.sh: missing protected testnet key frame-private\n",
        "install.sh: missing protected testnet key frame\nprivate\n",
        "private init error\n",
        "x" * 65537,
    ],
)
def test_nonexact_native_refusal_does_not_infer_failing_phase(output: str) -> None:
    assert linux_testnet_service.native_install_failure_category(output) == "unknown"


def test_unknown_new_readiness_predicate_is_not_exported() -> None:
    output = (
        "Container installation refused: Guard did not reach the expected healthy "
        "account/risk/licence state. (predicate=private-token).\n"
    )
    assert linux_testnet_service.container_install_failure_category(output) == "unknown"


@pytest.mark.parametrize(
    "message",
    [
        "managed software path is not a real directory",
        "managed software directory is not root-owned",
        "managed software directory mode is invalid",
        "managed software directory has unsafe permissions",
        "managed software parent is not publicly traversable",
    ],
)
@pytest.mark.parametrize("suffix", ["", "-private\n", "\nprivate\n"])
def test_nonexact_software_refusal_is_unknown(message: str, suffix: str) -> None:
    assert (
        linux_testnet_service.native_install_failure_category("install.sh: " + message + suffix)
        == "unknown"
    )


@pytest.mark.parametrize(
    "uid,gid,mode",
    [
        (0, 0, stat.S_IFDIR | 0o755),
        (1001, 1002, stat.S_IFDIR | 0o2775),
        (0, 0, stat.S_IFLNK | 0o777),
    ],
)
def test_opt_metadata_records_actual_owner_and_mode_without_following_or_mutating(
    monkeypatch: pytest.MonkeyPatch, uid: int, gid: int, mode: int
) -> None:
    def lstat(path: Path) -> os.stat_result:
        assert path == Path("/opt")
        return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))

    monkeypatch.setattr(Path, "lstat", lstat)
    assert linux_testnet_service.opt_metadata() == {
        "uid": uid,
        "gid": gid,
        "mode": format(stat.S_IMODE(mode), "04o"),
        "directory": stat.S_ISDIR(mode),
        "symlink": stat.S_ISLNK(mode),
    }


def test_opt_stat_failure_keeps_only_unknown_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    def lstat(path: Path) -> os.stat_result:
        raise OSError("private-provider-message")

    monkeypatch.setattr(Path, "lstat", lstat)
    assert linux_testnet_service.opt_metadata() == {
        "uid": None,
        "gid": None,
        "mode": None,
        "directory": None,
        "symlink": None,
    }
