"""Hosted Windows only: measure candidate refusal before removing four dump-policy keys."""

import hashlib
import importlib
import json
import os
import platform
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release

POLICY_PATHS = (
    r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
)
POLICY_KEYS = tuple(
    (hive, path) for hive in ("LocalMachine", "CurrentUser") for path in POLICY_PATHS
)
REFUSAL = (
    "zunder-guard: service refused: managed WER or LocalDumps policy "
    "prevents service secret admission"
)
REFUSAL_TOKEN = "windows-crash-policy-refusal"
REMOVAL_TOKEN = "windows-crash-policy-removed"
REMOVAL_NOTE = "policy removed by harness"


class Registry(Protocol):
    def scan(self) -> list[dict[str, str]]: ...
    def exclude(self) -> None: ...
    def remove(self) -> None: ...


class WindowsRegistry:
    def scan(self) -> list[dict[str, str]]:
        winreg = importlib.import_module("winreg")

        rows = []
        for hive, path in POLICY_KEYS:
            root = winreg.HKEY_LOCAL_MACHINE if hive == "LocalMachine" else winreg.HKEY_CURRENT_USER
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
                    status = "present"
            except FileNotFoundError:
                status = "absent"
            except OSError:
                raise LifecycleError("cannot read hosted Windows crash policy") from None
            rows.append(dict(hive=hive, path=path, view="Registry64", status=status))
        return rows

    def exclude(self) -> None:
        # Same per-executable WER exclusion as the installer; no global policy override.
        winreg = importlib.import_module("winreg")

        path = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications"
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        ) as key:
            winreg.SetValueEx(key, "zunder-guard.exe", 0, winreg.REG_DWORD, 1)

    def remove(self) -> None:
        hosted()
        winreg = importlib.import_module("winreg")

        budget = 1024

        def delete(root: int, path: str, depth: int = 0) -> None:
            nonlocal budget
            budget -= 1
            if depth > 32 or budget < 0:
                raise LifecycleError("hosted policy subtree exceeds removal bound")
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    # QueryInfoKey avoids treating an enumeration error as end-of-list.
                    children = [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
                for child in children:
                    delete(root, path + "\\" + child, depth + 1)
                winreg.DeleteKeyEx(root, path, winreg.KEY_WOW64_64KEY, 0)
            except FileNotFoundError:
                return
            except OSError:
                raise LifecycleError("cannot remove hosted Windows crash policy") from None

        for hive, path in POLICY_KEYS:
            delete(
                winreg.HKEY_LOCAL_MACHINE if hive == "LocalMachine" else winreg.HKEY_CURRENT_USER,
                path,
            )


def hosted() -> None:
    if (
        platform.system() != "Windows"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or not importlib.import_module("ctypes").windll.shell32.IsUserAnAdmin()
    ):
        raise LifecycleError(
            "crash-policy removal requires an elevated disposable hosted Windows runner"
        )


def rows_valid(rows: object, *, absent: bool = False) -> bool:
    if not isinstance(rows, list) or len(rows) != len(POLICY_KEYS):
        return False
    for row, (hive, path) in zip(rows, POLICY_KEYS, strict=True):
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("status"), str)
            or row != dict(hive=hive, path=path, view="Registry64", status=row.get("status"))
            or row.get("status") not in ({"absent"} if absent else {"absent", "present"})
        ):
            return False
    return True


def prepare(release: Release, work: Path, env: Mapping[str, str]) -> dict[str, object]:
    hosted()
    return _prepare(release, work, env, WindowsRegistry())


def _prepare(
    release: Release, work: Path, env: Mapping[str, str], registry: Registry
) -> dict[str, object]:
    work.mkdir(mode=0o700)
    before = registry.scan()
    if not rows_valid(before) or not any(row["status"] == "present" for row in before):
        raise LifecycleError(
            "hosted image must expose a readable crash policy for the refusal test"
        )
    body = release.binary("windows-amd64")
    binary = work / "zunder-guard.exe"
    binary.write_bytes(body)
    identity = dict(
        schema=1,
        tag=release.tag,
        commit=release.commit,
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        binary_sha256=hashlib.sha256(body).hexdigest(),
        scope="elevated hosted runner; Registry64; HKCU is runner identity",
    )
    registry.exclude()
    try:
        result = subprocess.run(
            [
                str(binary),
                "--home",
                str(work / "unused-home"),
                "init",
                "--network",
                "testnet",
                "--service-key-check",
                "--no-key",
                "--non-interactive",
                "--key-stdin",
            ],
            input=b"",
            env=env,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        raise LifecycleError("candidate crash-policy refusal probe did not complete") from None
    if (
        result.returncode != 2
        or result.stdout != b""
        or result.stderr not in (REFUSAL.encode() + b"\n", REFUSAL.encode() + b"\r\n")
    ):
        # Never retain unexpected output: this probe receives no key or account.
        raise LifecycleError("candidate did not emit the exact crash-policy refusal")
    if (work / "unused-home").exists():
        raise LifecycleError("policy refusal unexpectedly committed setup state")
    refusal = dict(
        **identity,
        result="passed",
        exit_status=2,
        stdout="",
        stderr=REFUSAL,
        private_stdin_supplied=False,
        before=before,
        coverage=[REFUSAL_TOKEN],
    )
    (work / "refusal.receipt.json").write_text(json.dumps(refusal) + "\n")
    # Refusal is durable before the first deletion. Never remove on a failed probe.
    registry.remove()
    after = registry.scan()
    if not rows_valid(after, absent=True):
        raise LifecycleError("hosted crash-policy removal did not confirm four absent keys")
    removal = dict(
        **identity,
        result="passed",
        crash_dump_policy=REMOVAL_NOTE,
        before=before,
        after=after,
        refusal_sha256=hashlib.sha256((work / "refusal.receipt.json").read_bytes()).hexdigest(),
        coverage=[REMOVAL_TOKEN],
    )
    path = work / "removal.receipt.json"
    path.write_text(json.dumps(removal) + "\n")
    return dict(
        crash_dump_policy=REMOVAL_NOTE,
        windows_policy_receipt_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def admit(release: Release, work: Path, lifecycle: dict[str, Any]) -> None:
    """Refusal and removal are separate measurements, never positive lifecycle credit."""
    paths = [work / name for name in ("refusal.receipt.json", "removal.receipt.json")]
    if any(
        path.is_symlink() or not path.is_file() or path.stat().st_size > 16384 for path in paths
    ):
        raise LifecycleError("bounded Windows policy receipts required")
    refusal, removal = [json.loads(path.read_bytes()) for path in paths]
    if not isinstance(refusal, dict) or not isinstance(removal, dict):
        raise LifecycleError("Windows policy receipt objects required")
    expected = dict(
        schema=1,
        result="passed",
        tag=release.tag,
        commit=release.commit,
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        binary_sha256=hashlib.sha256(release.binary("windows-amd64")).hexdigest(),
        scope="elevated hosted runner; Registry64; HKCU is runner identity",
    )
    if (
        any(any(value.get(k) != v for k, v in expected.items()) for value in (refusal, removal))
        or refusal.get("exit_status") != 2
        or refusal.get("stdout") != ""
        or refusal.get("stderr") != REFUSAL
        or refusal.get("private_stdin_supplied") is not False
        or refusal.get("coverage") != [REFUSAL_TOKEN]
        or not rows_valid(refusal.get("before"))
        or not any(row["status"] == "present" for row in refusal["before"])
        or removal.get("before") != refusal["before"]
        or not rows_valid(removal.get("after"), absent=True)
        or removal.get("coverage") != [REMOVAL_TOKEN]
        or removal.get("crash_dump_policy") != REMOVAL_NOTE
        or removal.get("refusal_sha256") != hashlib.sha256(paths[0].read_bytes()).hexdigest()
        or lifecycle.get("crash_dump_policy") != REMOVAL_NOTE
        or lifecycle.get("windows_policy_receipt_sha256")
        != hashlib.sha256(paths[1].read_bytes()).hexdigest()
    ):
        raise LifecycleError("Windows policy refusal/removal measurements differ")
