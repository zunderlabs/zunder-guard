"""slsa-verifier is admitted by its pinned SHA-256; only transport failures are retried.

Fake uname and curl; the real script. The success path runs a copy whose pin is
replaced by the fake binary's digest, so the shipped script carries no test hook.
"""

import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

GUARD = Path(__file__).resolve().parents[2]
SCRIPT = GUARD / "github/install-slsa-verifier.sh"
BINARY = b"fake slsa-verifier binary\n"
# Two independent sources agree: SHA256SUM.md of slsa-framework/slsa-verifier at
# 748161aa and the digests GitHub records for the v2.7.1 release assets.
PINS = {
    "slsa-verifier-linux-amd64": "946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339",
    "slsa-verifier-linux-arm64": "5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061",
    "slsa-verifier-darwin-amd64": (
        "4baf25415727821f847a38bccedc86c3e5b17cbfc2eb534cd554feb6c856d6f1"
    ),
    "slsa-verifier-darwin-arm64": (
        "39abfcf5f1d690c3e889ce3d2d6a8b87711424d83368511868d414e8f8bcb05c"
    ),
    "slsa-verifier-windows-amd64.exe": (
        "1d8f61ad747ecc3d375d2a563cebf2991748b7da1a9bda9a500804c3c499e3c0"
    ),
    "slsa-verifier-windows-arm64.exe": (
        "44144e98328d221f0490ef6b4a58a465defe8f697f387abbbf07ef5adb68d4ac"
    ),
}


def install(
    tmp_path: Path,
    plan: list[str],
    *,
    system: str = "Linux",
    machine: str = "x86_64",
    script: Path = SCRIPT,
) -> subprocess.CompletedProcess[str]:
    """`plan` per curl attempt: "ok", "reset" (exit 56), "timeout" (exit 28), or an HTTP code."""
    fakebin = tmp_path / "bin"
    fakebin.mkdir(exist_ok=True)
    (tmp_path / "plan").write_text("\n".join(plan) + "\n")
    (tmp_path / "binary").write_bytes(BINARY)
    (fakebin / "uname").write_text(
        f'#!/bin/sh\ncase "$1" in -s) echo {system} ;; -m) echo {machine} ;; *) exit 9 ;; esac\n'
    )
    (fakebin / "curl").write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, shutil, sys\n"
        "base = pathlib.Path(sys.argv[0]).resolve().parent.parent\n"
        "args = sys.argv[1:]\n"
        "with open(base / 'calls', 'a') as calls: calls.write(' '.join(args) + '\\n')\n"
        "n = sum(1 for _ in open(base / 'calls')) - 1\n"
        "step = (base / 'plan').read_text().split()[n]\n"
        "out = pathlib.Path(args[args.index('-o') + 1])\n"
        "if step == 'reset':\n"
        "    sys.stdout.write('000'); sys.stderr.write('curl: (56) Recv failure\\n')\n"
        "    raise SystemExit(56)\n"
        "if step == 'timeout':\n"
        "    sys.stdout.write('000'); raise SystemExit(28)\n"
        "if step == 'ok':\n"
        "    shutil.copyfile(base / 'binary', out); sys.stdout.write('200'); raise SystemExit(0)\n"
        "out.write_text('error page'); sys.stdout.write(step)\n"
    )
    for name in ("uname", "curl"):
        (fakebin / name).chmod(0o755)
    temp = tmp_path / "runner"
    temp.mkdir(exist_ok=True)
    (tmp_path / "github_path").write_text("")
    env = dict(
        os.environ,
        PATH=str(fakebin) + os.pathsep + os.environ["PATH"],
        RUNNER_TEMP=str(temp),
        GITHUB_PATH=str(tmp_path / "github_path"),
        SLSA_INSTALL_PAUSE="0",
    )
    return subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True, check=False, timeout=60
    )


def calls(tmp_path: Path) -> list[str]:
    path = tmp_path / "calls"
    return path.read_text().splitlines() if path.exists() else []


def pinned_to_fake(tmp_path: Path) -> Path:
    copy = tmp_path / "install-slsa-verifier.sh"
    text = SCRIPT.read_text()
    real = PINS["slsa-verifier-linux-amd64"]
    assert text.count(real) == 1
    copy.write_text(text.replace(real, hashlib.sha256(BINARY).hexdigest()))
    return copy


def installed(tmp_path: Path) -> list[str]:
    return [line for line in (tmp_path / "github_path").read_text().splitlines() if line]


def test_the_shipped_pins_are_the_published_v2_7_1_digests() -> None:
    text = SCRIPT.read_text()
    found = dict(re.findall(r"asset=(slsa-verifier-[a-z0-9.-]+)\s+pin=([0-9a-f]{64})", text))
    assert found == PINS
    assert "VERSION=v2.7.1" in text


@pytest.mark.parametrize(
    "plan",
    [["ok"], ["reset", "ok"], ["timeout", "503", "ok"], ["429", "ok"], ["502", "reset", "ok"]],
)
def test_transport_failures_are_retried_then_the_pinned_binary_is_installed(
    tmp_path: Path, plan: list[str]
) -> None:
    result = install(tmp_path, plan, script=pinned_to_fake(tmp_path))
    assert result.returncode == 0, result.stderr
    assert len(calls(tmp_path)) == len(plan)
    (directory,) = installed(tmp_path)
    binary = Path(directory) / "slsa-verifier"
    assert binary.read_bytes() == BINARY and os.access(binary, os.X_OK)
    assert all("--proto =https --proto-redir =https" in call for call in calls(tmp_path))
    assert calls(tmp_path)[0].endswith(
        "https://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1/"
        "slsa-verifier-linux-amd64"
    )


@pytest.mark.parametrize(
    ("plan", "attempts"),
    [
        (["reset", "reset", "reset", "ok"], 3),  # bounded
        (["503", "503", "503", "ok"], 3),
        (["404", "ok"], 1),  # an answer, not a transport failure
        (["403", "ok"], 1),
        (["302", "ok"], 1),
    ],
)
def test_other_answers_and_exhausted_retries_fail_closed(
    tmp_path: Path, plan: list[str], attempts: int
) -> None:
    result = install(tmp_path, plan, script=pinned_to_fake(tmp_path))
    assert result.returncode != 0
    assert len(calls(tmp_path)) == attempts
    # Refused by the download loop itself, never by a later step tripping on its leftovers.
    assert "slsa-verifier v2.7.1 download failed" in result.stderr
    assert installed(tmp_path) == []
    assert not any((tmp_path / "runner").rglob("slsa-verifier*download"))


@pytest.mark.parametrize(
    ("system", "machine", "asset"),
    [
        ("Linux", "x86_64", "slsa-verifier-linux-amd64"),
        ("Linux", "aarch64", "slsa-verifier-linux-arm64"),
        ("Darwin", "arm64", "slsa-verifier-darwin-arm64"),
        ("Darwin", "x86_64", "slsa-verifier-darwin-amd64"),
        ("MINGW64_NT-10.0-26100", "x86_64", "slsa-verifier-windows-amd64.exe"),
    ],
)
def test_a_checksum_mismatch_is_refused_once_and_never_retried(
    tmp_path: Path, system: str, machine: str, asset: str
) -> None:
    # The shipped script: the fake bytes cannot match the real pins.
    result = install(tmp_path, ["ok", "ok", "ok"], system=system, machine=machine)
    assert result.returncode != 0
    assert "differs from its pinned SHA-256" in result.stderr
    (call,) = calls(tmp_path)
    assert call.endswith("/v2.7.1/" + asset)
    assert installed(tmp_path) == []
    assert not any((tmp_path / "runner").rglob("slsa-verifier*download"))


@pytest.mark.parametrize(("system", "machine"), [("Linux", "riscv64"), ("FreeBSD", "x86_64")])
def test_an_unpinned_platform_is_refused_before_any_download(
    tmp_path: Path, system: str, machine: str
) -> None:
    result = install(tmp_path, ["ok"], system=system, machine=machine)
    assert result.returncode != 0 and calls(tmp_path) == []


def test_a_second_install_in_the_same_job_is_refused(tmp_path: Path) -> None:
    script = pinned_to_fake(tmp_path)
    assert install(tmp_path, ["ok"], script=script).returncode == 0
    assert install(tmp_path, ["ok", "ok"], script=script).returncode != 0
    assert len(calls(tmp_path)) == 1


def workflows() -> Path:
    private = GUARD / "github/workflows"
    return private if private.is_dir() else GUARD.parents[1] / ".github/workflows"


def test_the_installer_action_is_replaced_before_every_verification() -> None:
    install_step = "bash deploy/guard/github/install-slsa-verifier.sh"
    replaced = 0
    for name in ("verify.yml", "install-matrix.yml", "journey.yml", "promote.yml"):
        text = (workflows() / name).read_text()
        assert "slsa-verifier/actions/installer" not in text
        document: Any = yaml.safe_load(text)
        for job_name, job in document["jobs"].items():
            steps = job.get("steps") or []
            runs = [str(step.get("run", "")) for step in steps]
            installs = [i for i, run in enumerate(runs) if install_step in run]
            if not installs:
                continue
            replaced += len(installs)
            assert len(installs) == 1, (name, job_name)
            checkout = [
                i for i, step in enumerate(steps) if "actions/checkout@" in str(step.get("uses"))
            ]
            assert checkout and checkout[0] < installs[0], (name, job_name)
            using = [i for i, run in enumerate(runs) if "verify-release-assets.sh" in run]
            assert all(installs[0] < i for i in using), (name, job_name)
            step = steps[installs[0]]
            assert step["shell"] == "bash" and "if" not in step and "env" not in step
    assert replaced == 16
