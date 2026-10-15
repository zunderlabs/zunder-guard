"""Bounded download retries in the loaders: real POSIX loaders, offline fakes, no network."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_loader_cosign import PIN, fake_verifier, shell_fixture

SYSTEM = "darwin" if sys.platform == "darwin" else "linux"
ARCH = "arm64" if os.uname().machine in ("arm64", "aarch64") else "amd64"
ARCHIVE = f"zunder-guard-v0.0.0-{SYSTEM}-{ARCH}.tar.gz"
COSIGN = f"cosign-{SYSTEM}-{ARCH}"


def flaky_fixture(tmp_path: Path, name: str, failures: int) -> tuple[Path, dict[str, str], Path]:
    """The offline fixture, with `name` failing `failures` times after writing a partial file."""
    release, env, prefix = shell_fixture(tmp_path)
    fake_verifier(tmp_path / "fakebin/cosign", "GitVersion: v2.4.1\n", 0)  # forces the pinned get
    fakebin = tmp_path / "fakebin"
    offline = fakebin / "curl-offline"
    (fakebin / "curl").rename(offline)
    (fakebin / "curl").write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "url = sys.argv[-1]\n"
        "target = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
        "name = url.rsplit('/', 1)[-1]\n"
        "with open(os.environ['CURL_LOG'], 'a') as log:\n"
        "    log.write(name + (' stale' if target.exists() else ' fresh') + '\\n')\n"
        "if name == os.environ['FLAKY_NAME']:\n"
        "    count = pathlib.Path(os.environ['CURL_LOG'] + '.failed')\n"
        "    done = int(count.read_text()) if count.exists() else 0\n"
        "    if done < int(os.environ['FLAKY_FAILS']):\n"
        "        count.write_text(str(done + 1))\n"
        "        target.write_bytes(b'partial body of a reset connection')\n"
        "        raise SystemExit(56)\n"
        "offline = os.environ['OFFLINE_CURL']\n"
        "os.execv(offline, [offline, *sys.argv[1:]])\n"
    )
    (fakebin / "curl").chmod(0o755)
    # The pauses are recorded, not slept, so the test stays fast.
    (fakebin / "sleep").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SLEEP_LOG"\n')
    (fakebin / "sleep").chmod(0o755)
    env.update(
        CURL_LOG=str(tmp_path / "curl-log"),
        SLEEP_LOG=str(tmp_path / "sleep-log"),
        FLAKY_NAME=name,
        FLAKY_FAILS=str(failures),
        OFFLINE_CURL=str(offline),
    )
    return release, env, prefix


def run(
    release: Path, entry: str, env: dict[str, str], prefix: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(release / entry), "--install-only", "--prefix", str(prefix)],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=60,
    )


def lines(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


CASES = [
    ("i", "install.sh"),
    ("i", "SHA256SUMS"),
    ("i", COSIGN),
    ("install.sh", "SHA256SUMS"),
    ("install.sh", ARCHIVE),
    ("install.sh", COSIGN),
]


@pytest.mark.skipif(os.name == "nt", reason="POSIX loaders")
@pytest.mark.parametrize("entry,name", CASES)
def test_transient_failures_are_retried_with_a_fresh_file(
    tmp_path: Path, entry: str, name: str
) -> None:
    release, env, prefix = flaky_fixture(tmp_path, name, 3)
    result = run(release, entry, env, prefix)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (prefix / "zunder-guard").is_file()
    tries = [line for line in lines(tmp_path / "curl-log") if line.split()[0] == name]
    # Three failures and the fourth try succeeds; every try starts without the partial file.
    assert tries[:4] == [name + " fresh"] * 4
    assert all(line.endswith(" fresh") for line in lines(tmp_path / "curl-log"))
    assert lines(tmp_path / "sleep-log") == ["2", "4", "8"]
    assert "download failed" not in result.stderr
    assert result.stderr.count("of 4 failed; trying again in") == 3
    # The pinned cosign was fetched once successfully and still checked against its SHA-256.
    calls = (tmp_path / "calls").read_text()
    assert calls.count("fetch pinned") == 1 and "downloaded verify-blob" in calls


@pytest.mark.skipif(os.name == "nt", reason="POSIX loaders")
@pytest.mark.parametrize("entry,name", CASES)
def test_four_failed_tries_refuse_with_the_classified_message(
    tmp_path: Path, entry: str, name: str
) -> None:
    release, env, prefix = flaky_fixture(tmp_path, name, 99)
    result = run(release, entry, env, prefix)
    assert result.returncode != 0
    assert not (prefix / "zunder-guard").exists()
    tries = [line for line in lines(tmp_path / "curl-log") if line.split()[0] == name]
    assert tries == [name + " fresh"] * 4
    assert lines(tmp_path / "sleep-log") == ["2", "4", "8"]
    if name == COSIGN:
        url = f"https://github.com/sigstore/cosign/releases/download/{PIN}/{COSIGN}"
    else:
        url = release.as_uri() + "/" + name
    if entry == "i":  # the loader's own get: install.sh never ran
        expected = f"zunder-guard: download failed: {url}; refusing, nothing was run"
    else:
        expected = f"install.sh: download failed: {url}"
    assert result.stderr.splitlines()[-1] == expected, result.stderr
