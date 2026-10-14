"""Offline cosign selection: real loaders, synthetic releases, no network or keys."""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PIN = "v3.1.3"
VERSION = "v0.0.0"
IDENTITY = (
    f"https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/{VERSION}"
)
REPORTS = [
    ("", 0, False),
    ("GitVersion:    v3.1.3\n", 0, True),
    ("GitVersion:    v2.4.1\n", 0, False),
    ("GitVersion:    v4.0.0\n", 0, False),
    ("GitVersion:    v3.1.30\n", 0, False),
    ("GitVersion:    v3.1.3-dev\n", 0, False),
    ("GitVersion:    v3.1.3 extra\nGitVersion: v3.1.3\n", 0, False),
    ("GitVersion:    V3.1.3\n", 0, False),
    ("GitVersion:    v3.1.3 extra\n", 0, False),
    ("GitVersion:    v3.1.3\nGitVersion: v3.1.3\n", 0, False),
    ("unknown version\n", 0, False),
    ("GitVersion:    v3.1.3\n", 7, False),
    ("GitVersion:\tv3.1.3\r\n", 0, True),
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shell_fixture(tmp_path: Path, refusal: str = "") -> tuple[Path, dict[str, str], Path]:
    release = tmp_path / "release"
    release.mkdir()
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    calls = tmp_path / "calls"
    downloaded = tmp_path / "downloaded-cosign"
    downloaded.write_text(
        '#!/bin/sh\nprintf "downloaded %s\\n" "$*" >> "$COSIGN_CALLS"\n'
        + (ROOT / "test/fake-cosign").read_text().replace("#!/bin/sh\n", "", 1)
    )
    downloaded.chmod(0o755)
    installer = (ROOT / "install.sh").read_text().replace("@VERSION@", VERSION)
    installer = re.sub(r"(?<=COSIGN_SHA256=)[0-9a-f]{64}", digest(downloaded), installer)
    (release / "install.sh").write_text(installer)
    loader = (ROOT / "loader/i.sh").read_text().replace("@VERSION@", VERSION)
    loader = re.sub(r"(?<=H=)[0-9a-f]{64}", digest(downloaded), loader)
    (release / "i").write_text(loader)
    system = "darwin" if sys.platform == "darwin" else "linux"
    arch = "arm64" if os.uname().machine in ("arm64", "aarch64") else "amd64"
    archive = release / f"zunder-guard-{VERSION}-{system}-{arch}.tar.gz"
    (release / "zunder-guard").write_text('#!/bin/sh\necho "zunder-guard 0.0.0"\n')
    (release / "zunder-guard").chmod(0o755)
    notices = ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md")
    for name in notices:
        (release / name).write_text("inert notice fixture")
    with tarfile.open(archive, "w:gz") as tar:
        for name in ("zunder-guard", *notices):
            tar.add(release / name, arcname=name)
    sums = release / "SHA256SUMS"
    sums.write_text(
        f"{digest(archive)}  {archive.name}\n{digest(release / 'install.sh')}  install.sh\n"
    )
    bundle = {"identity": IDENTITY, "sha256": digest(sums)}
    if refusal == "signature":
        bundle["identity"] += "-other"
    (release / "SHA256SUMS.sigstore.json").write_text(json.dumps(bundle))
    if refusal == "checksums-hash":
        with sums.open("a") as stream:
            stream.write("0" * 64 + "  extra\n")
    if refusal == "archive-hash":
        with archive.open("ab") as stream:
            stream.write(b"tampered")
    if refusal == "download-hash":
        with downloaded.open("a") as stream:
            stream.write("# tampered\n")
    if refusal == "installer-hash":
        with (release / "install.sh").open("a") as stream:
            stream.write("# tampered\n")
    # Replace curl with an offline copier; any unexpected URL fails closed.
    curl = fakebin / "curl"
    curl.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, shutil, sys, urllib.parse\n"
        "url = sys.argv[-1]\n"
        f"expected = 'https://github.com/sigstore/cosign/releases/download/{PIN}/cosign-{system}-{arch}'\n"
        "if url == expected:\n"
        "    source = os.environ['COSIGN_DOWNLOAD']\n"
        "    with open(os.environ['COSIGN_CALLS'], 'a') as log: log.write('fetch pinned\\n')\n"
        "elif url.startswith('file://'):\n"
        "    source = urllib.parse.unquote(urllib.parse.urlparse(url).path)\n"
        "else: raise SystemExit('unexpected network URL: ' + url)\n"
        "shutil.copyfile(source, sys.argv[sys.argv.index('-o') + 1])\n"
    )
    curl.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    prefix = tmp_path / "installed"
    env = {
        **os.environ,
        "PATH": str(fakebin) + os.pathsep + os.environ["PATH"],
        "HOME": str(home),
        "ZUNDER_GUARD_BASE_URL": release.as_uri(),
        "COSIGN_CALLS": str(calls),
        "COSIGN_DOWNLOAD": str(downloaded),
    }
    env.pop("ZUNDER_GUARD_COSIGN", None)
    return release, env, prefix


def fake_verifier(path: Path, report: str, code: int, windows: bool = False) -> None:
    if windows:
        path.write_text(
            '@echo off\necho local %*>> "%COSIGN_CALLS%"\n'
            'if not "%~1"=="version" exit /b 91\necho probe-diagnostic-fixture 1>&2\n'
            + "".join(f"echo {line}\n" for line in report.splitlines())
            + f"exit /b {code}\n"
        )
    else:
        path.write_text(
            '#!/bin/sh\nprintf "local %s\\n" "$*" >> "$COSIGN_CALLS"\n'
            '[ "$1" = version ] || exit 91\n' + f"printf '%s' {shlex.quote(report)}\nexit {code}\n"
        )
        path.chmod(0o755)


@pytest.mark.skipif(os.name == "nt", reason="POSIX loaders")
@pytest.mark.parametrize("entry", ["i", "install.sh"])
@pytest.mark.parametrize("location", ["path", "override"])
@pytest.mark.parametrize("report,code,accepted", REPORTS)
def test_shell_cosign_selection(
    tmp_path: Path, entry: str, location: str, report: str, code: int, accepted: bool
) -> None:
    release, env, prefix = shell_fixture(tmp_path)
    verifier = tmp_path / "fakebin" / "cosign"
    # Delegate verification to the existing identity/issuer/hash-checking double.
    double = ROOT / "test/fake-cosign"
    fake_verifier(verifier, report, code)
    verifier.write_text(
        verifier.read_text().replace(
            '[ "$1" = version ] || exit 91',
            '[ "$1" = version ] || exec ' + shlex.quote(str(double)) + ' "$@"',
        )
    )
    if location == "override":
        override = tmp_path / "explicit cosign"
        verifier.rename(override)
        env["ZUNDER_GUARD_COSIGN"] = str(override)
    result = subprocess.run(
        ["sh", str(release / entry), "--install-only", "--prefix", str(prefix)],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (prefix / "zunder-guard").is_file()
    assert "probe-diagnostic-fixture" not in result.stdout + result.stderr
    calls = (tmp_path / "calls").read_text()
    assert ("fetch pinned" not in calls) is accepted
    assert ("local verify-blob" in calls) is accepted
    assert "local version" in calls
    if not accepted:
        assert calls.count("fetch pinned") == 1
        assert "downloaded verify-blob" in calls


@pytest.mark.skipif(os.name == "nt", reason="POSIX loaders")
@pytest.mark.parametrize("entry", ["i", "install.sh"])
@pytest.mark.parametrize(
    "refusal", ["download-hash", "signature", "checksums-hash", "archive-hash"]
)
def test_shell_fallback_keeps_verification(tmp_path: Path, entry: str, refusal: str) -> None:
    release, env, prefix = shell_fixture(tmp_path, refusal)
    fake_verifier(tmp_path / "fakebin/cosign", "GitVersion: v2.4.1\n", 0)
    result = subprocess.run(
        ["sh", str(release / entry), "--install-only", "--prefix", str(prefix)],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert not (prefix / "zunder-guard").exists()
    calls = (tmp_path / "calls").read_text()
    assert "fetch pinned" in calls and "local verify-blob" not in calls
    if refusal == "download-hash":
        assert "downloaded verify-blob" not in calls
        assert "SHA-256" in result.stdout + result.stderr
    else:
        assert "downloaded verify-blob" in calls


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe", "pwsh"])
@pytest.mark.parametrize("location", ["path", "override"])
@pytest.mark.parametrize("report,code,accepted", REPORTS)
def test_powershell_cosign_selection(
    tmp_path: Path,
    shell: str,
    location: str,
    report: str,
    code: int,
    accepted: bool,
    bad_download: bool = False,
) -> None:
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} is unavailable")
    source = ROOT / "loader/i.ps1"
    script = source.read_text()
    start = script.index("    $Cosign = $env:ZUNDER_GUARD_COSIGN")
    end = script.index("    # Stream verifier diagnostics", start)
    verifier = tmp_path / ("cosign.cmd" if os.name == "nt" else "cosign")
    fake_verifier(verifier, report, code, os.name == "nt")

    def quote(value: Path) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    env = {**os.environ, "COSIGN_CALLS": str(tmp_path / "calls")}
    env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
    env.pop("ZUNDER_GUARD_COSIGN", None)
    if location == "override":
        env["ZUNDER_GUARD_COSIGN"] = str(verifier)
    command = f"""
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile({quote(source)},[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'loader parse failed' }}
$definition=$ast.Find({{
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Test-ZgCosignVersion'
}},$true)
. ([scriptblock]::Create($definition.Extent.Text))
$CosignVersion='{PIN}'; $CosignSha256='fixture-digest'
function Get-Asset($Name,$From) {{
  if ($Name -cne 'cosign-windows-amd64.exe' -or
    $From -cne 'https://github.com/sigstore/cosign/releases/download/{PIN}') {{
    throw 'unexpected download'
  }}
  Write-Host 'FETCH-PINNED'
  return 'pinned-download-fixture'
}}
function Get-Sha256($Path) {{
  if ($Path -cne 'pinned-download-fixture') {{ throw 'wrong hash input' }}
  Write-Host 'HASH-CHECKED'
  return 'fixture-digest'
}}
{script[start:end]}
if ($ErrorActionPreference -ne 'Stop') {{ throw 'error preference was not restored' }}
Write-Host "SELECTED:$Cosign"
"""
    if bad_download:
        command = command.replace("return 'fixture-digest'", "return 'tampered-digest'")
    result = subprocess.run(
        [executable, "-NoProfile", "-Command", command],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = result.stdout + result.stderr
    if bad_download:
        assert result.returncode != 0
        assert "FETCH-PINNED" in output and "HASH-CHECKED" in output
        assert "does not match its pinned SHA-256" in output and "SELECTED:" not in output
        return
    assert result.returncode == 0, output
    assert "probe-diagnostic-fixture" not in output
    assert ("FETCH-PINNED" not in output) is accepted
    assert ("HASH-CHECKED" not in output) is accepted
    assert (tmp_path / "calls").read_text().strip() == "local version"
    assert "SELECTED:" + (str(verifier) if accepted else "pinned-download-fixture") in output


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe", "pwsh"])
def test_powershell_fallback_rejects_download_hash(tmp_path: Path, shell: str) -> None:
    test_powershell_cosign_selection(
        tmp_path, shell, "path", "GitVersion: v2.4.1\n", 0, False, bad_download=True
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX loader")
def test_shell_loader_refuses_tampered_installer(tmp_path: Path) -> None:
    release, env, prefix = shell_fixture(tmp_path, "installer-hash")
    fake_verifier(tmp_path / "fakebin/cosign", "GitVersion: v2.4.1\n", 0)
    result = subprocess.run(
        ["sh", str(release / "i"), "--install-only", "--prefix", str(prefix)],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "install.sh does not match the signed checksums" in result.stderr
    assert not (prefix / "zunder-guard").exists()
