"""Bounded download retries in the loaders: real POSIX loaders, offline fakes, no network."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_loader_cosign import PIN, ROOT, fake_verifier, shell_fixture

SYSTEM = "darwin" if sys.platform == "darwin" else "linux"
ARCH = "arm64" if os.uname().machine in ("arm64", "aarch64") else "amd64"
ARCHIVE = f"zunder-guard-v0.0.0-{SYSTEM}-{ARCH}.tar.gz"
COSIGN = f"cosign-{SYSTEM}-{ARCH}"


def flaky_fixture(
    tmp_path: Path, name: str, failures: int, refusal: str = ""
) -> tuple[Path, dict[str, str], Path]:
    """The offline fixture, with `name` failing `failures` times after writing a partial file."""
    release, env, prefix = shell_fixture(tmp_path, refusal)
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
        "with open(os.environ['CURL_LOG'] + '.args', 'a') as log:\n"
        "    log.write(' '.join(sys.argv[1:-3]) + '\\n')\n"
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
    # Every try is bounded, so a stalled server ends the try instead of hanging the loader.
    bounded = (
        "-fsSL --proto =https,file --connect-timeout 20"
        " --speed-limit 1024 --speed-time 60 --retry 3"
    )
    assert set(lines(tmp_path / "curl-log.args")) == {bounded}
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


TAMPERED = [
    ("i", "installer-hash", "install.sh", "install.sh does not match the signed checksums"),
    ("i", "download-hash", COSIGN, "cosign does not match its pinned SHA-256"),
    ("install.sh", "archive-hash", ARCHIVE, f"checksum mismatch for {ARCHIVE}; refusing"),
    ("install.sh", "download-hash", COSIGN, "cosign download does not match its pinned SHA-256"),
]


@pytest.mark.skipif(os.name == "nt", reason="POSIX loaders")
@pytest.mark.parametrize("entry,refusal,name,message", TAMPERED)
def test_a_complete_tampered_download_is_refused_after_one_fetch(
    tmp_path: Path, entry: str, refusal: str, name: str, message: str
) -> None:
    # curl succeeds with every byte of a file that differs from what is pinned or signed:
    # the retry loop covers transport failures only, never a verification failure.
    release, env, prefix = flaky_fixture(tmp_path, name, 0, refusal)
    result = run(release, entry, env, prefix)
    assert result.returncode != 0
    assert not (prefix / "zunder-guard").exists()
    tries = [line for line in lines(tmp_path / "curl-log") if line.split()[0] == name]
    assert tries == [name + " fresh"]
    assert lines(tmp_path / "sleep-log") == []
    assert "trying again" not in result.stderr
    assert message in result.stderr.splitlines()[-1], result.stderr


def powershell_function(path: Path, name: str) -> str:
    """The text of a PowerShell function, from its `function` line to its closing brace."""
    source = path.read_text()
    start = source.index(f"function {name}(")
    indent = source[source.rindex("\n", 0, start) + 1 : start]
    end = source.index("\n" + indent + "}\n", start)
    return source[start : end + len(indent) + 3]


def test_per_user_powershell_download_mirrors_the_posix_loop() -> None:
    # Static: PowerShell is not installed on every machine that runs this suite; the
    # executable twin below runs wherever powershell.exe or pwsh is.
    body = powershell_function(ROOT / "loader/i.ps1", "Get-Asset")
    assert "for ($Try = 1; $Try -le 4; $Try++)" in body
    assert "$Pause = 2" in body and "$Pause *= 2" in body
    # A fresh file before each try and no partial file after a failed one.
    assert body.count("[IO.File]::Delete($To)") == 2
    loop = body[body.index("for ($Try") :]
    assert loop.index("[IO.File]::Delete($To)") < loop.index("Invoke-WebRequest")
    assert 'Invoke-WebRequest -UseBasicParsing -Uri "$From/$Name" -OutFile $To @Bounds; break' in (
        body
    )
    # Each try is bounded without capping the transfer; PowerShell 5.1 has no retry parameter.
    assert "$Bounds = @{ TimeoutSec = 20 }" in body
    assert "$Bounds.OperationTimeoutSeconds = 60" in body
    assert body.count("Invoke-WebRequest -UseBasicParsing") == 1
    # A failed try's error response is closed, so no later try waits for its connection.
    catch = body[body.index("catch {", body.index("for ($Try")) :]
    assert catch.index("$Cause.Response.Close()") < catch.index("Start-Sleep")
    assert "if ($Cause -is [Net.WebException] -and $Cause.Response)" in catch
    # The final message is the one from before retries existed.
    assert (
        'throw "download failed: $From/$Name ($Failure); refusing, nothing was installed"' in body
    )
    # Verification is untouched and runs once, after the download, outside the loop.
    script = (ROOT / "loader/i.ps1").read_text()
    assert "Get-Sha256" not in body and "Invoke-ZgReleaseVerifier" not in body
    assert script.count("if ((Get-Sha256 $Cosign) -ne $CosignSha256)") == 1


def test_machine_powershell_download_retries_only_its_own_file() -> None:
    shared = powershell_function(ROOT / "windows/bootstrap.ps1.inc", "Get-ZgAsset")
    for copy in ("loader/i.ps1", "windows/service.ps1"):
        assert powershell_function(ROOT / copy, "Get-ZgAsset") == shared, copy
    https = shared[: shared.index("} elseif ([IO.Directory]::Exists($Source))")]
    assert "for ($attempt = 1; $attempt -le 4; $attempt++)" in https
    assert "$pause = 2" in https and "$pause *= 2" in https
    assert "Microsoft.PowerShell.Utility\\Start-Sleep -Seconds $pause" in https
    # Bounded: 20 s to connect and receive the headers, 60 s without a byte ends a read.
    assert "$request.Timeout = 20000" in https
    assert "$request.ReadWriteTimeout = 60000" in https
    assert "WebClient" not in https
    # The file is created with CreateNew (New-ZgSecureFile) on every try; only a file this try
    # created is deleted, and a refused existing entry or path is final.
    assert https.count("New-ZgSecureFile $Destination") == 1
    assert https.count("[IO.File]::Delete($Destination)") == 1
    assert "if ($step -eq 'copy') { [IO.File]::Delete($Destination) }" in https
    assert "if ($step -eq 'create' -or $attempt -ge 4) { throw }" in https
    order = [https.index(f"$step = '{step}'") for step in ("open", "create", "copy", "done")]
    assert order == sorted(order)
    assert "if ($step -eq 'done') { Assert-ZgPath $Destination; return }" in https
    # A short body is a failed try; a failed try aborts its request and closes an error
    # response before the next one (two connections per host on .NET Framework).
    assert "if ($response.ContentLength -ge 0 -and $received -ne $response.ContentLength)" in https
    catch = https[https.index("} catch {") : https.index("} finally {\n")]
    close = "if ($cause -is [Net.WebException] -and $cause.Response) { $cause.Response.Close() }"
    assert close in catch
    assert catch.index("$request.Abort()") < catch.index("throw")
    assert "$request = $null" in https
    # Diagnostics stay fixed categories: no path, URL or exception text in the retry line.
    notice = re.search(r'Write-Host "(Release download try[^"]*)"', https)
    assert notice is not None
    assert notice[1] == "Release download try $attempt of 4 failed; trying again in ${pause}s."
    # The offline branch is unchanged, and verification stays with the caller.
    assert "Copy-ZgSecureFile $inputStream $Destination" in shared
    assert "Confirm-ZgRelease" not in shared and "Get-ZgHash" not in shared


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe", "pwsh"])
@pytest.mark.parametrize("failures", [3, 99])
def test_per_user_powershell_download_runs_the_loop(
    tmp_path: Path, shell: str, failures: int
) -> None:
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} is unavailable")

    def quote(value: Path) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    log, sleeps, stage = tmp_path / "tries", tmp_path / "sleeps", tmp_path / "stage"
    loader = quote(ROOT / "loader/i.ps1")
    command = f"""
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile({loader},[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'loader parse failed' }}
$definition=$ast.Find({{
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-Asset'
}},$true)
. ([scriptblock]::Create($definition.Extent.Text))
$Tmp={quote(stage)}
New-Item -ItemType Directory -Path $Tmp | Out-Null
$global:Failed=0
# Load the real cmdlet before the fake shadows its name: Get-Asset asks the cmdlet (by
# command type) whether it has -OperationTimeoutSeconds, and a shadowing function stops
# module auto-loading.
Import-Module Microsoft.PowerShell.Utility
function Invoke-WebRequest {{
  param([switch]$UseBasicParsing,[string]$Uri,[string]$OutFile,[int]$TimeoutSec,[int]$OperationTimeoutSeconds)
  $state = if ([IO.File]::Exists($OutFile)) {{ 'stale' }} else {{ 'fresh' }}
  [IO.File]::AppendAllText({quote(log)},"$Uri $state $TimeoutSec $OperationTimeoutSeconds`n")
  if ($global:Failed -lt {failures}) {{
    $global:Failed++
    [IO.File]::WriteAllText($OutFile,'partial body of a reset connection')
    throw 'connection reset fixture'
  }}
  [IO.File]::WriteAllText($OutFile,'complete body')
}}
function Start-Sleep {{
  param([int]$Seconds)
  [IO.File]::AppendAllText({quote(sleeps)},"$Seconds`n")
}}
try {{
  $result = Get-Asset 'SHA256SUMS' 'https://release.invalid/v0.0.0'
  Write-Host "RESULT:$result"
  Write-Host ('BODY:' + [IO.File]::ReadAllText($result))
}} catch {{ Write-Host "ERROR:$($_.Exception.Message)" }}
"""
    result = subprocess.run(
        [executable, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    tries = lines(log)
    assert len(tries) == 4, output
    url = "https://release.invalid/v0.0.0/SHA256SUMS"
    # Every try starts without the partial file and is bounded; the read bound only where
    # the cmdlet offers it (PowerShell 7.4 or newer).
    assert len(set(tries)) == 1 and tries[0] in {f"{url} fresh 20 60", f"{url} fresh 20 0"}
    assert lines(sleeps) == ["2", "4", "8"]
    assert output.count("of 4 failed; trying again in") == 3
    target = stage / "SHA256SUMS"
    if failures == 3:
        assert f"RESULT:{target}" in output and "BODY:complete body" in output
    else:
        expected = (
            f"ERROR:download failed: {url} (connection reset fixture);"
            " refusing, nothing was installed"
        )
        assert expected in output
        assert not target.exists()


def test_windows_download_test_rewrites_still_match_the_loader_and_runs_on_both_shells() -> None:
    # windows-download.ps1 rewrites its own copy of each function, each text exactly once;
    # catch a loader edit that would break it here, before the Windows job.
    test = (ROOT / "test/windows-download.ps1").read_text()
    machine = powershell_function(ROOT / "loader/i.ps1", "Get-ZgAsset")
    user = powershell_function(ROOT / "loader/i.ps1", "Get-Asset")
    for old in (
        "$Source.StartsWith('https://')",
        "Microsoft.PowerShell.Utility\\Start-Sleep",
        "$request.ReadWriteTimeout = 60000",
    ):
        assert machine.count(old) == 1, old
        assert "'" + old.replace("'", "''") + "'" in test, old
    for old in ("$From -like 'https://*'", "$Bounds.OperationTimeoutSeconds = 60"):
        assert user.count(old) == 1, old
        assert "'" + old.replace("'", "''") + "'" in test, old
    # Production values are never rewritten outside the stall cases.
    assert "$request.Timeout = 20000" not in test and "TimeoutSec = 20" not in test
    # Private source keeps the workflows in deploy/guard/github/workflows; the export moves
    # them to .github/workflows.
    ci = ROOT / "github/workflows/ci.yml"
    if not ci.is_file():
        ci = ROOT.parents[1] / ".github/workflows/ci.yml"
    workflow = ci.read_text()
    job = workflow[workflow.index("\n  windows-main:") : workflow.index("\n  windows-tests:")]
    steps = re.findall(r"shell: (\w+)\n(?:\s+timeout-minutes: \d+\n)?\s+run: (\S+)", job)
    assert ("powershell", "./deploy/guard/test/windows-download.ps1") in steps
    assert ("pwsh", "./deploy/guard/test/windows-download.ps1") in steps
    assert (ROOT / "test/download-fixture-server.py").is_file()
