"""Negative attack inputs derived from real paper setup; never native custody proof."""

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

from guard_harness.mainnet_evidence import MatrixError
from guard_harness.mainnet_refusals import record
from guard_harness.native_release import Release
from guard_harness.runner import run

FIELDS = ["mode", "network", "allow_mainnet", "api_wallet", "policy.max_trading_equity_usd"]
LITERAL = "a mainnet key comes only on standard input (--key-stdin)"


def configuration(original: str) -> str:
    parsed = tomllib.loads(original)
    if parsed.get("mode") != "paper" or parsed.get("allow_mainnet") is not False:
        raise MatrixError("negative fixture must derive from real paper setup")
    text = original
    for name, value in (
        ("mode", '"mainnet"'),
        ("network", '"mainnet"'),
        ("allow_mainnet", "true"),
        ("api_wallet", '"0x' + "0" * 40 + '"'),
    ):
        pattern = rf"(?m)^{name}\s*=.*$"
        count = len(re.findall(pattern, text))
        if count > 1:
            raise MatrixError("ambiguous top-level fixture field")
        text = re.sub(pattern, f"{name} = {value}", text) if count else f"{name} = {value}\n" + text
    cap = r"(?m)^max_trading_equity_usd\s*=.*$"
    if re.search(cap, text):
        text = re.sub(cap, 'max_trading_equity_usd = "100"', text)
    elif "[policy]\n" in text:
        text = text.replace("[policy]\n", '[policy]\nmax_trading_equity_usd = "100"\n', 1)
    else:
        raise MatrixError("paper fixture policy table missing")
    expected = copy.deepcopy(parsed)
    expected.update(
        mode="mainnet", network="mainnet", allow_mainnet=True, api_wallet="0x" + "0" * 40
    )
    expected["policy"]["max_trading_equity_usd"] = "100"
    if tomllib.loads(text) != expected:
        raise MatrixError("negative fixture changed fields outside declared admission inputs")
    return text


def execute(
    release: Release,
    binary: Path,
    *,
    account: str,
    rules: str,
    work: Path,
    account_network: str = "mainnet",
) -> None:
    if account_network not in {"mainnet", "testnet"}:
        raise MatrixError("paper constructor account network refused")
    if (
        binary.is_symlink()
        or hashlib.sha256(binary.read_bytes()).digest()
        != hashlib.sha256(release.binary("linux-amd64")).digest()
    ):
        raise MatrixError("attack executable differs from authenticated release")
    work.mkdir(mode=0o700)
    home = work / "attack-home"
    home.mkdir(mode=0o700)
    clean = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home)}
    run(
        [
            str(binary),
            "--home",
            str(home),
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--account-network",
            account_network,
            "--account",
            account,
            "--rules",
            rules,
            "--no-key",
        ],
        env=clean,
        log=work / "paper-init.log",
        timeout=90,
        sensitive_output=True,
        stdin=b"",
    )
    config = home / "guard.toml"
    config.write_text(configuration(config.read_text()))
    # A positive parser/config check prevents a generic missing-config failure earning credit.
    run(
        [str(binary), "--home", str(home), "check-config"],
        env=clean,
        log=work / "positive-config.log",
        timeout=30,
        sensitive_output=True,
        stdin=b"",
    )
    descriptor = dict(
        kind="negative-attack-input",
        positive_config_check=True,
        changed_fields=FIELDS,
        native_custody_proof=False,
    )
    (work / "attack-fixture.json").write_text(json.dumps(descriptor) + "\n")
    dummy = home / "api-wallet-key"
    dummy.write_text("not-a-private-key\n")
    dummy.chmod(0o600)
    failed: list[str] = []
    for case, args, extra in (
        ("plain-key-file", [], {}),
        ("key-file-option", ["--key-stdin", "--key-file", str(dummy)], {}),
        (
            "environment-key",
            ["--key-stdin"],
            {"ZUNDER_GUARD_KEY_FILE": str(dummy)},
        ),
    ):
        result = subprocess.run(
            [str(binary), "--home", str(home), "run", "--network", "mainnet", *args],
            env=clean | extra,
            input=b"",
            capture_output=True,
            timeout=30,
            check=False,
        )
        literal = LITERAL if case == "plain-key-file" else "cannot be used with"
        output = (result.stdout + result.stderr).replace(account.encode(), b"[ACCOUNT]")
        passed = result.returncode != 0 and literal.encode() in output
        if not passed:
            failed.append(case)
        record(
            release,
            case=case,
            route="linux-systemd",
            target="linux-amd64",
            work=work / "M2",
            output=output,
            exit_code=result.returncode,
            literal=literal,
            passed=passed,
        )
    # Hide only the credential utility in an isolated PATH. The real signed installer
    # must refuse before binary installation, key parsing, units or credential writes.
    tools = work / "no-credential-tools"
    tools.mkdir(mode=0o700)
    for directory in os.defpath.split(os.pathsep):
        for source in Path(directory).iterdir():
            target = tools / source.name
            if source.name != "systemd-creds" and not target.exists() and source.is_file():
                target.symlink_to(source)
    installer = work / "authenticated-install.sh"
    installer.write_bytes(release.asset("install.sh"))
    result = subprocess.run(
        [
            shutil.which("sudo") or "/usr/bin/sudo",
            "-n",
            "env",
            "-i",
            "PATH=" + str(tools),
            "HOME=" + str(home),
            "/bin/sh",
            str(installer),
            "--service-instance",
            "mainnet",
            "--non-interactive",
            "--network",
            "mainnet",
            "--rules",
            rules,
            "--account",
            account,
            "--confirm-mainnet",
            account,
            "--equity-cap",
            "100",
            "--ip-share",
            "1",
            "--listen",
            "127.0.0.1:18548",
            "--key-file",
            str(dummy),
        ],
        input=b"",
        capture_output=True,
        timeout=300,
        check=False,
    )
    output = (result.stdout + result.stderr).replace(account.encode(), b"[ACCOUNT]")
    literal = "service instance requires systemd-creds; plaintext fallback is refused"
    passed = result.returncode != 0 and literal.encode() in output
    if not passed:
        failed.append("missing-credential-store")
    record(
        release,
        case="missing-credential-store",
        route="linux-systemd",
        target="linux-amd64",
        work=work / "M2",
        output=output,
        exit_code=result.returncode,
        literal=literal,
        passed=passed,
    )
    if failed:
        raise MatrixError("mainnet attack refusal evidence incomplete")


def containers(release: Release, *, image: str, home: Path, work: Path, account: str) -> None:
    """Exact signed Docker/Compose payloads with public negative input, closed stdin/network."""
    import io
    import tarfile
    import uuid

    if (
        image
        != json.loads(release.asset("release-manifest.json"))["distribution"]["docker"]["image"]
        + "@"
        + json.loads(release.asset("release-manifest.json"))["distribution"]["docker"]["digest"]
    ):
        raise MatrixError("container refusal subject differs from immutable C2 image")
    work.mkdir(mode=0o700)
    name = "guard-refusal-" + uuid.uuid4().hex
    created = False
    try:
        run(
            ["docker", "create", "--name", name, image, "--version"],
            log=work / "image-create.log",
            timeout=90,
            sensitive_output=True,
            stdin=b"",
        )
        created = True
        result = subprocess.run(
            ["docker", "cp", name + ":/usr/local/bin/zunder-guard", "-"],
            capture_output=True,
            timeout=90,
            check=False,
        )
        if result.returncode:
            raise MatrixError("container executable capture failed")
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            entries = archive.getmembers()
            if len(entries) != 1 or entries[0].name != "zunder-guard" or not entries[0].isfile():
                raise MatrixError("container executable capture is not a regular binary")
            stream = archive.extractfile(entries[0])
            if stream is None or stream.read() != release.binary("linux-amd64"):
                raise MatrixError("container executable differs from signed release archive")
    finally:
        if created:
            run(
                ["docker", "rm", "--force", name],
                log=work / "image-remove.log",
                timeout=90,
                sensitive_output=True,
                stdin=b"",
            )
    inputs = work / "negative-inputs"
    inputs.mkdir(mode=0o755)
    for name in ("guard.toml", "api-wallet-key"):
        path = inputs / name
        path.write_bytes((home / name).read_bytes())
        path.chmod(0o444)
    inputs.chmod(0o755)
    compose = work / "authenticated-compose.yaml"
    compose.write_bytes(release.asset("compose.yaml"))
    failed: list[str] = []
    for case, words in (
        (
            "plain-docker",
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "-v",
                str(inputs) + ":/data:ro",
                image,
            ],
        ),
        (
            "compose",
            [
                "docker",
                "compose",
                "-p",
                "guard-refusal-" + uuid.uuid4().hex,
                "-f",
                str(compose),
                "run",
                "--rm",
                "--no-deps",
                "-v",
                str(inputs) + ":/data:ro",
                "guard",
            ],
        ),
    ):
        # Without --key-stdin runtime must refuse before constructing a network client.
        result = subprocess.run(
            words + ["run", "--network", "mainnet", "--key-file", "/data/api-wallet-key"],
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": os.environ.get("HOME", ""),
                "ZUNDER_GUARD_IMAGE": image,
            },
            input=b"",
            capture_output=True,
            timeout=90,
            check=False,
        )
        literal = LITERAL
        output = (result.stdout + result.stderr).replace(account.encode(), b"[ACCOUNT]")
        passed = result.returncode != 0 and literal.encode() in output
        if not passed:
            failed.append(case)
        record(
            release,
            case=case,
            route=case,
            target="linux-amd64",
            work=work / "M2",
            output=output,
            exit_code=result.returncode,
            literal=literal,
            passed=passed,
        )

    if failed:
        raise MatrixError("mainnet container refusal evidence incomplete")
