"""Actual Linux curl-pipe and manual archive channels; paper-only, private output."""

import json
import os
import platform
import pty
import re
import select
import signal
import socket
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from guard_harness.cli import PAIR_SCHEMA, STATUS_SCHEMA, Pair, decode_json
from guard_harness.linux_lifecycle import (
    BINARY,
    HOME,
    ROOT_PATH,
    Inputs,
    NativeLifecycle,
    authenticated_file,
    require,
    snapshot,
    wait_healthy,
)
from guard_harness.paper_bot import LocalGuard
from guard_harness.paper_roundtrip import round_trip
from guard_harness.runner import run

CHANNEL_PRIVATE = Path("/root")


def dialogue(
    argv: list[str],
    account: str,
    network: str,
    *,
    cwd: Path | None = None,
    home: Path | None = None,
    timeout: float = 1200,
    mode_supplied: bool = False,
) -> None:
    """Literal published commands keep stdin piped; wizard replies use the controlling tty."""
    require(network in {"mainnet", "testnet"}, "paper read network required")
    replies = [
        (b"Keep these? [Y/edit]", b"\n"),
        (b"Hyperliquid account address", account.encode() + b"\n"),
        (b"Mode: paper", b"paper\n"),
        (b"Paper mode reads which network's account", network.encode() + b"\n"),
    ]
    if mode_supplied:
        replies = [reply for reply in replies if reply[0] != b"Mode: paper"]
    pid, descriptor = pty.fork()
    if pid == 0:
        if cwd is not None:
            os.chdir(cwd)
        env = {"PATH": ROOT_PATH, "HOME": "/root", "LANG": "C.UTF-8", "TERM": "dumb"}
        if home is not None:
            env["ZUNDER_GUARD_HOME"] = str(home)
        os.execve(argv[0], argv, env)
    pending, index, status = b"", 0, None
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([descriptor], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(descriptor, 65536)
                except OSError:
                    chunk = b""
                pending += chunk
                require(len(pending) <= 1048576, "interactive channel output exceeds bound")
                while index < len(replies) and replies[index][0] in pending:
                    prompt, reply = replies[index]
                    pending = pending.split(prompt, 1)[1]
                    os.write(descriptor, reply)
                    index += 1
            finished, observed = os.waitpid(pid, os.WNOHANG)
            if finished:
                status = observed
                break
        require(
            status is not None and os.waitstatus_to_exitcode(status) == 0,
            "published channel failed; interactive output withheld",
        )
        require(index == len(replies), "published channel did not reach complete paper wizard")
    finally:
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(descriptor)


def identity(inputs: Inputs, channel: str) -> dict[str, Any]:
    require(
        inputs.scenario == "fresh"
        and bool(re.fullmatch(r"[0-9a-f]{40}", inputs.release_commit))
        and bool(re.fullmatch(r"[0-9a-f]{64}", inputs.manifest_sha256))
        and bool(re.fullmatch(r"[0-9a-f]{64}", inputs.binary_sha256)),
        "fresh channel needs authenticated C2 source/manifest/binary identity",
    )
    return dict(
        schema=1,
        result="passed",
        channel=channel,
        scenario="fresh",
        mode="paper",
        tag=inputs.version,
        commit=inputs.release_commit,
        manifest_sha256=inputs.manifest_sha256,
        installed_binary_sha256=inputs.binary_sha256,
        version=inputs.version.removeprefix("v"),
    )


def curl_install(inputs: Inputs, *, website: bool = False) -> None:
    identity(inputs, "D1")
    require(inputs.loader_channel in {"staging", "canonical"}, "declared loader channel required")
    url = "https://zunderlabs.com/" + ("i-staging" if inputs.loader_channel == "staging" else "i")
    # Observe the actual public head on both sides, while the installation itself uses
    # the documented unmodified curl | sh pipeline and controlling-terminal questions.
    for step in ("before", "after"):
        with tempfile.TemporaryDirectory(prefix="guard-channel-loader-") as folder:
            loader = Path(folder) / "i"
            run(
                ["curl", "-fsSL", url, "-o", str(loader)],
                log=inputs.output / ("D1-head-" + step + ".log"),
                timeout=90,
                env={"PATH": ROOT_PATH, "HOME": "/root"},
                sensitive_output=True,
            )
            authenticated_file(loader, inputs.installer_sha256)
        if step == "before":
            dialogue(
                [
                    "/bin/sh",
                    "-c",
                    "curl -fsSL " + url + " | sh" + (" -s -- --network paper" if website else ""),
                ],
                inputs.account,
                inputs.account_network,
                mode_supplied=website,
            )
    authenticated_file(Path("/usr/local/bin/zunder-guard"), inputs.binary_sha256)


def website_install(lifecycle: NativeLifecycle) -> dict[str, Any]:
    """A second fresh customer install, after the bare form's measured uninstall."""
    inputs = lifecycle.inputs
    require(inputs.account_network == "testnet", "published paper form must use Testnet reads")
    require(
        HOME.is_dir() and not HOME.is_symlink() and not BINARY.exists(),
        "bare form must finish owned uninstall first",
    )
    private = CHANNEL_PRIVATE / (".guard-channel-data-" + inputs.marker)
    private.mkdir(mode=0o700)  # Exclusive ownership; retained on any uncertain outcome.
    HOME.rename(private / "bare-data")
    curl_install(inputs, website=True)
    lifecycle.version(inputs.version)
    lifecycle.healthy()
    pair = lifecycle.cli.pair()
    round_trip(lifecycle.guard, pair)
    before = snapshot(HOME)
    lifecycle.systemctl("D1-website-restart", "restart")
    lifecycle.healthy()
    round_trip(lifecycle.guard, pair)
    lifecycle.systemctl("D1-website-stop", "stop")
    lifecycle.command(
        "D1-website-uninstall", ["sh", str(inputs.installer), "--uninstall", "--non-interactive"]
    )
    from guard_harness.linux_lifecycle import preserved

    preserved(before, snapshot(HOME))
    require(
        not BINARY.exists()
        and not Path("/etc/systemd/system/zunder-guard.service").exists()
        and not Path("/etc/systemd/system/zunder-guard.service.d").exists(),
        "website form owned software survived uninstall",
    )
    HOME.rename(private / "website-data")
    (private / "bare-data").rename(HOME)
    return dict(
        form="website-parameter",
        command=published_command(inputs) + " -s -- --network paper",
        result="passed",
        installed_binary_sha256=inputs.binary_sha256,
        version=inputs.version.removeprefix("v"),
        mode="paper",
        account_network="testnet",
        health=True,
        paper_roundtrip=True,
        owned_process_stopped=True,
        cleanup_complete=True,
        cleanup_method="released-native-uninstall",
    )


def published_command(inputs: Inputs) -> str:
    return (
        "curl -fsSL https://zunderlabs.com/"
        + ("i-staging" if inputs.loader_channel == "staging" else "i")
        + " | sh"
    )


def curl_receipt(inputs: Inputs, website: dict[str, Any]) -> None:
    value = identity(inputs, "D1")
    require(
        website.get("form") == "website-parameter" and website.get("result") == "passed",
        "independent website paper install receipt required",
    )
    bare = dict(
        form="manifest-bare",
        command=published_command(inputs),
        result="passed",
        installed_binary_sha256=inputs.binary_sha256,
        version=inputs.version.removeprefix("v"),
        mode="paper",
        account_network=inputs.account_network,
        health=True,
        paper_roundtrip=True,
        owned_process_stopped=True,
        cleanup_complete=True,
        cleanup_method="released-native-uninstall",
    )
    value.update(
        command=published_command(inputs),
        loader_sha256=inputs.installer_sha256,
        cleanup_complete=True,
        executions=[bare, website],
        coverage=[
            "literal-curl-pipe",
            "interactive-paper-init",
            "installed-binary-readback",
            "paper-allow-resize-veto",
            "uninstall",
            "cleanup",
            "manifest-bare-form",
            "website-parameter-form",
        ],
    )
    (inputs.output / "channels").mkdir(exist_ok=True)
    (inputs.output / "channels/D1.json").write_text(json.dumps(value) + "\n")


def container_curl_install(inputs: Inputs) -> str:
    identity(inputs, "D7")
    require(inputs.account_network == "testnet", "container paper channel needs Testnet reads")
    url = "https://zunderlabs.com/" + ("i-staging" if inputs.loader_channel == "staging" else "i")
    descriptor = "curl -fsSL " + url + " | sh -s -- --container --network paper"
    for step in ("before", "after"):
        with tempfile.TemporaryDirectory(prefix="guard-container-loader-") as folder:
            loader = Path(folder) / "i"
            run(
                ["curl", "-fsSL", url, "-o", str(loader)],
                log=inputs.output / ("D7-head-" + step + ".log"),
                timeout=90,
                env={"PATH": ROOT_PATH, "HOME": "/root"},
                sensitive_output=True,
            )
            authenticated_file(loader, inputs.installer_sha256)
        if step == "before":
            run(
                [
                    "/bin/sh",
                    "-c",
                    descriptor
                    + " --non-interactive --account-network testnet"
                    + ' --account "$GUARD_CHANNEL_ACCOUNT" --rules "$GUARD_CHANNEL_RULES"',
                ],
                log=inputs.output / "D7-install.log",
                timeout=1200,
                stdin=b"",
                sensitive_output=True,
                env={
                    "PATH": ROOT_PATH,
                    "HOME": "/root",
                    "GUARD_CHANNEL_ACCOUNT": inputs.account,
                    "GUARD_CHANNEL_RULES": inputs.rules,
                },
            )
    return descriptor


def manual(inputs: Inputs) -> None:
    value = identity(inputs, "D5")
    require(
        inputs.archive is not None and bool(re.fullmatch(r"[0-9a-f]{64}", inputs.archive_sha256)),
        "authenticated manual archive required",
    )
    assert inputs.archive is not None
    authenticated_file(inputs.archive, inputs.archive_sha256)
    target = "linux-arm64" if platform.machine() in {"aarch64", "arm64"} else "linux-amd64"
    name = f"zunder-guard-{inputs.version}-{target}.tar.gz"
    base = "https://github.com/zunderlabs/zunder-guard/releases/download/" + inputs.version + "/"
    with tempfile.TemporaryDirectory(prefix="guard-channel-manual-") as folder:
        root = Path(folder)

        def command(args: list[str], label: str) -> str:
            return run(
                args,
                log=inputs.output / ("D5-" + label + ".log"),
                cwd=root,
                env={"PATH": ROOT_PATH, "HOME": "/root"},
                timeout=300,
                stdin=b"",
                sensitive_output=True,
            ).output.strip()

        for asset in (name, "SHA256SUMS", "SHA256SUMS.sigstore.json"):
            command(["curl", "-fsSL", base + asset, "-o", str(root / asset)], "download-" + asset)
        authenticated_file(root / name, inputs.archive_sha256)
        loader = inputs.installer.read_text()
        pins = re.findall(r"P=" + target + r" H=([0-9a-f]{64})", loader)
        versions = re.findall(r" C=(v[0-9]+\.[0-9]+\.[0-9]+) ", loader)
        require(len(pins) == len(versions) == 1, "signed loader verifier pin is not understood")
        verifier = root / "cosign"
        command(
            [
                "curl",
                "-fsSL",
                "https://github.com/sigstore/cosign/releases/download/"
                + versions[0]
                + "/cosign-"
                + target,
                "-o",
                str(verifier),
            ],
            "verifier-download",
        )
        authenticated_file(verifier, pins[0])
        verifier.chmod(0o700)
        command(
            [
                str(verifier),
                "verify-blob",
                "--bundle",
                "SHA256SUMS.sigstore.json",
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-identity",
                "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/"
                + inputs.version,
                "SHA256SUMS",
            ],
            "signature",
        )
        command(["sha256sum", "--ignore-missing", "-c", "SHA256SUMS"], "signed-checksums")
        with tarfile.open(root / name) as archive:
            members = archive.getmembers()
            require(
                all(
                    m.isfile()
                    and m.name
                    in {
                        "zunder-guard",
                        "README.md",
                        "LICENSE",
                        "NOTICE",
                        "THIRD_PARTY_LICENSES.md",
                        "zunder-guard.service",
                    }
                    and 0 <= m.size <= 128 * 1024 * 1024
                    for m in members
                )
                and len({m.name for m in members}) == len(members),
                "manual archive paths refused",
            )
        command(["tar", "-xzf", name], "archive-extract")
        binary, home = root / "zunder-guard", root / "private-home"
        authenticated_file(binary, inputs.binary_sha256)
        dialogue([str(binary), "init"], inputs.account, inputs.account_network, cwd=root, home=home)
        pair_data = decode_json(
            command([str(binary), "--home", str(home), "pair", "--json"], "private-pair"),
            PAIR_SCHEMA,
        )
        pair = Pair(pair_data["client_address"], pair_data["client_key"])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env = {
            "PATH": ROOT_PATH,
            "HOME": "/root",
            "ZUNDER_GUARD_HOME": str(home),
            "ZUNDER_GUARD_LISTEN": f"127.0.0.1:{port}",
        }
        process = subprocess.Popen(
            [str(binary), "run"],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            guard = LocalGuard(f"http://127.0.0.1:{port}")
            wait_healthy(guard)
            status = decode_json(
                command(
                    [str(binary), "--home", str(home), "status", "--json", "--url", guard.url],
                    "status",
                ),
                STATUS_SCHEMA,
            )
            require(
                status["mode"] == "paper"
                and status["account"].lower() == inputs.account.lower()
                and status["version"] == inputs.version.removeprefix("v"),
                "manual paper identity differs",
            )
            round_trip(guard, pair)
        finally:
            process.terminate()
            try:
                process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                require(False, "manual owned Guard did not stop cleanly")
        require(process.returncode == 0, "manual Guard clean stop not observed")
        state = snapshot(home)
        value.update(
            command=(
                "curl archive/checksums/bundle; cosign verify-blob; sha256sum -c; "
                "tar -xzf; ./zunder-guard init; ./zunder-guard run"
            ),
            archive_sha256=inputs.archive_sha256,
            cleanup_complete=True,
            retained_state_sha256=state,
            coverage=[
                "manual-release-download",
                "signed-checksums",
                "archive-extract",
                "interactive-paper-init",
                "installed-binary-readback",
                "paper-allow-resize-veto",
                "owned-process-stop",
                "cleanup",
            ],
        )
    require(not root.exists(), "manual private software/home remain")
    (inputs.output / "channels").mkdir(exist_ok=True)
    (inputs.output / "channels/D5.json").write_text(json.dumps(value) + "\n")
