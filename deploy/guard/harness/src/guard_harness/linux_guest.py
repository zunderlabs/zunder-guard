"""Run released native lifecycle in a pinned signed Ubuntu KVM guest.

Reuses the container-native VM's image/signature/cloud-init/SSH recipe, but runs only
released Guard bytes, never its synthetic installer or fake Guard fixtures.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import nullcontext
from pathlib import Path

from guard_harness.linux_lifecycle import require
from guard_harness.runner import RunError, run

IMAGE_DIR = "https://cloud-images.ubuntu.com/releases/noble/release-20260911/"
IMAGE = "ubuntu-24.04-server-cloudimg-amd64.img"
IMAGE_SHA = "612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354"
ROOT = Path(__file__).resolve().parents[5]


class Guest:
    def __init__(self, temp: Path, output: Path) -> None:
        self.temp = temp
        self.output = output
        self.counter = 0
        self.env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(temp),
            "LANG": "C.UTF-8",
        }
        self.ssh: list[str] = []

    def command(self, argv: list[str], *, timeout: float = 300) -> str:
        self.counter += 1
        return run(
            argv, log=self.output / f"host-{self.counter}.log", timeout=timeout, env=self.env
        ).output.strip()

    def remote(self, command: str, *, timeout: float = 300) -> str:
        return self.command([*self.ssh, command], timeout=timeout)

    def private_remote(self, command: str, key: bytes, *, timeout: float = 1200) -> str:
        """Encrypted SSH stdin only; never argv, environment, tar, file or diagnostic."""
        require(re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is not None, "stdin key frame refused")
        self.counter += 1
        return run(
            [*self.ssh, command],
            stdin=key,
            secrets=[key.decode().strip()],
            sensitive_output=True,
            log=self.output / f"host-{self.counter}.log",
            timeout=timeout,
            env=self.env,
        ).output.strip()

    def destroy_testnet(self, process: subprocess.Popen[bytes], arguments: list[str]) -> None:
        """Unknown/hanging cleanup preserves the live guest and its private disk."""
        try:
            observed = json.loads(
                self.remote(self.testnet_command(arguments) + " --phase check-flat", timeout=900)
            )
            require(observed == {"flat": True}, "guest cleanup flat readback differs")
        except (RunError, ValueError, RuntimeError):
            (self.output / "cleanup-required.json").write_text(
                json.dumps(
                    {
                        "cleanup_complete": False,
                        "disk_retained": True,
                        "runtime_alive": process.poll() is None,
                    }
                )
                + "\n"
            )
            raise RuntimeError("Testnet cleanup unknown; owned guest preserved") from None
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        shutil.rmtree(self.temp)

    def wait(self, process: subprocess.Popen[bytes], *, previous_boot: str = "") -> str:
        deadline = time.monotonic() + 900
        while True:
            require(process.poll() is None, "QEMU exited before guest readiness")
            try:
                boot = self.remote("cat /proc/sys/kernel/random/boot_id", timeout=10)
                if boot and boot != previous_boot:
                    return boot
            except RunError:
                pass
            require(time.monotonic() < deadline, "guest readiness/reboot deadline exceeded")
            time.sleep(3)

    def prepare(self, marker: str, *, allow_tcg_local: bool = False) -> list[str]:
        self.acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        require(self.acceleration == "kvm" or allow_tcg_local, "release guest tier requires KVM")
        for asset in (IMAGE, "SHA256SUMS", "SHA256SUMS.gpg"):
            self.command(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--proto",
                    "=https",
                    "--output",
                    str(self.temp / asset),
                    IMAGE_DIR + asset,
                ],
                timeout=900,
            )
        self.command(
            [
                "gpgv",
                "--keyring",
                "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg",
                str(self.temp / "SHA256SUMS.gpg"),
                str(self.temp / "SHA256SUMS"),
            ]
        )
        entries = [
            line.split()[0]
            for line in (self.temp / "SHA256SUMS").read_text().splitlines()
            if len(line.split()) == 2 and line.split()[1].lstrip("*") == IMAGE
        ]
        require(entries == [IMAGE_SHA], "signed guest checksum differs from pin")
        with (self.temp / IMAGE).open("rb") as stream:
            require(
                hashlib.file_digest(stream, "sha256").hexdigest() == IMAGE_SHA,
                "guest image digest differs",
            )
        disk = self.temp / "guest.qcow2"
        self.command(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(self.temp / IMAGE),
                str(disk),
            ]
        )
        self.command(["qemu-img", "resize", str(disk), "14G"])
        self.command(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.temp / "ssh-key")]
        )
        public = (self.temp / "ssh-key.pub").read_text().strip()
        config = {
            "users": [
                {
                    "name": "ubuntu",
                    "shell": "/bin/bash",
                    "groups": ["sudo"],
                    "sudo": ["ALL=(ALL) NOPASSWD:ALL"],
                    "ssh_authorized_keys": [public],
                }
            ],
            "package_update": True,
            "packages": ["python3-venv", "ca-certificates", "docker.io"],
            "write_files": [
                {
                    "path": "/etc/zunder-native-disposable",
                    "owner": "root:root",
                    "permissions": "0600",
                    "content": marker + "\n",
                }
            ],
        }
        (self.temp / "user-data").write_text("#cloud-config\n" + json.dumps(config) + "\n")
        (self.temp / "meta-data").write_text(
            json.dumps({"instance-id": marker, "local-hostname": "guard-release-guest"})
        )
        self.command(
            [
                "cloud-localds",
                str(self.temp / "seed.img"),
                str(self.temp / "user-data"),
                str(self.temp / "meta-data"),
            ]
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.ssh = [
            "ssh",
            "-i",
            str(self.temp / "ssh-key"),
            "-p",
            str(port),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=" + str(self.temp / "known-hosts"),
            "ubuntu@127.0.0.1",
        ]
        return [
            "qemu-system-x86_64",
            "-machine",
            "q35",
            "-accel",
            self.acceleration,
            "-m",
            "4096",
            "-smp",
            "2",
            "-drive",
            f"file={disk},format=qcow2,if=virtio",
            "-drive",
            f"file={self.temp / 'seed.img'},format=raw,if=virtio",
            "-nic",
            f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-nographic",
        ]

    def exercise(
        self,
        arguments: list[str],
        process: subprocess.Popen[bytes],
        *,
        refusals_only: bool = False,
        testnet_key: bytes | None = None,
    ) -> None:
        self.wait(process)
        self.remote("sudo cloud-init status --wait", timeout=1200)
        self.remote(
            "sudo mkdir -p /opt/guard-release-harness && "
            "sudo tar -xzf source.tar.gz -C /opt/guard-release-harness"
        )
        self.remote(
            "sudo python3 -m venv /opt/guard-release-harness/venv && "
            "sudo /opt/guard-release-harness/venv/bin/pip install "
            "/opt/guard-release-harness/harness",
            timeout=600,
        )
        if testnet_key is not None:
            command = self.testnet_command(arguments)
            self.private_remote(command + " --phase before-reboot", testnet_key, timeout=2400)
            self.remote(command + " --phase check-flat", timeout=900)
            boot = self.remote("cat /proc/sys/kernel/random/boot_id")
            try:
                self.remote("sudo systemctl reboot", timeout=10)
            except RunError:
                pass
            self.wait(process, previous_boot=boot)
            self.private_remote(command + " --phase after-reboot", testnet_key, timeout=2400)
            return
        if refusals_only:
            refusal_args = []
            for flag in (
                "installer",
                "installer-sha256",
                "rules",
                "account",
                "output",
                "marker",
                "tag",
                "commit",
                "harness-commit",
                "manifest-sha256",
                "binary-sha256",
                "image",
            ):
                refusal_args.extend(["--" + flag, arguments[arguments.index("--" + flag) + 1]])
            if "--diagnostic" in arguments:
                refusal_args.append("--diagnostic")
            if arguments[arguments.index("--mode") + 1] == "container":
                refusal_args.append("--container")
            self.remote(
                shlex.join(
                    [
                        "sudo",
                        "/opt/guard-release-harness/venv/bin/python",
                        "-m",
                        "guard_harness.linux_mainnet_refusal",
                        *refusal_args,
                    ]
                ),
                timeout=1000,
            )
            return
        command = shlex.join(
            [
                "sudo",
                "/opt/guard-release-harness/venv/bin/python",
                "-m",
                "guard_harness.linux_lifecycle",
                *arguments,
            ]
        )
        if "--source-container-diagnostic" in arguments:
            self.remote(
                "sudo apt-get update -qq && sudo apt-get install -y -qq docker.io", timeout=600
            )
            self.remote(
                "sudo curl -fsSL --proto =https "
                "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 "
                "-o /usr/local/bin/cosign && "
                "echo '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 "
                " /usr/local/bin/cosign' | sudo sha256sum -c - && "
                "sudo chmod 755 /usr/local/bin/cosign",
                timeout=180,
            )
        self.remote(command + " --phase before-reboot", timeout=1200)
        boot = self.remote("cat /proc/sys/kernel/random/boot_id")
        try:
            self.remote("sudo systemctl reboot", timeout=10)
        except RunError:
            pass
        self.wait(process, previous_boot=boot)
        self.remote(command + " --phase after-reboot", timeout=1200)

    def testnet_command(self, arguments: list[str]) -> str:
        return shlex.join(
            [
                "sudo",
                "/opt/guard-release-harness/venv/bin/python",
                "-m",
                "guard_harness.linux_testnet_lifecycle",
                *arguments,
            ]
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("candidate", "previous", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in ("version", "previous-version", "rules", "account"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--mode", choices=("native", "container"), default="native")
    parser.add_argument("--account-network", choices=("mainnet", "testnet"), default="mainnet")
    parser.add_argument("--allow-tcg-local", action="store_true")
    parser.add_argument("--harness-root", type=Path, default=ROOT / "deploy/guard/harness")
    parser.add_argument("--source-paper-script", type=Path)
    parser.add_argument("--candidate-image", type=Path)
    parser.add_argument("--previous-image", type=Path)
    parser.add_argument("--mainnet-refusals-only", action="store_true")
    parser.add_argument("--testnet-lifecycle", action="store_true")
    parser.add_argument("--previous-binary-sha256", default="")
    parser.add_argument("--previous-release-image", default="")
    for flag in (
        "release-tag",
        "release-commit",
        "harness-commit",
        "manifest-sha256",
        "binary-sha256",
    ):
        parser.add_argument("--" + flag)
    parser.add_argument("--release-image", default="")
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    key = None
    if args.testnet_lifecycle:
        require(
            not args.mainnet_refusals_only
            and not args.source_paper_script
            and not args.allow_tcg_local
            and args.account_network == "testnet",
            "Testnet lifecycle needs released KVM subjects and Testnet account",
        )
        require(
            args.binary_sha256 is not None and bool(args.previous_binary_sha256),
            "both released binary digests required",
        )
        key = sys.stdin.buffer.read(66)
        require(re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is not None, "private host stdin required")
    if args.mainnet_refusals_only:
        require(
            all(
                (
                    args.release_tag,
                    args.release_commit,
                    args.harness_commit,
                    args.manifest_sha256,
                    args.binary_sha256,
                )
            ),
            "M1 requires authenticated subjects",
        )
    if args.source_paper_script:
        require(
            args.allow_tcg_local
            and not args.mainnet_refusals_only
            and args.mode == "container"
            and args.candidate_image
            and args.previous_image,
            "source diagnostic needs explicit nongate TCG and both released image descriptors",
        )
    else:
        require(
            not args.candidate_image and not args.previous_image,
            "image overrides are diagnostic-only",
        )
    args.output.mkdir(parents=True, exist_ok=True)
    # Testnet guests survive unknown cleanup outcomes. Never delete their encrypted
    # custody/protection or disk solely because the harness failed.
    folder_context = (
        nullcontext(tempfile.mkdtemp(prefix="guard-release-testnet-"))
        if args.testnet_lifecycle
        else tempfile.TemporaryDirectory(prefix="guard-release-guest-")
    )
    with folder_context as folder:
        Path(folder).chmod(0o700)
        guest = Guest(Path(folder), args.output)
        marker = uuid.uuid4().hex
        command = guest.prepare(marker, allow_tcg_local=args.allow_tcg_local)
        archive = guest.temp / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(
                args.harness_root,
                arcname="harness",
                filter=lambda info: (
                    None
                    if any(part in info.name.split("/") for part in ("__pycache__", ".venv"))
                    else info
                ),
            )
            tar.add(args.candidate, arcname="candidate-install.sh")
            tar.add(args.previous, arcname="previous-install.sh")
            if args.source_paper_script:

                def root_owned(info: tarfile.TarInfo) -> tarfile.TarInfo:
                    info.uid = 0
                    info.gid = 0
                    info.mode = 0o600
                    return info

                tar.add(
                    args.source_paper_script,
                    arcname="container-paper-source/install-container-paper.py",
                    filter=root_owned,
                )
                tar.add(
                    args.candidate_image,
                    arcname="container-paper-source/zunder-guard-" + args.version + ".image.txt",
                    filter=root_owned,
                )
                tar.add(
                    args.previous_image,
                    arcname="container-paper-source/zunder-guard-"
                    + args.previous_version
                    + ".image.txt",
                    filter=root_owned,
                )
        prefix = "/opt/guard-release-harness/"
        arguments = [
            "--account-network",
            args.account_network,
            "--mode",
            args.mode,
            "--installer",
            prefix + "candidate-install.sh",
            "--installer-sha256",
            hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
            "--previous-installer",
            prefix + "previous-install.sh",
            "--previous-installer-sha256",
            hashlib.sha256(args.previous.read_bytes()).hexdigest(),
            "--version",
            args.version,
            "--previous-version",
            args.previous_version,
            "--rules",
            args.rules,
            "--account",
            args.account,
            "--output",
            prefix + "evidence",
            "--marker",
            marker,
        ]
        if args.testnet_lifecycle:
            arguments = arguments[4:]  # Sending driver uses route, never paper account mode.
            arguments.extend(
                [
                    "--route",
                    args.mode,
                    "--binary-sha256",
                    args.binary_sha256,
                    "--previous-binary-sha256",
                    args.previous_binary_sha256,
                    "--image",
                    args.release_image,
                    "--previous-image",
                    args.previous_release_image,
                ]
            )
        if args.mainnet_refusals_only:
            for flag, value in (
                ("tag", args.release_tag),
                ("commit", args.release_commit),
                ("harness-commit", args.harness_commit),
                ("manifest-sha256", args.manifest_sha256),
                ("binary-sha256", args.binary_sha256),
                ("image", args.release_image),
            ):
                arguments.extend(["--" + flag, value])
            if args.diagnostic or guest.acceleration != "kvm":
                arguments.append("--diagnostic")
        if args.source_paper_script:
            arguments.append("--source-container-diagnostic")
        with (args.output / "qemu.log").open("wb") as log:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=guest.env
            )
        try:
            guest.wait(process)
            # scp -P uses the same forwarded SSH port and disposable known-host file.
            port = guest.ssh[guest.ssh.index("-p") + 1]
            guest.command(
                [
                    "scp",
                    "-i",
                    str(guest.temp / "ssh-key"),
                    "-P",
                    port,
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "UserKnownHostsFile=" + str(guest.temp / "known-hosts"),
                    str(archive),
                    "ubuntu@127.0.0.1:source.tar.gz",
                ]
            )
            guest.exercise(
                arguments, process, refusals_only=args.mainnet_refusals_only, testnet_key=key
            )
        finally:
            # These logs are sanitized by the guest runner before collection; pairing
            # stdout and credential-bearing commands are never retained there.
            try:
                guest.remote(
                    "sudo tar -czf /tmp/guard-release-evidence.tar.gz "
                    "-C /opt/guard-release-harness evidence && "
                    "sudo chmod 644 /tmp/guard-release-evidence.tar.gz",
                    timeout=30,
                )
                guest.command(
                    [
                        "scp",
                        "-i",
                        str(guest.temp / "ssh-key"),
                        "-P",
                        port,
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "UserKnownHostsFile=" + str(guest.temp / "known-hosts"),
                        "ubuntu@127.0.0.1:/tmp/guard-release-evidence.tar.gz",
                        str(args.output / "guest-evidence.tar.gz"),
                    ],
                    timeout=30,
                )
            except RunError:
                pass
            try:
                receipt_name = (
                    "testnet-lifecycle.json"
                    if args.testnet_lifecycle
                    else "mainnet-refusal.json"
                    if args.mainnet_refusals_only
                    else "linux-lifecycle.json"
                )
                record = guest.remote(
                    "sudo cat /opt/guard-release-harness/evidence/" + receipt_name, timeout=10
                )
                receipt = json.loads(record)
                receipt["guest_acceleration"] = guest.acceleration
                receipt["guest_image_sha256"] = IMAGE_SHA
                receipt["gate_eligible"] = (
                    guest.acceleration == "kvm"
                    and not args.source_paper_script
                    and not args.diagnostic
                )
                (args.output / receipt_name).write_text(json.dumps(receipt, indent=2) + "\n")
            except RunError:
                pass
            if args.testnet_lifecycle:
                guest.destroy_testnet(process, arguments)
            else:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


if __name__ == "__main__":
    main()
