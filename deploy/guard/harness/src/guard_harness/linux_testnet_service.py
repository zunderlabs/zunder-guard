"""T2 protected service custody/start only; never executes an order or cleanup.

The root orchestrator owns account serialization and the testnet trading journey. This
helper consumes its key descriptor on stdin and returns only public service metadata.
"""

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from guard_harness.linux_lifecycle import MARKER, ROOT_PATH, authenticated_file, require
from guard_harness.runner import run


def opt_metadata() -> dict[str, object]:
    """Read only fixed /opt stat fields; never retain an exception or follow a symlink."""
    try:
        info = Path("/opt").lstat()
    except OSError:
        return {"uid": None, "gid": None, "mode": None, "directory": None, "symlink": None}
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"),
        "directory": stat.S_ISDIR(info.st_mode),
        "symlink": stat.S_ISLNK(info.st_mode),
    }


def container_install_failure_category(output: str) -> str:
    """Recognize complete public installer refusals; retain no private output fragment."""
    if type(output) is not str:
        return "unknown"
    refusals = {
        "Verified image signature admission failed before wallet input.": (
            "container-image-signature"
        ),
        "Verified image pull failed before wallet input.": "container-image-pull",
        "Guard setup command failed; activation remains inhibited.": "container-guard-setup",
        "Encrypted supervisor installation failed; activation remains inhibited.": (
            "container-supervisor"
        ),
        "Guard did not reach the expected healthy account/risk/licence state.": (
            "container-readiness"
        ),
    }
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
    ):
        refusals[
            "Guard did not reach the expected healthy account/risk/licence state. "
            f"(predicate={predicate})."
        ] = "container-readiness-" + predicate
    for message, category in refusals.items():
        if output == "Container installation refused: " + message + "\n":
            return category
    return "unknown"


def native_install_failure_category(output: str) -> str:
    """Only a complete fixed shell refusal line identifies a native prerequisite."""
    if type(output) is not str or len(output) > 65536:
        return "unknown"
    refusals = {
        (
            "protected testnet stdin requires systemd-creds; plaintext fallback is refused"
        ): "native-prerequisite",
        (
            "service instance requires systemd-creds; plaintext fallback is refused"
        ): "native-prerequisite",
        "service instance port is already listening": "native-listener",
        "missing protected testnet key frame": "native-key-frame",
        "protected testnet frame requires exactly 64 hex digits": "native-key-frame",
        "invalid protected testnet key frame": "native-key-frame",
        "the key was refused; nothing was stored": "native-key-refused",
        "systemd-creds could not encrypt the key": "native-credential-encryption",
        "managed software path is not a real directory": "native-software-directory",
        "managed software directory is not root-owned": "native-software-owner",
        "managed software directory mode is invalid": "native-software-mode",
        "managed software directory has unsafe permissions": "native-software-permissions",
        "managed software parent is not publicly traversable": "native-software-parent-traversal",
        (
            "Guard did not become healthy; see the log above (journalctl -u zunder-guard-testnet)"
        ): "native-readiness",
    }
    lines = output.splitlines(keepends=True)
    if not lines:
        return "unknown"
    for message, category in refusals.items():
        if lines[-1] == "install.sh: " + message + "\n":
            return category
    return "unknown"


@dataclass(frozen=True)
class TestnetService:
    installer: Path
    installer_sha256: str
    account: str
    rules: str
    port: int
    output: Path
    marker: str
    container: bool = False
    ip_share: str = "1"

    def setup(self, key: bytes) -> dict[str, str]:
        require(self.ip_share in {"1", "0.4"}, "request allocation refused")
        require(os.geteuid() == 0 and Path("/run/systemd/system").is_dir(), "root systemd required")
        require(
            MARKER.is_file() and MARKER.read_text().strip() == self.marker,
            "disposable marker differs",
        )
        require(re.fullmatch(r"[0-9a-f]{32}", self.marker) is not None, "marker shape refused")
        require(
            re.fullmatch(r"0x[0-9a-fA-F]{40}", self.account) is not None, "account shape refused"
        )
        require(
            type(self.port) is int
            and 1024 <= self.port <= 65535
            and (self.port == 8547 if self.container else self.port != 8547),
            "port refused",
        )
        require(re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is not None, "key frame refused")
        authenticated_file(self.installer, self.installer_sha256)
        command = [
            "sh",
            str(self.installer),
            "--non-interactive",
            "--network",
            "testnet",
            "--account",
            self.account,
            "--key-stdin",
        ]
        # T2 shares its IP with the independent scanner; its caller reserves that share.
        if self.container:
            command.append("--container")
            # Protected container runtime fixes its port to 8547. Existing setup
            # preserves all risk choices; the released installer rejects overrides.
            fresh = not Path("/etc/zunder-guard-container/config.json").exists()
            if fresh:
                command.extend(
                    ["--rules", self.rules, "--equity-cap", "40", "--ip-share", self.ip_share]
                )
            # Fresh init and supervisor provisioning each consume one stdin frame.
            frames = key * (2 if fresh else 1)
        else:
            command.extend(
                [
                    "--rules",
                    self.rules,
                    "--equity-cap",
                    "40",
                    "--ip-share",
                    self.ip_share,
                    "--listen",
                    f"127.0.0.1:{self.port}",
                    "--service-instance",
                    "testnet",
                ]
            )
            frames = key
        run(
            command,
            log=self.output / "testnet-service-install.log",
            timeout=600,
            stdin=frames,
            secrets=[key.decode().strip()],
            sensitive_output=True,
            failure_classifier=(
                container_install_failure_category
                if self.container
                else native_install_failure_category
            ),
            env={"PATH": ROOT_PATH, "HOME": "/root"},
        )
        if self.container:
            config = json.loads(Path("/etc/zunder-guard-container/config.json").read_bytes())
            require(config.get("mode") == "testnet", "container network differs")
            require(
                config.get("account", "").lower() == self.account.lower(),
                "container account differs",
            )
            credential = Path("/etc/zunder-guard-container/credential.cred")
            require(
                credential.is_file() and not credential.is_symlink(), "encrypted credential missing"
            )
            require(
                credential.stat().st_uid == 0 and credential.stat().st_mode & 0o077 == 0,
                "encrypted credential permissions differ",
            )
            unit = Path("/etc/systemd/system/zunder-guard-container.service").read_text()
            require(
                "LoadCredentialEncrypted=" in unit and "LoadCredential=" not in unit,
                "container credential route differs",
            )
            mount = run(
                [
                    "docker",
                    "volume",
                    "inspect",
                    str(config["volume"]),
                    "--format",
                    "{{.Mountpoint}}",
                ],
                log=self.output / "testnet-volume.log",
                timeout=30,
                sensitive_output=True,
                env={"PATH": ROOT_PATH, "HOME": "/root"},
            ).output.strip()
            require(
                mount.startswith("/var/lib/docker/volumes/") and mount.endswith("/_data"),
                "managed volume path differs",
            )
            return {
                "unit": "zunder-guard-container.service",
                "binary": "",
                "home": mount,
                "url": f"http://127.0.0.1:{self.port}",
            }
        dropin = Path("/etc/systemd/system/zunder-guard-testnet.service.d/10-install.conf")
        text = dropin.read_text()
        require(
            "LoadCredentialEncrypted=" in text and "LoadCredential=" not in text,
            "testnet service credential is not encrypted",
        )
        require(
            "--key-stdin" in text and "--network testnet" in text, "testnet service route differs"
        )
        require(
            not Path("/etc/zunder-guard-testnet/hl-api-wallet-key").exists(),
            "plaintext credential exists",
        )
        return {
            "unit": "zunder-guard-testnet.service",
            "binary": "/opt/zunder-guard-testnet/bin/zunder-guard",
            "home": "/var/lib/zunder-guard-testnet",
            "url": f"http://127.0.0.1:{self.port}",
        }
