"""T2 protected service custody/start only; never executes an order or cleanup.

The root orchestrator owns account serialization and the testnet trading journey. This
helper consumes its key descriptor on stdin and returns only public service metadata.
"""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from guard_harness.linux_lifecycle import MARKER, ROOT_PATH, authenticated_file, require
from guard_harness.runner import run


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

    def setup(self, key: bytes) -> dict[str, str]:
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
        if self.container:
            command.append("--container")
            # Protected container runtime fixes its port to 8547. Existing setup
            # preserves all risk choices; the released installer rejects overrides.
            fresh = not Path("/etc/zunder-guard-container/config.json").exists()
            if fresh:
                command.extend(["--rules", self.rules, "--equity-cap", "40", "--ip-share", "0.1"])
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
                    "0.1",
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
