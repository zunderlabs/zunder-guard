"""T2 protected service custody/start only; never executes an order or cleanup.

The root orchestrator owns account serialization and the testnet trading journey. This
helper consumes its key descriptor on stdin and returns only public service metadata.
"""

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
            type(self.port) is int and 1024 <= self.port <= 65535 and self.port != 8547,
            "port refused",
        )
        require(re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is not None, "key frame refused")
        authenticated_file(self.installer, self.installer_sha256)
        run(
            [
                "sh",
                str(self.installer),
                "--non-interactive",
                "--network",
                "testnet",
                "--service-instance",
                "testnet",
                "--rules",
                self.rules,
                "--account",
                self.account,
                "--equity-cap",
                "40",
                "--ip-share",
                "0.1",
                "--listen",
                f"127.0.0.1:{self.port}",
                "--key-stdin",
            ],
            log=self.output / "testnet-service-install.log",
            timeout=600,
            stdin=key,
            secrets=[key.decode().strip()],
            sensitive_output=True,
            env={"PATH": ROOT_PATH, "HOME": "/root"},
        )
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
