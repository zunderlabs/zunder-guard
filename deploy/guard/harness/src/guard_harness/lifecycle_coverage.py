"""Pinned measured acceptance for install rows and their documented distribution paths."""

import re
from collections.abc import Mapping

MODES = frozenset(
    {
        "paper:fresh-candidate",
        "paper:previous-release-upgrade",
        "testnet:fresh-candidate",
        "testnet:previous-release-upgrade",
        "restart",
        "journal-history",
        "pairing-retained",
        "upgrade",
        "reinstall",
        "uninstall",
        "cleanup",
    }
)
# Windows testnet receipt scopes: the per-user install alone, or the machine (SCM) service
# measured after it (its own receipt; the per-user receipt stays beside it).
WINDOWS_TESTNET_SCOPE = "windows-per-user"
WINDOWS_SERVICE_SCOPE = "windows-service"
# The first release whose Windows SCM service starts. An upgrade from an older release has
# no working service to upgrade: that scenario records WINDOWS_SERVICE_SKIP by name in its
# receipt and measures the per-user scope; from this release on, every upgrade measures the
# service too.
WINDOWS_SERVICE_SINCE = "v1.0.2"
WINDOWS_SERVICE_SKIP = "windows-service-skipped:previous-release-has-no-service"


def release_version(tag: str) -> tuple[int, int, int, int, int]:
    """The ordering key of a release tag `vX.Y.Z[-rc.N]`, shared by every harness check."""
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-rc\.([1-9]\d*))?", tag)
    if match is None:
        raise ValueError("release version required")
    # A final version follows every RC with the same numeric version.
    return int(match[1]), int(match[2]), int(match[3]), 0 if match[4] else 1, int(match[4] or 0)


def windows_service_measured(scenario: str, previous_tag: str) -> bool:
    """Whether a Windows scenario must measure the SCM service after the per-user install.

    Fresh: always. Upgrade: exactly when the previous release has a working service
    (`previous_tag >= WINDOWS_SERVICE_SINCE`); otherwise the scenario's receipt names the
    skip (WINDOWS_SERVICE_SKIP) and admission requires that name.
    """
    if scenario == "fresh":
        return True
    if scenario != "upgrade":
        raise ValueError("native lifecycle scenario refused")
    return release_version(previous_tag) >= release_version(WINDOWS_SERVICE_SINCE)


LIFECYCLE_COVERAGE: Mapping[str, frozenset[str]] = {
    "I1": MODES
    | {
        "paper:kernel-reboot",
        "testnet:kernel-reboot",
        "crash-recovery",
        "D1:curl-pipe",
        "D5:manual-archive",
    },
    "I2": MODES | {"crash-recovery", "D1:curl-pipe"},
    "I3": MODES | {"crash-recovery", "supervisor-reload", "D1:curl-pipe", "D3:homebrew"},
    # Windows: the per-user install and, from 1.0.2, the SCM service with its crash recovery.
    "I4": MODES
    | {
        "crash-recovery",
        "manual-crash-restart",
        "D2:irm-iex",
        "windows2022-ps51",
        "windows2022-ps7",
        "windows2025-ps51",
        "windows2025-ps7",
        "per-user:credential-manager",
    },
    "I5": MODES | {"crash-recovery", "D4:docker", "D4:compose"},
    "I6": MODES
    | {"paper:kernel-reboot", "testnet:kernel-reboot", "crash-recovery", "D7:container-native"},
    "I7": frozenset(
        {
            "signed-template-url",
            "signed-release",
            "stack-bootstrap",
            "paper-allow-resize-veto",
            "pairing",
            "restart",
            "crash-recovery",
            "instance-reboot",
            "previous-release-upgrade",
            "reinstall",
            "journal-prefix",
            "client-signature-survives",
            "uninstall",
            "data-retained",
            "owned-stack-and-retained-volume-cleanup",
            "D6:cloudformation",
        }
    ),
}
CHANNEL_COVERAGE: Mapping[str, Mapping[str, frozenset[str]]] = {
    "unix_loader": {row: frozenset({"D1:curl-pipe"}) for row in ("I1", "I2", "I3")},
    "windows_loader": {"I4": frozenset({"D2:irm-iex"})},
    "homebrew": {"I3": frozenset({"D3:homebrew"})},
    "docker": {"I5": frozenset({"D4:docker", "D4:compose"})},
    "archive": {"I1": frozenset({"D5:manual-archive"})},
    "aws_template": {"I7": frozenset({"D6:cloudformation"})},
    "container_native": {"I6": frozenset({"D7:container-native"})},
}
