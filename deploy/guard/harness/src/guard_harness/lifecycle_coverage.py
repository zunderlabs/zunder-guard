"""Pinned measured acceptance for install rows and their documented distribution paths."""

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
# The only Windows testnet receipt scope Guard 1.0 admits.
WINDOWS_TESTNET_SCOPE = "windows-per-user"
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
    # Guard 1.0 Windows is the per-user install; the SCM service's crash recovery is
    # 1.0.1 work (decision of 15 Oct 2026).
    "I4": MODES
    | {
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
