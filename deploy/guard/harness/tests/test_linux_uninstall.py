"""Exercise the full installer with local filesystem and service-manager fixtures."""

import os
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"


class Installation:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.prefix = root / "usr/local/bin"
        self.notices = root / "usr/local/share/licenses/zunder-guard"
        self.units = root / "etc/systemd/system"
        self.unit = self.units / "zunder-guard.service"
        self.dropin = self.units / "zunder-guard.service.d/10-install.conf"
        self.calls = root / "calls"
        self.shims = root / "shims"
        self.shims.mkdir()
        self.preserved = [
            root / "var/lib/zunder-guard/guard.toml",
            root / "var/lib/zunder-guard/decisions.jsonl",
            root / "etc/zunder-guard/hl-api-wallet-key",
            root / "etc/credstore.encrypted/zunder-guard.hl-api-wallet-key",
            root / "etc/zunder-guard/mainnet-confirm.env",
            self.units / "zunder-guard.service.d/operator.conf",
            self.prefix / "other-program",
            self.notices / "operator-note",
        ]
        for path in [self.prefix / "zunder-guard", self.unit, self.dropin, *self.preserved]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture preserved bytes\n")
        for name in ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"]:
            (self.notices / name).write_text("fixture notice\n")
        self.script = root / "install.sh"
        source = INSTALLER.read_text().replace("/etc/systemd/system", str(self.units))
        source = source.replace("PREFIX=/usr/local/bin", f"PREFIX={self.prefix}")
        source = source.replace(
            "PREFIX=/opt/$SERVICE_UNIT/bin", f"PREFIX={root}/opt/$SERVICE_UNIT/bin"
        )
        self.script.write_text(source)
        self.shim("uname", "printf 'Linux\\n'\n")
        self.shim("id", 'printf "%s\\n" "${FIXTURE_UID:-0}"\n')
        self.shim("curl", "exit 99\n")
        self.shim(
            "systemctl",
            'printf "%s\\n" "$*" >> "$FIXTURE_CALLS"\n'
            'case "$*" in\n'
            ' *FragmentPath*) if [ -f "$FIXTURE_UNIT" ]; then '
            'printf "%s\\n" "${FIXTURE_FRAGMENT:-$FIXTURE_UNIT}"; fi ;;\n'
            ' *ActiveState*) printf "%s\\n" "${FIXTURE_ACTIVE:-inactive}" ;;\n'
            ' disable*) exit "${FIXTURE_DISABLE_EXIT:-0}" ;;\n'
            " daemon-reload) exit 0 ;;\n"
            " *) exit 98 ;;\n"
            "esac\n",
        )

    def shim(self, name: str, body: str) -> None:
        path = self.shims / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)

    def run(self, *args: str, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(self.script), "--uninstall", *args],
            env={
                **os.environ,
                "PATH": f"{self.shims}:{os.environ['PATH']}",
                "FIXTURE_UNIT": str(self.unit),
                "FIXTURE_CALLS": str(self.calls),
                **environment,
            },
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )

    def assert_preserved(self) -> None:
        for path in self.preserved:
            assert path.read_text() == "fixture preserved bytes\n"

    def assert_installed(self) -> None:
        for path in [self.prefix / "zunder-guard", self.unit, self.dropin]:
            assert path.exists()
        for name in ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"]:
            assert (self.notices / name).exists()
        self.assert_preserved()


@pytest.fixture
def installation(tmp_path: Path) -> Installation:
    return Installation(tmp_path)


def test_managed_uninstall_stops_then_removes_only_owned_files(installation: Installation) -> None:
    result = installation.run()
    assert result.returncode == 0, result.stderr
    assert installation.calls.read_text().splitlines() == [
        "show zunder-guard.service --property=FragmentPath --value",
        "disable --now zunder-guard.service",
        "show zunder-guard.service --property=ActiveState --value",
        "daemon-reload",
    ]
    assert not (installation.prefix / "zunder-guard").exists()
    assert not installation.unit.exists()
    assert not installation.dropin.exists()
    for name in ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"]:
        assert not (installation.notices / name).exists()
    installation.assert_preserved()
    assert installation.run().returncode == 0  # Missing owned files are idempotent.


@pytest.mark.parametrize(
    "environment",
    [
        {"FIXTURE_UID": "1000"},
        {"FIXTURE_DISABLE_EXIT": "1"},
        {"FIXTURE_ACTIVE": "active"},
        {"FIXTURE_FRAGMENT": "/different-installer/guard.service"},
    ],
)
def test_service_failure_keeps_all_files(
    installation: Installation, environment: dict[str, str]
) -> None:
    assert installation.run(**environment).returncode != 0
    installation.assert_installed()


@pytest.mark.parametrize("target", ["binary", "prefix", "notice", "unit", "dropin"])
def test_uninstall_refuses_symlink_before_service_mutation(
    installation: Installation, target: str
) -> None:
    paths = {
        "binary": installation.prefix / "zunder-guard",
        "prefix": installation.prefix,
        "notice": installation.notices / "NOTICE",
        "unit": installation.unit,
        "dropin": installation.dropin.parent,
    }
    selected = paths[target]
    moved = selected.with_name(selected.name + "-original")
    selected.rename(moved)
    selected.symlink_to(moved, target_is_directory=moved.is_dir())
    assert installation.run().returncode != 0
    assert not installation.calls.exists()
    assert moved.exists()
    installation.assert_installed()


@pytest.mark.parametrize(
    "args",
    [
        ["--network", "paper"],
        ["--install-only"],
        ["--force"],
        ["--container"],
        ["--key-stdin"],
        ["--prefix", "relative"],
        ["--prefix", "/tmp/../bin"],
        ["--service-instance", "other"],
    ],
)
def test_uninstall_refuses_setup_and_ambiguous_targets(
    installation: Installation, args: list[str]
) -> None:
    assert installation.run(*args).returncode != 0
    assert not installation.calls.exists()
    installation.assert_installed()


def test_files_only_uninstall_leaves_service_and_state(installation: Installation) -> None:
    result = installation.run(
        "--no-service", "--prefix", str(installation.prefix), FIXTURE_UID="1000"
    )
    assert result.returncode == 0, result.stderr
    assert not installation.calls.exists()
    assert not (installation.prefix / "zunder-guard").exists()
    assert installation.unit.exists() and installation.dropin.exists()
    installation.assert_preserved()


def test_unregistered_active_service_is_not_treated_as_missing(installation: Installation) -> None:
    installation.unit.unlink()
    result = installation.run(FIXTURE_ACTIVE="active")
    assert result.returncode != 0
    assert (installation.prefix / "zunder-guard").exists()
    assert installation.dropin.exists()
    installation.assert_preserved()


def test_named_uninstall_does_not_touch_default_service(installation: Installation) -> None:
    prefix = installation.root / "opt/zunder-guard-testnet/bin"
    unit = installation.units / "zunder-guard-testnet.service"
    dropin = installation.units / "zunder-guard-testnet.service.d/10-install.conf"
    notices = prefix.parent / "share/licenses/zunder-guard"
    for path in [prefix / "zunder-guard", unit, dropin, notices / "LICENSE"]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("named installation")
    result = installation.run("--service-instance", "testnet", FIXTURE_UNIT=str(unit))
    assert result.returncode == 0, result.stderr
    assert not unit.exists() and not dropin.exists()
    assert not (prefix / "zunder-guard").exists()
    assert "disable --now zunder-guard-testnet.service" in installation.calls.read_text()
    installation.assert_installed()
