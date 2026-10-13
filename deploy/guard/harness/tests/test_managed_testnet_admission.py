"""Execute public installer admission offline; no helper, key read or download runs."""

import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"


def admission(system: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    assert system in {"Linux", "Darwin"}
    source = INSTALLER.read_text().split(
        "# ---------------------------------------------------------------- platform", 1
    )[0]
    # The shim exists only inside this test shell. Container admission resets PATH,
    # so a shell function supplies the inert platform without altering production.
    script = f"uname() {{ printf '%s\\n' {system}; }}\n" + source
    script += "\nprintf '%s\\n' authenticated-helper-dispatch-boundary\n"
    return subprocess.run(
        ["/bin/sh", "-c", script, "installer-admission", *arguments],
        input="",
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize(
    "system,extra",
    [("Linux", ["--container", "--account", "0x" + "1" * 40]), ("Darwin", [])],
)
def test_existing_managed_testnet_defers_setup_values_to_authenticated_helper(
    system: str, extra: list[str]
) -> None:
    result = admission(system, ["--non-interactive", "--network", "testnet", "--key-stdin", *extra])
    assert result.returncode == 0
    assert result.stdout == "authenticated-helper-dispatch-boundary\n"
    assert result.stderr == ""


@pytest.mark.parametrize("system,extra", [("Linux", ["--container"]), ("Darwin", [])])
def test_fresh_managed_testnet_keeps_supplied_setup_values(system: str, extra: list[str]) -> None:
    result = admission(
        system,
        [
            "--non-interactive",
            "--network",
            "testnet",
            "--key-stdin",
            "--rules",
            "zr1_fixture",
            "--account",
            "0x" + "1" * 40,
            "--equity-cap",
            "40",
            *extra,
        ],
    )
    assert result.returncode == 0
    assert result.stdout == "authenticated-helper-dispatch-boundary\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "system,arguments,error",
    [
        ("Linux", ["--network", "testnet", "--key-stdin"], "--non-interactive needs --rules"),
        (
            "Linux",
            ["--network", "testnet", "--key-stdin", "--rules", "zr1_fixture"],
            "testnet needs --account",
        ),
        (
            "Linux",
            ["--network", "testnet", "--key-stdin", "--service-instance", "testnet"],
            "service instance needs explicit rules, account, equity-cap and ip-share",
        ),
        ("Darwin", ["--network", "testnet"], "--non-interactive needs --rules"),
        (
            "Darwin",
            ["--network", "testnet", "--key-stdin", "--no-service"],
            "--key-stdin requires explicit testnet, non-interactive managed setup",
        ),
        (
            "Darwin",
            ["--network", "testnet", "--key-stdin", "--key-file", "/nonexistent"],
            "testnet private stdin cannot be combined with a key file or mainnet consent",
        ),
        (
            "Darwin",
            ["--network", "testnet", "--key-stdin", "--confirm-mainnet", "0x" + "1" * 40],
            "testnet private stdin cannot be combined with a key file or mainnet consent",
        ),
        (
            "Darwin",
            ["--network", "testnet", "--key-stdin", "--install-only"],
            "--install-only cannot be combined with setup options "
            "(rules, network, account, key, licence, limits, listen or --force)",
        ),
        (
            "Darwin",
            ["--key-stdin"],
            "--key-stdin requires explicit testnet, non-interactive managed setup",
        ),
        (
            "Darwin",
            ["--network", "paper", "--key-stdin"],
            "--key-stdin requires explicit testnet, non-interactive managed setup",
        ),
        ("Darwin", ["--network", "paper"], "--non-interactive needs --rules"),
        (
            "Linux",
            ["--container", "--network", "testnet", "--key-stdin", "--force"],
            "container mode requires managed setup",
        ),
        (
            "Linux",
            ["--container", "--network", "testnet", "--key-stdin", "--rules", "invalid"],
            "a rules string starts with zr1_",
        ),
        (
            "Darwin",
            ["--network", "testnet", "--key-stdin", "--account", "invalid"],
            "an account address is 0x and 40 hex digits",
        ),
        (
            "Darwin",
            ["--network", "mainnet", "--key-stdin"],
            "--key-stdin requires explicit testnet, non-interactive managed setup",
        ),
        ("Darwin", ["--network", "mainnet"], "--non-interactive needs --rules"),
        ("Darwin", ["--network", "mainnet", "--rules", "zr1_fixture"], "mainnet needs --account"),
        (
            "Linux",
            ["--container", "--network", "mainnet"],
            "mainnet container setup retains interactive confirmation and hidden input",
        ),
    ],
)
def test_setup_delegation_never_admits_native_plaintext_paper_or_mainnet(
    system: str, arguments: list[str], error: str
) -> None:
    result = admission(system, ["--non-interactive", *arguments])
    assert result.returncode == 1
    assert result.stderr == "install.sh: " + error + "\n"
    assert "authenticated-helper-dispatch-boundary" not in result.stdout


@pytest.mark.parametrize("system", ["Linux", "Darwin"])
def test_mainnet_file_confirmation_and_cap_remain_required(tmp_path: Path, system: str) -> None:
    # Readability alone is checked here. This file holds no key and is never read.
    readable = tmp_path / "readable"
    readable.touch()
    account = "0x" + "1" * 40
    arguments = [
        "--non-interactive",
        "--network",
        "mainnet",
        "--rules",
        "zr1_fixture",
        "--account",
        account,
    ]
    no_file = admission(system, arguments)
    assert no_file.returncode == 1
    assert no_file.stderr == (
        "install.sh: mainnet needs --key-file with a readable file "
        "(protected testnet also accepts --key-stdin)\n"
    )
    arguments += ["--key-file", str(readable)]
    no_confirmation = admission(system, arguments)
    assert no_confirmation.returncode == 1
    assert (
        no_confirmation.stderr
        == "install.sh: mainnet needs --confirm-mainnet naming the same account\n"
    )
    arguments += ["--confirm-mainnet", account]
    no_cap = admission(system, arguments)
    assert no_cap.returncode == 1
    assert (
        no_cap.stderr == "install.sh: mainnet needs --equity-cap "
        "(the most equity Guard sizes from, at most 2500 USDC)\n"
    )
    complete = admission(system, [*arguments, "--equity-cap", "40"])
    assert complete.returncode == 0
    assert complete.stdout == "authenticated-helper-dispatch-boundary\n"
