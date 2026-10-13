import tomllib
from pathlib import Path
from typing import Any

import pytest

import guard_harness.mainnet_attack as attacks
from guard_harness.mainnet_attack import configuration
from guard_harness.mainnet_evidence import MatrixError
from guard_harness.native_release import Release

CONFIG = """mode = "paper"
network = "mainnet"
allow_mainnet = false
account = "public-account-fixture"
[policy]
max_notional = "40"
[policy.risk]
max_daily_loss = "0.02"
[auth]
clients = ["public-client-fixture"]
"""


@pytest.mark.parametrize("network", ["mainnet", "testnet"])
def test_attack_fixture_changes_only_declared_admission_fields(network: str) -> None:
    parsed = tomllib.loads(
        configuration(CONFIG.replace('network = "mainnet"', f'network = "{network}"'))
    )
    assert parsed["mode"] == "mainnet" and parsed["allow_mainnet"] is True
    assert parsed["policy"]["max_trading_equity_usd"] == "100"
    assert parsed["policy"]["max_notional"] == "40"
    assert parsed["policy"]["risk"]["max_daily_loss"] == "0.02"
    assert parsed["account"] == "public-account-fixture"
    assert parsed["auth"] == {"clients": ["public-client-fixture"]}


@pytest.mark.parametrize(
    "mutation", ["sending", "mainnet-allowed", "missing-policy", "duplicate-mode"]
)
def test_attack_fixture_refuses_uncontrolled_source(mutation: str) -> None:
    source = CONFIG
    if mutation == "sending":
        source = source.replace('mode = "paper"', 'mode = "testnet"')
    elif mutation == "mainnet-allowed":
        source = source.replace("allow_mainnet = false", "allow_mainnet = true")
    elif mutation == "missing-policy":
        source = source.replace("[policy]\n", "[other]\n")
    else:
        source = source + '\nmode = "paper"\n'
    with pytest.raises((MatrixError, tomllib.TOMLDecodeError)):
        configuration(source)


@pytest.mark.parametrize("network", [None, "mainnet", "testnet"])
def test_real_paper_constructor_selects_only_explicit_read_network(
    network: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "released-binary"
    binary.write_bytes(b"authenticated released bytes fixture")
    release = Release("v1.0.0-rc.5", "b" * 40, tmp_path / "assets")
    monkeypatch.setattr(Release, "binary", lambda self, target: binary.read_bytes())
    calls: list[list[str]] = []

    def constructor(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)
        assert argv[3:7] == ["init", "--non-interactive", "--network", "paper"]
        assert argv[argv.index("--account-network") + 1] == (network or "mainnet")
        assert "--no-key" in argv and "--key-stdin" not in argv
        assert kwargs["stdin"] == b"" and kwargs["sensitive_output"] is True
        raise RuntimeError("paper constructor boundary")

    monkeypatch.setattr(attacks, "run", constructor)
    options = {} if network is None else {"account_network": network}
    with pytest.raises(RuntimeError, match="paper constructor boundary"):
        attacks.execute(
            release,
            binary,
            account="0x" + "1" * 40,
            rules="zr1_fixture",
            work=tmp_path / "work",
            **options,
        )
    assert len(calls) == 1


@pytest.mark.parametrize("network", ["", "paper", "mainnet\ntestnet"])
def test_invalid_paper_read_network_refuses_before_subject_or_process(
    network: str, tmp_path: Path
) -> None:
    with pytest.raises(MatrixError, match="account network"):
        attacks.execute(
            Release("v1.0.0-rc.5", "b" * 40, tmp_path / "missing-assets"),
            tmp_path / "missing-binary",
            account="0x" + "1" * 40,
            rules="zr1_fixture",
            work=tmp_path / "work",
            account_network=network,
        )
    assert not (tmp_path / "work").exists()


def test_key_option_and_environment_cannot_earn_generic_missing_stdin_credit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    binary = tmp_path / "signed-subject"
    binary.write_bytes(b"fixture")
    release = Release("v1.0.0-rc.7", "a" * 40, tmp_path / "assets")
    monkeypatch.setattr(Release, "binary", lambda *_: b"fixture")

    def setup(argv: list[str], **kwargs: Any) -> None:
        if "init" in argv:
            (Path(argv[2]) / "guard.toml").write_text(CONFIG)

    monkeypatch.setattr(attacks, "run", setup)
    commands: list[tuple[list[str], dict[str, Any]]] = []

    def refuse(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        commands.append((argv, kwargs))
        assert kwargs["input"] == b""
        assert "ZUNDER_MAINNET_CONFIRM" not in kwargs["env"]
        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=attacks.LITERAL.encode())

    monkeypatch.setattr(subprocess, "run", refuse)
    proofs: list[dict[str, Any]] = []

    def capture(*args: Any, **kwargs: Any) -> None:
        proofs.append(kwargs)
        if len(proofs) == 3:
            raise RuntimeError("three-key-refusals-observed")

    monkeypatch.setattr(attacks, "record", capture)
    with pytest.raises(RuntimeError, match="three-key-refusals-observed"):
        attacks.execute(
            release, binary, account="0x" + "1" * 40, rules="zr1_fixture", work=tmp_path / "work"
        )
    assert [proof["passed"] for proof in proofs] == [True, False, False]
    assert proofs[1]["literal"] == proofs[2]["literal"] == "cannot be used with"
    assert "--key-stdin" in commands[1][0] and "--key-file" in commands[1][0]
    assert "--key-stdin" in commands[2][0]
    assert "ZUNDER_GUARD_KEY_FILE" in commands[2][1]["env"]
    assert "ZUNDER_API_WALLET_KEY" not in commands[2][1]["env"]


@pytest.mark.parametrize("output", [attacks.LITERAL, "cannot be used with"])
def test_container_refusals_require_the_boundary_actually_exercised(
    output: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import json
    import subprocess
    import tarfile

    release = Release("v1.0.0-rc.7", "b" * 40, tmp_path / "assets")
    image = "example.invalid/guard@sha256:" + "a" * 64
    binary = b"signed binary fixture"
    manifest = {
        "distribution": {
            "docker": {
                "image": "example.invalid/guard",
                "digest": "sha256:" + "a" * 64,
            }
        }
    }
    monkeypatch.setattr(
        Release,
        "asset",
        lambda self, name: (
            json.dumps(manifest).encode() if name == "release-manifest.json" else b"services: {}"
        ),
    )
    monkeypatch.setattr(Release, "binary", lambda self, target: binary)
    home = tmp_path / "home"
    home.mkdir()
    for name in ("guard.toml", "api-wallet-key"):
        (home / name).write_bytes(b"public negative fixture")
    captured = io.BytesIO()
    with tarfile.open(fileobj=captured, mode="w") as archive:
        entry = tarfile.TarInfo("zunder-guard")
        entry.size = len(binary)
        archive.addfile(entry, io.BytesIO(binary))
    calls: list[list[str]] = []
    records: list[dict[str, Any]] = []
    monkeypatch.setattr(attacks, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(attacks, "record", lambda release, **kwargs: records.append(kwargs))

    def process(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[:2] == ["docker", "cp"]:
            return subprocess.CompletedProcess(argv, 0, captured.getvalue(), b"")
        calls.append(argv)
        assert "--key-stdin" not in argv
        assert argv[-5:] == ["run", "--network", "mainnet", "--key-file", "/data/api-wallet-key"]
        assert kwargs["input"] == b""
        assert "ZUNDER_MAINNET_CONFIRM" not in kwargs["env"]
        return subprocess.CompletedProcess(argv, 1, b"", output.encode())

    monkeypatch.setattr(subprocess, "run", process)
    if output == attacks.LITERAL:
        attacks.containers(
            release, image=image, home=home, work=tmp_path / "work", account="public"
        )
    else:
        with pytest.raises(MatrixError, match="container refusal evidence incomplete"):
            attacks.containers(
                release, image=image, home=home, work=tmp_path / "work", account="public"
            )
    assert len(calls) == 2
    assert {item["case"] for item in records} == {"plain-docker", "compose"}
    assert all(item["literal"] == attacks.LITERAL for item in records)
    assert all(item["passed"] is (output == attacks.LITERAL) for item in records)


@pytest.mark.parametrize(
    "bad_case",
    [None, "plain-key-file", "key-file-option", "environment-key", "missing-credential-store"],
)
def test_actual_negative_installer_inputs_pass_setup_admission_and_failed_cases_fail_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad_case: str | None,
) -> None:
    import subprocess

    # Exercise unchanged real shell parsing/service admission plus its credential-store
    # guard, omitting the intervening download/verification/install phases entirely.
    # No keys, network access, systemd or root operations are involved in this regression.
    installer = (Path(__file__).parents[2] / "install.sh").read_text()
    prefix = installer.split(
        "# ---------------------------------------------------------------- platform", 1
    )[0]
    boundary = installer.split("  if ! { command -v systemd-creds", 1)[1]
    credential_guard = "if ! { command -v systemd-creds" + boundary.split("  # Linux shells", 1)[0]
    inert = tmp_path / "installer-admission-only.sh"
    inert.write_text(prefix + "\n" + credential_guard)
    actual_process = subprocess.run
    binary = tmp_path / "signed-subject"
    binary.write_bytes(b"fixture")
    release = Release("v1.0.0-rc.14", "a" * 40, tmp_path / "assets")
    monkeypatch.setattr(Release, "binary", lambda *_: b"fixture")
    monkeypatch.setattr(Release, "asset", lambda *_: installer.encode())

    def setup(argv: list[str], **kwargs: Any) -> None:
        if "init" in argv:
            (Path(argv[2]) / "guard.toml").write_text(CONFIG)

    monkeypatch.setattr(attacks, "run", setup)
    records: list[dict[str, Any]] = []
    commands: list[list[str]] = []
    monkeypatch.setattr(attacks, "record", lambda release, **kwargs: records.append(kwargs))

    def process(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        commands.append(argv)
        assert kwargs["input"] == b""
        if "/bin/sh" in argv:
            assert argv[argv.index("--ip-share") + 1] == "1"
            assert argv[argv.index("--listen") + 1] == "127.0.0.1:18548"
            shell = argv.index("/bin/sh")
            environment = dict(field.split("=", 1) for field in argv[argv.index("-i") + 1 : shell])
            result = actual_process(
                ["/bin/sh", str(inert), *argv[shell + 2 :]],
                env=environment,
                input=b"",
                capture_output=True,
                timeout=10,
                check=False,
            )
            expected = b"service instance requires systemd-creds; plaintext fallback is refused"
            assert result.returncode != 0 and expected in result.stderr
            assert b"needs explicit" not in result.stderr and b"listen must" not in result.stderr
            case = "missing-credential-store"
            output = result.stderr
        else:
            case = (
                "environment-key"
                if "ZUNDER_GUARD_KEY_FILE" in kwargs["env"]
                else "key-file-option"
                if "--key-stdin" in argv
                else "plain-key-file"
            )
            output = (
                attacks.LITERAL.encode() if case == "plain-key-file" else b"cannot be used with"
            )
        if case == bad_case:
            output = b"PRIVATE-SENTINEL generic unrelated refusal"
        return subprocess.CompletedProcess(argv, 1, b"", output)

    monkeypatch.setattr(subprocess, "run", process)
    options: dict[str, Any] = dict(
        account="0x" + "1" * 40, rules="zr1_fixture", work=tmp_path / "work"
    )
    if bad_case is None:
        attacks.execute(release, binary, **options)
    else:
        with pytest.raises(MatrixError, match="attack refusal evidence incomplete") as caught:
            attacks.execute(release, binary, **options)
        assert "PRIVATE" not in str(caught.value)
    assert len(commands) == len(records) == 4  # A bad early row cannot conceal later rows.
    assert all(record["passed"] is (record["case"] != bad_case) for record in records)
