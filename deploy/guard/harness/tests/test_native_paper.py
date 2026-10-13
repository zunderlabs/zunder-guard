import os
import plistlib
import subprocess
from pathlib import Path
from typing import cast

import pytest

from guard_harness.native_paper import LifecycleError, Paper, retained, verify_retained
from guard_harness.native_release import Release
from guard_harness.runner import RunError


@pytest.mark.parametrize("label", ["homebrew.mxcl.zunder-guard", "sh.brew.zunder-guard"])
@pytest.mark.parametrize("domains", [("user",), ("gui",), (), ("user", "gui")])
def test_crash_discovers_only_owned_nonroot_homebrew_service_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, domains: tuple[str, ...], label: str
) -> None:
    paper, plist, arguments, uid = launchd_fixture(tmp_path, monkeypatch, label=label)
    probes: list[str] = []
    kills: list[list[str]] = []

    def probe(words: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert words[:2] == ["launchctl", "print"]
        target = words[2]
        assert target in {
            f"user/{uid}/{label}",
            f"gui/{uid}/{label}",
        }
        probes.append(target)
        if target.split("/")[0] not in domains:
            return subprocess.CompletedProcess(words, 113, b"", b"private probe body")
        return subprocess.CompletedProcess(
            words, 0, launchd_text(target, plist, paper, arguments), b""
        )

    monkeypatch.setattr("guard_harness.native_paper.subprocess.run", probe)

    def capture_kill(words: list[str]) -> str:
        kills.append(words)
        return ""

    monkeypatch.setattr(paper, "command", capture_kill)
    if len(domains) == 1:
        paper.crash()
        assert kills == [["launchctl", "kill", "SIGKILL", f"{domains[0]}/{uid}/{label}"]]
    else:
        with pytest.raises(LifecycleError, match="missing or ambiguous"):
            paper.crash()
        assert not kills
    assert len(probes) == 2 and not any("system" in value for value in probes)
    for path in tmp_path.glob("step-*.log"):
        assert path.read_text() == "[owned launchd probe output withheld]\n"


def launchd_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, label: str = "homebrew.mxcl.zunder-guard"
) -> tuple[Paper, Path, list[str], int]:
    uid = os.getuid() or 501
    monkeypatch.setattr("guard_harness.native_paper.os.getuid", lambda: uid)
    paper = object.__new__(Paper)
    paper.brew, paper.sequence, paper.work = True, 0, tmp_path
    paper.env = {"HOME": str(tmp_path)}
    paper.home = tmp_path / "paper-state"
    paper.binary = tmp_path / "installed-binary"
    paper.binary.write_bytes(b"authenticated binary fixture")
    opt = tmp_path / "homebrew-opt-binary"
    opt.symlink_to(paper.binary)  # Real Homebrew plist uses opt_bin, harness uses prefix/bin.
    arguments = [str(opt), "run", "--network", "paper"]
    agents = tmp_path / "Library/LaunchAgents"
    agents.mkdir(parents=True)
    plist = agents / (label + ".plist")
    plist.write_bytes(
        plistlib.dumps(
            {
                "Label": label,
                "ProgramArguments": arguments,
                "EnvironmentVariables": {"ZUNDER_GUARD_HOME": str(paper.home)},
            }
        )
    )
    if os.stat(plist).st_uid != uid:
        original = Path.lstat

        def metadata(path: Path) -> os.stat_result:
            fields = list(original(path))
            fields[4] = uid
            return os.stat_result(fields)

        monkeypatch.setattr(Path, "lstat", metadata)
    return paper, plist, arguments, uid


def launchd_text(target: str, plist: Path, paper: Paper, arguments: list[str]) -> bytes:
    return (
        target
        + " = {\n path = "
        + str(plist.resolve())
        + "\n program = "
        + str(paper.binary)
        + "\n arguments = {\n"
        + "\n".join(arguments)
        + "\n }\n environment = {\n"
        + " ZUNDER_GUARD_HOME => "
        + str(paper.home)
        + "\n }\n pid = 123\n}\n"
    ).encode()


@pytest.mark.parametrize("label", ["homebrew.mxcl.zunder-guard", "sh.brew.zunder-guard"])
@pytest.mark.parametrize(
    "mutation",
    [
        "root",
        "plist-link",
        "writable",
        "foreign-program",
        "foreign-home",
        "foreign-loaded",
        "bad-status",
        "missing-pid",
    ],
)
def test_crash_refuses_unsafe_registration_or_unknown_domain_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, label: str
) -> None:
    paper, plist, arguments, uid = launchd_fixture(tmp_path, monkeypatch, label=label)
    if mutation == "root":
        monkeypatch.setattr("guard_harness.native_paper.os.getuid", lambda: 0)
    elif mutation == "plist-link":
        renamed = plist.with_suffix(".actual")
        plist.rename(renamed)
        plist.symlink_to(renamed)
    elif mutation == "writable":
        plist.chmod(0o666)
    elif mutation in {"foreign-program", "foreign-home"}:
        data = plistlib.loads(plist.read_bytes())
        if mutation == "foreign-program":
            data["ProgramArguments"] = ["/foreign/never-execute", "run", "--network", "paper"]
        else:
            data["EnvironmentVariables"]["ZUNDER_GUARD_HOME"] = "/foreign/home"
        plist.write_bytes(plistlib.dumps(data))

    def probe(words: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        text = launchd_text(words[2], plist, paper, arguments)
        if mutation == "foreign-loaded":
            text = text.replace(b"--network\npaper", b"--network\nmainnet")
        elif mutation == "missing-pid":
            text = text.replace(b" pid = 123\n", b"")
        return subprocess.CompletedProcess(
            words, 5 if mutation == "bad-status" else 0, text, b"private body"
        )

    monkeypatch.setattr("guard_harness.native_paper.subprocess.run", probe)
    monkeypatch.setattr(
        paper, "command", lambda words: pytest.fail("unadmitted job cannot be killed")
    )
    with pytest.raises(LifecycleError):
        paper.crash()


def paper_state(home: Path) -> dict[str, bytes]:
    state = {
        "guard.toml": b"paper configuration and pairing fixture\n",
        "risk-paper.jsonl": b"paper risk prefix\n",
        "decisions-paper.jsonl": b"paper decisions prefix\n",
    }
    for name, value in state.items():
        (home / name).write_bytes(value)
    return state


def test_paper_lifecycle_retains_its_journals_without_using_testnet_history(
    tmp_path: Path,
) -> None:
    expected = paper_state(tmp_path)
    for name in ("risk.jsonl", "decisions.jsonl"):
        (tmp_path / name).write_bytes(b"separate testnet history\n")
    before = retained(tmp_path)
    assert before == expected
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        with (tmp_path / name).open("ab") as output:
            output.write(b"next paper lifecycle record\n")
    verify_retained(before, tmp_path)
    for name in ("risk.jsonl", "decisions.jsonl"):
        assert (tmp_path / name).read_bytes() == b"separate testnet history\n"


def test_testnet_journals_cannot_substitute_for_missing_paper_journals(
    tmp_path: Path,
) -> None:
    for name in ("guard.toml", "risk.jsonl", "decisions.jsonl"):
        (tmp_path / name).write_bytes(b"testnet fixture\n")
    with pytest.raises(LifecycleError, match="configuration or journal missing"):
        retained(tmp_path)


def test_paper_append_consumes_zero_reserve_without_erasing_history(tmp_path: Path) -> None:
    expected = paper_state(tmp_path)
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        (tmp_path / name).write_bytes(expected[name] + b"\x00" * 4096)
    before = retained(tmp_path)
    assert before == expected
    for name in ("risk-paper.jsonl", "decisions-paper.jsonl"):
        (tmp_path / name).write_bytes(
            expected[name] + b"durable appended record\n" + b"\x00" * 4000
        )
    verify_retained(before, tmp_path)
    (tmp_path / "decisions-paper.jsonl").write_bytes(
        b"replaced populated prefix\n" + b"\x00" * 4096
    )
    with pytest.raises(LifecycleError, match="journal history changed"):
        verify_retained(before, tmp_path)


@pytest.mark.parametrize("name", ["guard.toml", "risk-paper.jsonl", "decisions-paper.jsonl"])
def test_paper_lifecycle_rejects_replaced_config_or_journal_prefix(
    tmp_path: Path, name: str
) -> None:
    before = paper_state(tmp_path)
    (tmp_path / name).write_bytes(b"replacement\n")
    with pytest.raises(LifecycleError, match="changed across lifecycle"):
        verify_retained(before, tmp_path)


@pytest.mark.parametrize("ambiguous", [False, True])
def test_missing_or_two_known_plists_never_selects_a_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ambiguous: bool
) -> None:
    paper, plist, _, _ = launchd_fixture(tmp_path, monkeypatch)
    if ambiguous:
        (plist.parent / "sh.brew.zunder-guard.plist").write_bytes(plist.read_bytes())
    else:
        plist.unlink()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("no domain probe"))
    monkeypatch.setattr(paper, "command", lambda _: pytest.fail("no kill"))
    with pytest.raises(LifecycleError, match="missing or ambiguous"):
        paper.crash()


def cleanup_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Paper:
    monkeypatch.setattr("guard_harness.native_paper.platform.system", lambda: "Darwin")
    release = cast(Release, object())
    return Paper(release=release, previous=release, work=tmp_path, shell="sh")


def test_final_stop_after_uninstall_does_not_reload_removed_formula(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paper = cleanup_fixture(tmp_path, monkeypatch)
    calls: list[list[str]] = []
    uninstalled = False

    def command(words: list[str]) -> str:
        nonlocal uninstalled
        calls.append(words)
        if words == ["brew", "uninstall", "zunder-guard"]:
            uninstalled = True
        elif uninstalled:
            raise RunError("Refusing to load formula from untrusted tap")
        return ""

    monkeypatch.setattr(paper, "command", command)
    try:
        paper.start()
        paper.stop()
        paper.command(["brew", "uninstall", "zunder-guard"])
    finally:
        paper.stop()
    assert calls == [
        ["brew", "services", "start", "zunder-guard"],
        ["brew", "services", "stop", "zunder-guard"],
        ["brew", "uninstall", "zunder-guard"],
    ]


def test_failed_start_still_requires_actual_service_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paper = cleanup_fixture(tmp_path, monkeypatch)
    calls: list[list[str]] = []

    def command(words: list[str]) -> str:
        calls.append(words)
        if words[2] == "start":
            raise RunError("start failed after registering service")
        return ""

    monkeypatch.setattr(paper, "command", command)
    with pytest.raises(RunError, match="start failed"):
        try:
            paper.start()
        finally:
            paper.stop()
    assert [words[2] for words in calls] == ["start", "stop"]
    assert not paper.brew_stop_required


def test_failed_stop_is_not_treated_as_completed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paper = cleanup_fixture(tmp_path, monkeypatch)

    def command(words: list[str]) -> str:
        if words[2] == "stop":
            raise RunError("stop failed")
        return ""

    monkeypatch.setattr(paper, "command", command)
    paper.start()
    with pytest.raises(RunError, match="stop failed"):
        paper.stop()
    assert paper.brew_stop_required


def test_never_started_service_needs_no_brew_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paper = cleanup_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(paper, "command", lambda words: pytest.fail("no service was started"))
    paper.stop()
