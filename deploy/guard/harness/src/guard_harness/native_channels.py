"""Execute the literal macOS/Windows paper loader command on a disposable runner."""

import errno
import hashlib
import os
import platform
import re
import select
import socket
import subprocess
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from guard_harness.cli import GuardCLI
from guard_harness.native_paper import LifecycleError, healthy
from guard_harness.native_release import Release, staged_loader
from guard_harness.native_verifier import LoaderDownloads, verifier_probe
from guard_harness.paper_bot import LocalGuard
from guard_harness.paper_roundtrip import round_trip
from guard_harness.runner import run
from guard_harness.windows_environment import WINDOWS_LOCATIONS

# Ordered from specific refusals to wrapper/cmdlet failures. Never return a
# regex capture: paths, exception details and even successful setup output can
# contain private material. The per-user install has no machine ACL admission;
# ownership/inventory refusals below belong to its later -Uninstall path.
PAPER_FAILURE_PATTERNS = (
    (
        "verifier-trust-root",
        r"(?:getting trusted root|setting trusted material|tuf refresh failed)",
    ),
    ("signature-verification", r"signature\s+check\s+FAILED"),
    ("checksum-missing", r"is not in the signed checksums; refusing"),
    ("checksum", r"checksum mismatch|pinned SHA-256; refusing"),
    ("archive-missing-binary", r"the archive holds no zunder-guard\.exe"),
    ("install-copy", r"could not replace .+?\(is Guard running\?"),
    ("installed-version", r"installed binary reports"),
    ("download", r"download failed"),
    ("rules-refused", r"the rules code is refused|a rules string is zr1_"),
    ("console-required", r"init is interactive: run it on a terminal"),
    (
        "init-config-exists",
        r"exists; pass --force to replace it \(the old client keys stop working; "
        r"the journal is kept\)",
    ),
    ("init-runtime", r"zunder-guard: starting the async runtime:"),
    ("init-input-ended", r"zunder-guard: input ended"),
    ("uninstall-options", r"Per-user uninstall accepts only InstallDir and NonInteractive"),
    ("uninstall-directory", r"Noncanonical per-user uninstall directory"),
    ("uninstall-ancestor", r"Per-user uninstall ancestor is not a plain directory"),
    ("uninstall-executable", r"Owned per-user executable missing; removal refused"),
    ("uninstall-entry", r"Unknown or aliased per-user install entry; removal refused"),
    ("uninstall-ownership", r"Per-user installation ownership record refused"),
    ("uninstall-inventory", r"Per-user release inventory differs"),
    ("uninstall-changed-files", r"Installed release files changed; uninstall refused"),
    ("init-refused", r"zunder-guard init stopped"),
    # PowerShell's fixed command/error identifiers cover exceptions from
    # cmdlets and .NET, which the loader does not wrap in a fixed throw.
    (
        "archive-extraction",
        r"\bExpand-Archive\b|\b(?:ExpandArchiveHelper|ZipArchiveHelper)\b|"
        r"Microsoft\.PowerShell\.Archive\.psm1",
    ),
    (
        "install-directory",
        r"New-Item -ItemType Directory -Force -Path \$InstallDir|"
        r"Microsoft\.PowerShell\.Commands\.NewItemCommand",
    ),
    (
        "install-notices",
        r"Copy-Item -LiteralPath \$From -Destination|"
        r"Microsoft\.PowerShell\.Commands\.CopyItemCommand",
    ),
    ("install-inventory-write", r"\bSet-Content\b|\bConvertTo-Json\b"),
    ("file-hash", r"\bGet-FileHash\b"),
    ("signed-checksums-read", r"Get-Content -LiteralPath \$Sums"),
    ("user-path", r"\bSetEnvironmentVariable\b"),
    ("binary-version-call", r"\$Version = \(& \$Exe --version\)"),
)


def paper_failure_category(text: str) -> str:
    """Fixed categories only: terminal text can contain private material."""
    text = re.sub(r"\s+", " ", text)  # ConPTY wraps long refusals across terminal rows.
    for category, pattern in PAPER_FAILURE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return category
    return "unknown"


def channel_environment() -> dict[str, str]:
    """Keep OS/profile/module locations, never arbitrary runner credentials."""
    allowed = {
        "PATH",
        "HOME",
        "LOCALAPPDATA",
        "USERPROFILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
    }
    if platform.system() == "Windows":
        # PowerShell and module discovery need the normal Windows profile and
        # program roots. Python normalizes Windows environment names to upper
        # case; use a case-insensitive allow-list for the two PowerShell editions.
        allowed |= WINDOWS_LOCATIONS  # the same list as the installer rows (windows_environment)
    clean = {name: value for name, value in os.environ.items() if name.upper() in allowed}
    clean["TERM"] = "dumb"
    return clean


def dialogue(
    argv: list[str],
    account: str,
    *,
    env: dict[str, str],
    windows: bool,
    timeout: float = 1200,
    mode_prompt: bool = True,
    log: Path | None = None,
) -> None:
    """Public paper replies only; unknown/private-key prompts always refuse."""
    replies = [
        ("Keep these? [Y/edit]", ""),
        ("Hyperliquid account address", account),
        ("Mode: paper", "paper"),
        ("Paper mode reads which network's account", "testnet"),
    ]
    if not mode_prompt:
        replies = [item for item in replies if item[0] != "Mode: paper"]
    child = None
    pid, descriptor = 0, -1
    if windows:
        from winpty import Backend, PtyProcess

        child = PtyProcess.spawn(argv, env=env, backend=Backend.ConPTY)
    else:
        import pty

        pid, descriptor = pty.fork()
        if pid == 0:
            os.execve(argv[0], argv, env)
    pending, index, status = "", 0, None
    category = "unknown"
    events = ["[paper terminal output withheld]"]
    phases = {
        "Keep these? [Y/edit]": "rules",
        "Hyperliquid account address": "account",
        "Mode: paper": "mode",
        "Paper mode reads which network's account": "read-network",
    }
    deadline = time.monotonic() + timeout
    drain_deadline = None
    try:
        while time.monotonic() < deadline:
            chunk = ""
            readable, _, _ = select.select(
                [child.fileobj if child is not None else descriptor], [], [], 0.2
            )
            if readable:
                try:
                    chunk = (
                        child.read(65536)
                        if child is not None
                        else os.read(descriptor, 65536).decode(errors="replace")
                    )
                except EOFError:
                    chunk = ""
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = ""
                pending += chunk
                if len(pending) > 1048576 or "API wallet" in pending:
                    category = "output-or-private-prompt"
                    raise LifecycleError("paper channel output/private prompt refused")
                pending = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", pending)
                observed = paper_failure_category(pending)
                if observed != "unknown":
                    category = observed
                while status is None and index < len(replies) and replies[index][0] in pending:
                    prompt, reply = replies[index]
                    pending = pending.split(prompt, 1)[1]
                    if child is None:
                        os.write(descriptor, (reply + "\n").encode())
                    else:
                        child.write(reply + "\r\n")
                    events.append("reply phase: " + phases[prompt])
                    index += 1
            if child is None:
                finished, raw = os.waitpid(pid, os.WNOHANG)
                if finished:
                    status = os.waitstatus_to_exitcode(raw)
            elif not child.isalive():
                status = child.exitstatus
            if status is not None:
                # ConPTY can report process exit while its socket still holds
                # the final error. Drain readable output (bounded) before
                # recording the category; never send replies after known exit.
                if child is not None and chunk:
                    now = time.monotonic()
                    if drain_deadline is None:
                        drain_deadline = now + 2
                    if now < drain_deadline:
                        continue
                break
        if status != 0 or index != len(replies):
            outcome = (
                "deadline"
                if status is None
                else "child-nonzero"
                if status != 0
                else "incomplete-dialogue"
            )
            phase = phases[replies[index][0]] if index < len(replies) else "setup-exit"
            # Never include the terminal transcript, account, argv or private suffix.
            exit_status = (
                str(status) if type(status) is int and -255 <= status <= 255 else "unknown"
            )
            events += [
                "outcome: " + outcome,
                "next phase: " + phase,
                "exit status: " + exit_status,
            ]
            raise LifecycleError(
                "literal paper loader did not finish complete interactive setup "
                f"(outcome={outcome}, phase={phase}, exit={exit_status})"
            )
        events.append("outcome: passed")
    finally:
        try:
            if child is not None:
                child.close(force=True)
            else:
                if status is None:
                    import signal

                    os.killpg(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                os.close(descriptor)
        finally:
            if log is not None:
                log.write_text("\n".join([*events, "failure category: " + category]) + "\n")


def destinations(windows: bool, env: dict[str, str]) -> tuple[Path, ...]:
    if windows:
        return (Path(env["LOCALAPPDATA"]) / "Programs/zunder-guard/zunder-guard.exe",)
    return (Path("/usr/local/bin/zunder-guard"), Path(env["HOME"]) / ".local/bin/zunder-guard")


def clear_home(home: Path) -> None:
    """Remove only paper data created after a strict absent-default-home preflight."""
    paths = [home, *home.rglob("*")]
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths):
        raise LifecycleError("owned default paper home cleanup refused")
    if len(paths) > 1024 or any(path.is_file() and path.stat().st_nlink != 1 for path in paths):
        raise LifecycleError("owned default paper home inventory differs")
    for path in sorted(paths, key=lambda path: len(path.parts), reverse=True):
        if path.is_file():
            path.unlink()
        else:
            path.rmdir()


def remove_macos_paper(release: Release, binary: Path, *, env: dict[str, str], work: Path) -> None:
    """Measured manual removal of owned foreground software; no product uninstall claim."""
    import io
    import tarfile

    notices = binary.parent.parent / "share/licenses/zunder-guard"
    names = {"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"}
    archive_bytes = release.asset(f"zunder-guard-{release.tag}-darwin-arm64.tar.gz")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        expected = {}
        for name in names:
            member = archive.getmember(name)
            if not member.isfile():
                raise LifecycleError("signed paper notice is not a regular file")
            stream = archive.extractfile(member)
            if stream is None:
                raise LifecycleError("signed paper notice missing")
            with stream:
                expected[name] = stream.read()
    files = [binary, *[notices / name for name in sorted(names)]]
    if (
        notices.is_symlink()
        or not notices.is_dir()
        or {path.name for path in notices.iterdir()} != names
    ):
        raise LifecycleError("owned paper notice inventory differs")
    for path in files:
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise LifecycleError("owned foreground software is not plain installed files")
        if path != binary and path.read_bytes() != expected[path.name]:
            raise LifecycleError("owned paper notice differs from signed release")
    if (
        hashlib.sha256(binary.read_bytes()).hexdigest()
        != hashlib.sha256(release.binary("darwin-arm64")).hexdigest()
    ):
        raise LifecycleError("owned foreground binary changed before manual cleanup")
    if any(path.stat().st_uid != os.getuid() for path in files):
        run(
            ["sudo", "-n", "/bin/rm", "--", *map(str, files)],
            env=env,
            log=work / "manual-cleanup.log",
            timeout=30,
            stdin=b"",
            sensitive_output=True,
        )
        run(
            ["sudo", "-n", "/bin/rmdir", str(notices)],
            env=env,
            log=work / "manual-directory-cleanup.log",
            timeout=30,
            stdin=b"",
            sensitive_output=True,
        )
    else:
        for path in files:
            path.unlink()
        notices.rmdir()
    if any(path.exists() or path.is_symlink() for path in [*files, notices]):
        raise LifecycleError("owned foreground manual cleanup incomplete")


def execute(release: Release, work: Path, *, account: str, shell: str) -> dict[str, Any]:
    import tomllib

    from guard_harness.channel_evidence import commands, required

    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise LifecycleError("documented native channel requires disposable hosted runner")
    windows = platform.system() == "Windows"
    if not windows and (platform.system() != "Darwin" or os.geteuid() == 0):
        raise LifecycleError("macOS documented channel must run as the hosted runner user")
    work.mkdir(mode=0o700)
    clean = channel_environment()
    home = (
        Path(clean["LOCALAPPDATA"]) / "zunder-guard"
        if windows
        else Path(clean["HOME"]) / ".zunder-guard"
    )
    channel = "D2" if windows else "D1"
    target = "windows-amd64" if windows else "darwin-arm64"
    forms = commands(channel, canonical=os.environ.get("INSTALL_MATRIX_PROFILE") == "nightly")
    expected = hashlib.sha256(release.binary(target)).hexdigest()
    observed = []
    for form, literal in forms.items():
        directory = work / form
        directory.mkdir(mode=0o700)
        candidates = destinations(windows, clean)
        if (
            home.exists()
            or home.is_symlink()
            or any(path.exists() or path.is_symlink() for path in candidates)
        ):
            raise LifecycleError("documented channel needs fresh default user state/software")
        if not windows and any(
            (path.parent.parent / "share/licenses/zunder-guard").exists()
            or (path.parent.parent / "share/licenses/zunder-guard").is_symlink()
            for path in candidates
        ):
            raise LifecycleError("documented channel refuses existing paper notice inventory")
        for step in ("before", "after"):
            staged_loader(
                release,
                windows=windows,
                output=directory / (step + (".ps1" if windows else ".loader")),
                channel="canonical"
                if os.environ.get("INSTALL_MATRIX_PROFILE") == "nightly"
                else "staging",
            )
            if step == "before":
                argv = (
                    [
                        shell,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        # PS7's ConciseView can omit the command/error identifier
                        # on a module exception. NormalView matches PS5.1 and
                        # lets the allow-list classify it; text stays withheld.
                        "$ErrorView = 'NormalView'; " + literal,
                    ]
                    if windows
                    else ["/bin/sh", "-c", literal]
                )
                log = directory / "dialogue.log"
                downloads = LoaderDownloads(release, clean) if windows else None
                try:
                    with downloads if downloads is not None else nullcontext():
                        dialogue(
                            argv,
                            account,
                            env=clean,
                            windows=windows,
                            mode_prompt=form == "manifest-bare",
                            log=log,
                        )
                except LifecycleError:
                    # Only a fixed signature category admits verifier output;
                    # wizard/private output continues to be withheld entirely.
                    try:
                        if (
                            downloads is not None
                            and log.is_file()
                            and "failure category: signature-verification"
                            in log.read_text().splitlines()
                        ):
                            verifier_probe(
                                release,
                                downloads,
                                directory,
                                clean=clean,
                                full=dict(os.environ),
                                shell=shell,
                                account=account,
                            )
                    except OSError:
                        pass  # Diagnostic I/O must never replace the loader's refusal.
                    raise
        installed = [path for path in candidates if path.is_file() and not path.is_symlink()]
        if len(installed) != 1:
            raise LifecycleError("documented user installer destination differs")
        binary = installed[0]
        actual = run(
            [str(binary), "--version"],
            env=clean,
            log=directory / "version.log",
            timeout=30,
            stdin=b"",
        ).output.strip()
        if hashlib.sha256(
            binary.read_bytes()
        ).hexdigest() != expected or actual != "zunder-guard " + release.tag.removeprefix("v"):
            raise LifecycleError("literal loader installed another released binary/version")
        config = tomllib.loads((home / "guard.toml").read_text())
        if (
            config.get("mode") != "paper"
            or config.get("network") != "testnet"
            or config.get("account", "").lower() != account.lower()
        ):
            raise LifecycleError(
                "literal paper wizard did not initialize the default user home/account/network"
            )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        pair = GuardCLI(binary, directory, home).pair()
        with (directory / "runtime.log").open("wb") as output:
            process = subprocess.Popen(
                [
                    str(binary),
                    "--home",
                    str(home),
                    "run",
                    "--network",
                    "paper",
                    "--listen",
                    f"127.0.0.1:{port}",
                ],
                env=clean,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
                start_new_session=not windows,
            )
            try:
                guard = LocalGuard(f"http://127.0.0.1:{port}")
                status = healthy(guard, version=release.tag.removeprefix("v"))
                if status.get("account", "").lower() != account.lower():
                    raise LifecycleError("documented paper channel account differs")
                round_trip(guard, pair)
            finally:
                if windows:
                    process.terminate()
                else:
                    import signal

                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    if windows:
                        process.kill()
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                    raise LifecycleError("documented channel did not stop cleanly") from None
        if windows:
            run(
                [
                    shell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(directory / "after.ps1"),
                    "-Uninstall",
                    "-NonInteractive",
                ],
                env=clean,
                log=directory / "uninstall.log",
                timeout=120,
                stdin=b"",
                sensitive_output=True,
            )
            if binary.exists() or binary.is_symlink():
                raise LifecycleError("documented per-user release uninstall failed")
        else:
            remove_macos_paper(release, binary, env=clean, work=directory)
        clear_home(home)
        observed.append(
            dict(
                form=form,
                command=literal,
                result="passed",
                installed_binary_sha256=expected,
                version=release.tag.removeprefix("v"),
                mode="paper",
                account_network="testnet",
                health=True,
                paper_roundtrip=True,
                owned_process_stopped=True,
                cleanup_complete=True,
                setup_identity="runner-user",
                configuration_home="user-default",
                cleanup_method="released-per-user-uninstall" if windows else "owned-manual-cleanup",
            )
        )
    return dict(
        schema=1,
        result="passed",
        channel=channel,
        scenario="fresh",
        mode="paper",
        tag=release.tag,
        commit=release.commit,
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        installed_binary_sha256=expected,
        version=release.tag.removeprefix("v"),
        command=forms["manifest-bare"],
        loader_sha256=hashlib.sha256(release.asset("i.ps1" if windows else "i")).hexdigest(),
        cleanup_complete=True,
        coverage=sorted(required(channel, target)),
        executions=observed,
    )
