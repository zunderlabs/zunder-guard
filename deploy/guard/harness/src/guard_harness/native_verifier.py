"""Probe the Windows loader's verifier without changing its environment or refusal."""

import hashlib
import re
import subprocess
import threading
from pathlib import Path
from types import TracebackType

from guard_harness.native_release import Release

NAMES = ("SHA256SUMS", "SHA256SUMS.sigstore.json")


class LoaderDownloads:
    """Keep exact downloaded bytes in memory before the signed loader removes its temp dir."""

    def __init__(self, release: Release, env: dict[str, str]) -> None:
        self.release = release
        self.roots = {Path(env[name]) for name in ("TMP", "TEMP") if env.get(name)}
        self.before: set[Path] = set()
        self.sources: set[Path] = set()
        self.expected: tuple[bytes, ...] = ()
        self.bodies: tuple[bytes, ...] | None = None
        self.status = "loader-downloads-not-captured"
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def directories(self) -> set[Path]:
        return {
            path
            for root in self.roots
            for path in root.glob("zunder-guard-*")
            if re.fullmatch(r"zunder-guard-[0-9a-f]{32}", path.name)
            and not path.is_symlink()
            and path.is_dir()
        }

    def scan(self) -> None:
        for directory in self.directories() - self.before:
            paths = [directory / name for name in NAMES]
            if any(
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_nlink != 1
                or not 0 < path.stat().st_size <= 16 * 1024 * 1024
                for path in paths
            ):
                continue
            bodies = tuple(path.read_bytes() for path in paths)
            # A partial download must never become the probe's input. These are
            # the loader's files, with complete bytes pinned by C2 authentication.
            if bodies != self.expected:
                continue
            self.sources.add(directory)
            if len(self.sources) != 1:
                self.bodies = None
                self.status = "loader-downloads-ambiguous"
            else:
                self.bodies = bodies
                self.status = "captured-loader-downloads-match-authenticated-release"

    def watch(self) -> None:
        while not self.stop.is_set():
            try:
                self.scan()
            except OSError:
                pass  # Downloads and the loader's cleanup can race these reads.
            self.stop.wait(0.01)

    def __enter__(self) -> "LoaderDownloads":
        try:
            self.expected = tuple((self.release.assets / name).read_bytes() for name in NAMES)
            self.before = self.directories()
        except OSError:
            self.status = "authenticated-verifier-inputs-unavailable"
            return self
        self.thread = threading.Thread(target=self.watch, daemon=True)
        self.thread.start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join()


def verifier_probe(
    release: Release,
    downloads: LoaderDownloads,
    work: Path,
    *,
    clean: dict[str, str],
    full: dict[str, str],
    shell: str,
    account: str,
) -> None:
    """Retain both verifier outcomes; this diagnostic never admits an installation."""
    log = work / "verifier-probe.log"
    events = ["Windows signature-verification probe", "inputs: " + downloads.status]

    def redact(text: str) -> str:
        return (
            re.sub(re.escape(account), "[REDACTED]", text, flags=re.IGNORECASE) if account else text
        )

    try:
        if downloads.bodies is None:
            events.append("probe outcome: unavailable; original loader files were not captured")
            return
        loader = release.asset("i.ps1").decode("utf-8-sig")
        versions = re.findall(r"\$CosignVersion = '(v[0-9]+\.[0-9]+\.[0-9]+)'", loader)
        hashes = re.findall(r"\$CosignSha256 = '([0-9a-f]{64})'", loader)
        if len(versions) != 1 or len(hashes) != 1:
            events.append("probe outcome: signed loader verifier pin unavailable")
            return
        version, digest = versions[0], hashes[0]
        identity = (
            "https://github.com/zunderlabs/zunder-guard/.github/workflows/"
            "release.yml@refs/tags/" + release.tag
        )
        issuer = "https://token.actions.githubusercontent.com"
        events += ["cosign version: " + version, "cosign SHA-256: " + digest]
        inputs = work / "verifier-inputs"
        inputs.mkdir(mode=0o700)
        for name, body in zip(NAMES, downloads.bodies, strict=True):
            (inputs / name).write_bytes(body)
            events.append(name + " SHA-256: " + hashlib.sha256(body).hexdigest())
        verifier = inputs / "cosign-windows-amd64.exe"

        def quote(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        # Same TLS, Invoke-WebRequest and SHA-256 boundary as the per-user loader.
        script = work / "verifier-download.ps1"
        script.write_text(
            "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n"
            "[Net.ServicePointManager]::SecurityProtocol = "
            "[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12\n"
            "try {\n  Invoke-WebRequest -UseBasicParsing -Uri "
            + quote(
                "https://github.com/sigstore/cosign/releases/download/"
                + version
                + "/cosign-windows-amd64.exe"
            )
            + " -OutFile "
            + quote(str(verifier))
            + "\n  if ((Get-FileHash -LiteralPath "
            + quote(str(verifier))
            + " -Algorithm SHA256).Hash.ToLowerInvariant() -ne "
            + quote(digest)
            + ") { exit 2 }\n} catch { exit 1 }\nexit 0\n",
            encoding="utf-8-sig",  # PS5.1 reads non-ASCII runner paths correctly.
        )
        prepared = subprocess.run(
            [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            env=clean,
            input=b"",
            capture_output=True,
            check=False,
            timeout=180,
        )
        events.append("pinned download exit status: " + str(prepared.returncode))
        if prepared.returncode or hashlib.sha256(verifier.read_bytes()).hexdigest() != digest:
            events.append("probe outcome: pinned verifier download/check refused")
            return
        argv = [
            str(verifier),
            "verify-blob",
            "--bundle",
            str(inputs / NAMES[1]),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            str(inputs / NAMES[0]),
        ]
        events += ["certificate identity: " + identity, "certificate issuer: " + issuer]
        for label, env in (
            ("native_channels clean environment", clean),
            ("runner full environment", full),
        ):
            events.append("environment: " + label)
            try:
                result = subprocess.run(
                    argv, env=env, input=b"", capture_output=True, check=False, timeout=180
                )
                events += [
                    "exit status: " + str(result.returncode),
                    "stdout:\n" + redact(result.stdout.decode("utf-8", errors="replace")),
                    "stderr:\n" + redact(result.stderr.decode("utf-8", errors="replace")),
                ]
            except subprocess.TimeoutExpired as error:
                events += [
                    "exit status: unavailable (timeout)",
                    "stdout:\n" + redact((error.stdout or b"").decode("utf-8", errors="replace")),
                    "stderr:\n" + redact((error.stderr or b"").decode("utf-8", errors="replace")),
                ]
            except OSError:
                events.append("exit status: unavailable (process start failed)")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        events.append("probe outcome: preparation failed; original paper failure retained")
    finally:
        log.write_text(redact("\n".join(events)) + "\n", encoding="utf-8")
