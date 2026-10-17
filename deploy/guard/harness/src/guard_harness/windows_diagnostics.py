"""Finite Windows lifecycle failure observations; never receipts or raw output."""

import re
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from guard_harness.guard_refusals import GUARD_SERVICE_REFUSALS
from guard_harness.runner import RunError

STEPS = frozenset(
    {
        "per-user-lifecycle",
        "per-user-readiness",
        "per-user-shutdown",
        "per-user-journal-audit",
        "crash-policy-prepare",
        "scm-install",
    }
)
REFUSALS = {
    "stored-key per-user runtime exited": "per-user-runtime-exited",
    "per-user testnet identity mismatch": "per-user-identity-mismatch",
    "per-user testnet readiness deadline": "per-user-readiness-deadline",
    "candidate crash-policy refusal probe did not complete": "crash-policy-probe-incomplete",
    "candidate did not emit the exact crash-policy refusal": "crash-policy-refusal-mismatch",
    "cannot read hosted Windows crash policy": "crash-policy-unreadable",
    "cannot remove hosted Windows crash policy": "crash-policy-removal-failed",
    "hosted crash-policy removal did not confirm four absent keys": "crash-policy-still-present",
}


# Explicit literals from the signed Windows loader/helper. No paths, SIDs, accounts,
# rights masks, exception details or input fragments are copied into observations.
# This frozen allow-list is diagnostic only; it never admits a lifecycle or a receipt.
INSTALLER_WRAPPER = (
    "Verified service helper did not complete. Organization execution policy "
    "remains authoritative; no policy was changed. Inspect the preceding error "
    "and use the retained helper Status/Resume only for an owned pending setup."
)
INSTALLER_REFUSALS = frozenset(
    {
        "A transaction is pending; use its exact retained helper Resume.",
        "Archive member exceeds installer size bound.",
        "Binding differs from owned transaction.",
        "Broker identity mismatch.",
        "Builder fee readiness fields must be present booleans.",
        "Case-colliding signed asset refused.",
        "Completed lifecycle: use explicit Upgrade or Start; loader never reinitializes.",
        "Configuration or journal changed during disabled upgrade; no rollback of state attempted.",
        "Consumed asset must appear exactly once in signed checksums.",
        "Different licence supplied on resume; use explicit service licence-set.",
        "Equity cap is outside the existing mainnet ceiling.",
        "Equity cap must be a decimal string.",
        "Exact explicit ConfirmAccount is required.",
        "Exact stable or release candidate tag required.",
        "Executable differs from admitted binding.",
        "Existing journal is never initialized again or resumed automatically.",
        "Existing machine file entry refused.",
        "Existing transaction identity differs; nothing was changed.",
        "Explicit Startup Manual or DelayedAuto is required; no default activation.",
        "Explicit account/confirmation and decimal cap required.",
        "Explicit human review note required.",
        "Explicit repeated account confirmation did not match.",
        "Explicit scoped journal initialization is required.",
        "Fee-free status requires an active licence.",
        "Guard public metadata validation failed.",
        "Guard refused this lifecycle step; no following step was performed.",
        "Image rollback requires explicit pre-start upgrade recovery and unchanged journal.",
        "Initialized Testnet risk journal is missing; no reset permitted.",
        "Instance already exists. Use retained helper Resume/Upgrade; never Force or reinitialize.",
        "Interrupted activation left disabled. Review Status and explicitly Start again.",
        "Invalid instance ID.",
        "Invalid public licence key.",
        "Invalid rules code.",
        "Invalid service instance Id.",
        "Journal changed while quiescing; rollback refused.",
        "Journal not committed; explicitly invoke JournalInit with a review note.",
        "Listener is not the admitted broker child.",
        "Listener virtual account differs.",
        "Loopback readiness request did not succeed.",
        "Machine file absence could not be admitted.",
        "Main account must have 40 hex digits.",
        "Mainnet needs an elevated interactive console; EOF or cancellation never confirms setup.",
        "Mainnet refuses NonInteractive, KeyStdin, InstallOnly, Force and alternate InstallDir.",
        "Mainnet requires native Windows x64 PowerShell.",
        "Mainnet runtime cannot report paper fee state.",
        "Mainnet service readiness must use explicit loopback IP.",
        "Malformed signed checksum line refused.",
        "Missing old binding backup and unexpected active binding.",
        "Missing old image backup and unexpected active digest.",
        "Missing or reparse machine path refused.",
        "Missing or unsupported builder approval state.",
        "NUL in SCM argument refused; transaction remains pending.",
        "New admitted release digest changed.",
        "No owned transaction. Refusing to adopt existing state.",
        "No unique owned loopback listener.",
        "Noncanonical machine file refused.",
        "Noncanonical machine path refused.",
        "Old binding backup changed.",
        "Old image backup changed.",
        (
            "Open a trusted elevated PowerShell window explicitly; the loader will not "
            "elevate a downloaded script."
        ),
        "Oversized owned transaction refused.",
        "Oversized readiness response.",
        "Oversized transaction refused.",
        "Owned executable still has a live process; no mutation permitted.",
        (
            "Owned runtime did not meet mainnet/account/risk/licence readiness; service "
            "is being disabled."
        ),
        "Owned service must be stopped with startup Disabled.",
        "Partial installation image differs from transaction.",
        (
            "Pending transaction belongs to another release. Use its retained helper "
            "Status/Resume; no service was changed."
        ),
        "Pinned verifier checksum mismatch.",
        "Prepared service metadata differs from transaction.",
        "Private unattended key input is Testnet Prepare/Resume only.",
        "Protected Testnet key setup requires explicit private redirected stdin.",
        "Protected Testnet requires NonInteractive, private KeyStdin and the machine installation.",
        "Protected Testnet requires explicit account, repeated account, equity cap and rules.",
        "Recovered API wallet differs from transaction.",
        "Recovery backup does not match durable admission.",
        "Release signature verification failed.",
        "Release source must be HTTPS or an offline release directory.",
        "Reparse ACL target refused.",
        "Required executable or notice missing.",
        "Resume must use the exact transaction release cache.",
        "Retained lifecycle helper changed.",
        "Running lifecycle helper is not the signed release helper.",
        "Runtime changed during readiness proof.",
        "Runtime equity cap differs.",
        "Runtime has no fresh synchronization for this start.",
        "Runtime mainnet/account/risk admission not ready.",
        "Runtime readiness field missing.",
        "Runtime risk readiness requires boolean fields.",
        "Runtime schema must be an integer.",
        "Runtime start timestamp must be an integer.",
        "Runtime synchronization timestamp must be an integer.",
        "Runtime version/status schema differs from admitted release.",
        "SCM broker not running.",
        "SCM client cleanup failed; transaction remains pending.",
        "SCM client could not start; transaction remains pending.",
        "SCM client did not exit after termination.",
        "SCM client timed out; transaction remains pending.",
        "SCM did not disable startup.",
        "SCM operation failed; transaction remains pending.",
        "SCM registration is not this owned installation.",
        "Signed release asset checksum mismatch.",
        "Testnet cannot adopt a Mainnet journal transaction.",
        (
            "Testnet journal is created only during fresh init; no reinitialization or "
            "automatic resume."
        ),
        "Testnet requires a separate testnet- instance identity.",
        "Testnet requires fee mode off or an active fee-free licence.",
        "Transaction account differs from explicit confirmation.",
        "Transaction belongs to another sending network; adoption refused.",
        "Transaction identity or phase is ambiguous; refuse recovery.",
        (
            "Uncommitted config staging exists. Retained helper Status/Resume requires "
            "manual inspection; no init or deletion repeated."
        ),
        "Uninstalled instance data is retained; automatic adoption/reinitialization is refused.",
        "Unknown interrupted image state.",
        "Unknown transaction operation.",
        "Unsafe, repeated or unexpected archive member.",
        "Unsupported fee mode; trading readiness cannot be established.",
        "Unsupported owned sending network.",
        "Unsupported protected service network.",
        "Upgrade needs an owned installed instance.",
        "Use the exact retained helper named by this transaction.",
        "Validated licence is not active/fee-free in this runtime.",
        "Verified binary does not report the release version.",
        "Windows mainnet requires native x64, not ARM emulation.",
        (
            "Windows did not resolve ProgramData or Program Files for this process; run the "
            "installer with the complete Windows environment."
        ),
    }
)
PATH_KINDS = ("drive-root", "program-data-root", "program-files-root", "protected-path")
INSTALLER_REFUSALS |= frozenset(
    f"Untrusted machine path owner ({kind}, owner={owner})."
    for kind in PATH_KINDS
    for owner in ("current-user", "other")
)
INSTALLER_REFUSALS |= frozenset(
    f"Organization {scope} execution policy is {policy} and prevents this Sigstore-verified "
    "helper. No policy was changed; contact the policy administrator."
    for scope in ("MachinePolicy", "UserPolicy")
    for policy in ("Restricted", "AllSigned")
)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ERROR_PREFIX = re.compile(
    r"^(?:.*\.ps1\s*:\s*|(?:Exception|Write-Error):\s*|"
    r"\+\s*FullyQualifiedErrorId\s*:\s*)"
)


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


# Fixed literals compared without whitespace: PowerShell 5.1 hard-wraps redirected error
# output at the buffer width, mid-word, so a wrapped payload rejoined either way matches.
COMPACT_REFUSALS = {_compact(message): message for message in INSTALLER_REFUSALS}
COMPACT_WRAPPER = _compact(INSTALLER_WRAPPER)


def _lines(stderr: str) -> tuple[list[str], list[str]]:
    raw, lines = [], []
    for line in ANSI.sub("", stderr[:65536]).splitlines():
        line = line.strip()
        line = re.sub(r"^\|\s*", "", line)
        raw.append(line)
        lines.append(ERROR_PREFIX.sub("", line).strip())
    return raw, lines


# The same prefixes as ERROR_PREFIX, on a compacted window: a wrap can split them too.
COMPACT_PREFIX = re.compile(r"^(?:.*\.ps1:|Exception:|Write-Error:|\+FullyQualifiedErrorId:)")


def installer_refusal(stderr: str) -> str:
    """Recognize PS5.1/PS7 error payloads; return only a frozen, public literal.

    PS7 decorates/wraps payload lines with a pipe; PS5.1 prefixes the script
    filename and hard-wraps redirected output at the buffer width, at a space or
    mid-word, the prefix included. Source excerpts, unknown messages and appended
    private data cannot match a complete allow-listed payload: the joined window,
    without its prefix, must equal the literal, ignoring only whitespace.
    """
    raw, lines = _lines(stderr)
    wrapper = False
    for index in range(len(lines)):
        # Bounded unfolding, returning the allow-list value rather than captured text.
        for count in range(1, 17):
            if index + count > len(lines):
                break
            candidates = (
                _compact(" ".join(lines[index : index + count])),
                COMPACT_PREFIX.sub("", _compact(" ".join(raw[index : index + count]))),
            )
            for compact in candidates:
                if compact in COMPACT_REFUSALS:
                    return COMPACT_REFUSALS[compact]
                for kind in PATH_KINDS:
                    if re.fullmatch(
                        re.escape(
                            _compact(
                                "Unprivileged machine path mutation rights refused "
                                f"({kind}, rights="
                            )
                        )
                        + r"[0-9a-f]{8}\)\.",
                        compact,
                    ):
                        return (
                            f"Unprivileged machine path mutation rights refused ({kind}, "
                            "rights withheld)."
                        )
                wrapper |= compact == COMPACT_WRAPPER
    return INSTALLER_WRAPPER if wrapper else "unknown"


# ErrorCategory names (System.Management.Automation.ErrorCategory): a closed enumeration.
ERROR_CATEGORIES = frozenset(
    {
        "NotSpecified",
        "OpenError",
        "CloseError",
        "DeviceError",
        "DeadlockDetected",
        "InvalidArgument",
        "InvalidData",
        "InvalidOperation",
        "InvalidResult",
        "InvalidType",
        "MetadataError",
        "NotImplemented",
        "NotInstalled",
        "ObjectNotFound",
        "OperationStopped",
        "OperationTimeout",
        "SyntaxError",
        "ParserError",
        "PermissionDenied",
        "ResourceBusy",
        "ResourceExists",
        "ResourceUnavailable",
        "ReadError",
        "WriteError",
        "FromStdErr",
        "SecurityError",
        "ProtocolError",
        "ConnectionError",
        "AuthenticationError",
        "LimitsExceeded",
        "QuotaExceeded",
        "NotEnabled",
    }
)
# A .NET or PowerShell error identifier: letters and dots only (no digits, so no key,
# account, SID or address; no separators, so no path or free text).
ERROR_ID = re.compile(r"[A-Za-z][A-Za-z.]{2,100}")
# Guard's own service refusals: exactly one of its fixed Rust literals (guard_refusals).
# Guard's inherited stderr is never wrapped by PowerShell.
GUARD_REFUSAL_PREFIX = "zunder-guard: service refused: "
GUARD_OS_ERROR = re.compile(r"zunder-guard: service I/O: .*\(os error (\d{1,6})\)")


def installer_details(stderr: str) -> list[str]:
    """Finite, sanitized classes of the installer's errors; never captured free text.

    Each line is `name: value`, where the value is a closed-set name, a letters-only
    error identifier, one of Guard's fixed service refusal literals or a decimal OS error.
    """
    found: dict[str, list[str]] = {}

    def add(name: str, value: str) -> None:
        values = found.setdefault(name, [])
        if value not in values and len(values) < 4:
            values.append(value)

    for raw in ANSI.sub("", stderr[:65536]).splitlines():
        line = raw.strip()
        if line.startswith(GUARD_REFUSAL_PREFIX):
            literal = line.removeprefix(GUARD_REFUSAL_PREFIX)
            if literal in GUARD_SERVICE_REFUSALS:
                add("guard service refusal", literal)
            else:
                add("guard error", "present")
            continue
        if match := GUARD_OS_ERROR.fullmatch(line):
            add("guard os error", match[1])
            continue
        if line.startswith("zunder-guard: "):
            add("guard error", "present")
            continue
        line = re.sub(r"^\|\s*", "", line)
        if match := re.fullmatch(r"\+\s*FullyQualifiedErrorId\s*:\s*([^,\s]+)(?:,.*)?", line):
            if ERROR_ID.fullmatch(match[1]):
                add("powershell error id", match[1])
        elif match := re.fullmatch(r"\+\s*CategoryInfo\s*:\s*([A-Za-z]+)\s*:.*", line):
            if match[1] in ERROR_CATEGORIES:
                add("powershell error category", match[1])
    return [f"{name}: {value}" for name, values in found.items() for value in values]


def reason(error: Exception) -> str:
    if isinstance(error, ModuleNotFoundError) and error.name == "pwd":
        return "posix-pwd-unavailable"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command-timeout"
    if isinstance(error, RunError):
        return "command-failed"
    # Return only a literal from this table; exception details never enter artifacts.
    return REFUSALS.get(str(error), "unknown")


@contextmanager
def observe(
    work: Path,
    step: str,
    *,
    installer: bool = False,
    after_failure: Callable[[], list[str]] | None = None,
) -> Iterator[Callable[[str], str] | None]:
    """Record a failing step's fixed classes. `after_failure` returns `name: value`
    lines from closed sets (such as the owned transaction's phase), read after a
    failed installer command; anything else it returns is dropped."""
    step = step if step in STEPS else "unknown"
    capture = installer and step == "scm-install"
    refusal = "unknown"
    details: list[str] = []

    def classify(stderr: str) -> str:
        nonlocal refusal, details
        refusal = installer_refusal(stderr)
        details = installer_details(stderr)
        return "unknown"  # runner's finite category; the literal lives only in this observation.

    try:
        yield classify if capture else None
    except Exception as error:
        work.mkdir(parents=True, exist_ok=True)
        failed = isinstance(error, RunError)
        observed: list[str] = []
        if capture and failed:
            observed = list(details)
            if after_failure is not None:
                try:
                    observed += [
                        line
                        for line in after_failure()
                        if re.fullmatch(r"[a-z ]{3,40}: [A-Za-z0-9 .;,'/()-]{1,160}", line)
                    ]
                except Exception:
                    observed.append("after-failure observation: unavailable")
        (work / f"windows-{step}-failure.log").write_text(
            f"Windows lifecycle failure step: {step}\nfailure reason: {reason(error)}\n"
            + (f"installer refusal: {refusal if failed else 'unknown'}\n" if capture else "")
            + "".join(line + "\n" for line in observed)
        )
        raise
