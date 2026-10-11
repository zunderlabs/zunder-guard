"""Admit complete mainnet rows only from exact released-source native observations."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from guard_harness.attestation import verify_predicate
from guard_harness.journey_evidence import MAINNET_COVERAGE, PREDICATE_TYPE, _check
from guard_harness.native_release import Release


class MatrixError(ValueError):
    """Incomplete, diagnostic or identity-mismatched mainnet evidence."""


M1_STAGES = frozenset({"protected-setup-unapproved-wallet"})
SIGNING_CHECKS = {
    platform: {"hl-protocol.sdk-vectors", "guard-core.sign", "guard.keyread", "guard.framing"}
    | (
        {"guard.service.macos"}
        if platform == "macos"
        else {"guard.service.windows"}
        if platform == "windows"
        else set()
    )
    for platform in ("linux", "macos", "windows")
}
M2_ROUTES = {
    "missing-consent": "linux-systemd",
    "wrong-account-consent": "linux-systemd",
    "plain-key-file": "linux-systemd",
    "missing-credential-store": "linux-systemd",
    "key-file-option": "linux-systemd",
    "environment-key": "linux-systemd",
    "plain-docker": "plain-docker",
    "compose": "compose",
    "homebrew-services": "homebrew-services",
    "windows-per-user": "windows-per-user",
}
M2_LITERALS = {
    "missing-consent": "mainnet needs --confirm-mainnet",
    "wrong-account-consent": "the confirmation does not name the account",
    "missing-credential-store": (
        "service instance requires systemd-creds; plaintext fallback is refused"
    ),
    "windows-per-user": "mainnet is not offered on Windows outside the protected machine service",
    "homebrew-services": '"mode": "paper"',
    **{
        case: "a mainnet key comes only on standard input (--key-stdin)"
        for case in (
            "plain-key-file",
            "key-file-option",
            "environment-key",
            "plain-docker",
            "compose",
        )
    },
}
TARGETS = {
    "linux-systemd": "linux-amd64",
    "linux-container-native": "linux-amd64",
    "macos-launchdaemon": "darwin-arm64",
    "homebrew-foreground": "darwin-arm64",
    "windows-scm": "windows-amd64",
    "aws-template": "linux-arm64",
    "plain-docker": "linux-amd64",
    "compose": "linux-amd64",
    "homebrew-services": "darwin-arm64",
    "windows-per-user": "windows-amd64",
}


def observation(path: Path, release: Release, journey: str, route: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise MatrixError("native observation must be a regular receipt")
    value: Any = json.loads(path.read_bytes())
    digest = hashlib.sha256(release.asset("release-manifest.json")).hexdigest()
    binary_digest = hashlib.sha256(release.binary(TARGETS[route])).hexdigest()
    if not isinstance(value, dict) or any(
        value.get(key) != expected
        for key, expected in {
            "schema": 1,
            "journey": journey,
            "route": route,
            "tag": release.tag,
            "commit": release.commit,
            "harness_commit": release.commit,
            "manifest_sha256": digest,
            "binary_sha256": binary_digest,
            "result": "passed",
            "tier": "e2e",
            "diagnostic": False,
            "exchange_requests": 0,
        }.items()
    ):
        raise MatrixError("native observation failed or identifies different source/runtime")
    if (
        type(value["schema"]) is not int
        or type(value["exchange_requests"]) is not int
        or value["diagnostic"] is not False
    ):
        raise MatrixError("native observation numeric types differ")
    coverage = value.get("coverage")
    if (
        not isinstance(coverage, list)
        or any(not isinstance(item, str) for item in coverage)
        or len(set(coverage)) != len(coverage)
    ):
        raise MatrixError("native observation coverage malformed")
    return value


def native_row(row: str, release: Release, evidence: Path) -> dict[str, Any]:
    if row == "M1":
        for route in sorted(MAINNET_COVERAGE[row]):
            value = observation(evidence / row / f"{route}.json", release, row, route)
            if (
                set(value["coverage"]) != M1_STAGES
                or value.get("wallet_role") != "unapproved"
                or value.get("mode") != "mainnet"
            ):
                raise MatrixError(
                    "M1 requires actual protected setup refusal of an unapproved wallet"
                )
            for field in (
                "config_written",
                "credential_written",
                "service_enabled",
                "service_started",
            ):
                if value.get(field) is not False:
                    raise MatrixError("M1 refused setup left state, credentials or a service")
            if value.get("exit_code") == 0 or type(value.get("exit_code")) is not int:
                raise MatrixError("M1 did not observe a failed protected setup process")
            log = evidence / row / f"{route}.log"
            literal = value.get("expected_refusal")
            if literal != "is not an API wallet of" or log.is_symlink() or not log.is_file():
                raise MatrixError("M1 actual unapproved-wallet diagnostic missing")
            body = log.read_bytes()
            if (
                literal.encode() not in body
                or value.get("log_sha256") != hashlib.sha256(body).hexdigest()
            ):
                raise MatrixError("M1 actual refused userRole response was not captured")
    elif row == "M2":
        for case in sorted(MAINNET_COVERAGE[row]):
            value = observation(evidence / row / f"{case}.json", release, row, M2_ROUTES[case])
            if (
                value["coverage"] != [case]
                or type(value.get("exit_code")) is not int
                or (value["exit_code"] == 0 and case != "homebrew-services")
            ):
                raise MatrixError("M2 requires the literal failed process for every refusal")
            if case == "homebrew-services" and (
                value.get("mechanism") != "supervisor-mode" or value.get("observed_mode") != "paper"
            ):
                raise MatrixError(
                    "Homebrew service must positively remain paper under mainnet override"
                )
            literal = value.get("expected_refusal")
            if literal != M2_LITERALS[case]:
                raise MatrixError("M2 literal differs from the required platform refusal")
            log = evidence / row / f"{case}.log"
            if not isinstance(literal, str) or not literal or log.is_symlink() or not log.is_file():
                raise MatrixError("M2 refusal diagnostic missing")
            body = log.read_bytes()
            if (
                value.get("log_sha256") != hashlib.sha256(body).hexdigest()
                or literal.encode() not in body
            ):
                raise MatrixError("M2 expected refusal was not observed in captured process output")
    else:
        raise MatrixError("native row must be M1 or M2")
    return predicate(row, release)


def predicate(row: str, release: Release) -> dict[str, Any]:
    return dict(
        schema=1,
        journey=row,
        commit=release.commit,
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        result="passed",
        tier="e2e",
        coverage=sorted(MAINNET_COVERAGE[row]),
    )


def signing_row(release: Release, evidence: Path, logs: Path) -> dict[str, Any]:
    subject = release.assets / "release-manifest.json"
    digest = hashlib.sha256(release.asset("release-manifest.json")).hexdigest()
    for platform, required in SIGNING_CHECKS.items():
        verified = verify_predicate(
            subject,
            evidence / f"signing-{platform}.sigstore.json",
            workflow="journey.yml",
            commit=release.commit,
            tag=release.tag,
            predicate_type="https://zunderlabs.com/guard/signing/v1",
            log=logs / f"signing-{platform}.log",
        )
        value = verified.predicate
        if (
            set(value)
            != {"schema", "commit", "manifest_sha256", "result", "platform", "checks", "networks"}
            or type(value.get("schema")) is not int
            or value["schema"] != 1
            or value.get("commit") != release.commit
            or value.get("manifest_sha256") != digest
            or value.get("result") != "passed"
            or value.get("platform") != platform
            or value.get("networks") != ["mainnet", "testnet"]
        ):
            raise MatrixError("authenticated per-platform signing contract differs")
        checks = value.get("checks")
        if not isinstance(checks, list) or len(checks) != len(required) or set(checks) != required:
            raise MatrixError("SDK vectors and every public native key wrapper must pass")
    for row in ("T1", "T2"):
        verified = verify_predicate(
            subject,
            evidence / f"{row}.sigstore.json",
            workflow="journey.yml",
            commit=release.commit,
            tag=release.tag,
            predicate_type=PREDICATE_TYPE,
            log=logs / f"{row}.log",
        )
        _check(verified.predicate, row, release.commit, digest)
    return predicate("M3", release)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "row"):
        parser.add_argument("--" + name, required=True)
    for name in ("assets", "evidence", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    release = Release(args.tag, args.commit, args.assets)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = (
        signing_row(release, args.evidence, args.output)
        if args.row == "M3"
        else native_row(args.row, release, args.evidence)
    )
    (args.output / f"{args.row}.predicate.json").write_text(json.dumps(result) + "\n")


if __name__ == "__main__":
    main()
