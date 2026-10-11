import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import guard_harness.mainnet_evidence as matrix
from guard_harness.attestation import VerifiedPredicate
from guard_harness.journey_evidence import MAINNET_COVERAGE
from guard_harness.native_release import Release


@pytest.fixture
def release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Release:
    monkeypatch.setattr(Release, "asset", lambda self, name: b"authenticated manifest")
    monkeypatch.setattr(Release, "binary", lambda self, target: b"authenticated binary")
    result = Release("v1.0.0", "a" * 40, tmp_path)
    (tmp_path / "release-manifest.json").write_bytes(b"authenticated manifest")
    return result


def fixtures(root: Path, release: Release, row: str) -> None:
    directory = root / row
    directory.mkdir()
    for name in MAINNET_COVERAGE[row]:
        route = name if row == "M1" else matrix.M2_ROUTES[name]
        value: dict[str, Any] = dict(
            schema=1,
            journey=row,
            route=route,
            tag=release.tag,
            commit=release.commit,
            harness_commit=release.commit,
            diagnostic=False,
            manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
            binary_sha256=hashlib.sha256(release.binary(matrix.TARGETS[route])).hexdigest(),
            result="passed",
            tier="e2e",
            exchange_requests=0,
            coverage=sorted(matrix.M1_STAGES) if row == "M1" else [name],
        )
        if row == "M1":
            body = b"unapproved wallet is not an API wallet of account"
            (directory / f"{name}.log").write_bytes(body)
            value.update(
                mode="mainnet",
                wallet_role="unapproved",
                config_written=False,
                credential_written=False,
                service_enabled=False,
                service_started=False,
                exit_code=1,
                expected_refusal="is not an API wallet of",
                log_sha256=hashlib.sha256(body).hexdigest(),
            )
        else:
            if name == "homebrew-services":
                value.update(mechanism="supervisor-mode", observed_mode="paper")
            body = matrix.M2_LITERALS[name].encode()
            (directory / f"{name}.log").write_bytes(body)
            value.update(
                exit_code=1,
                expected_refusal=matrix.M2_LITERALS[name],
                log_sha256=hashlib.sha256(body).hexdigest(),
            )
        (directory / f"{name}.json").write_text(json.dumps(value))


@pytest.mark.parametrize("row", ["M1", "M2"])
def test_complete_exact_identity_coverage(release: Release, tmp_path: Path, row: str) -> None:
    fixtures(tmp_path, release, row)
    assert set(matrix.native_row(row, release, tmp_path)["coverage"]) == MAINNET_COVERAGE[row]


@pytest.mark.parametrize("row", ["M1", "M2"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "b" * 40),
        ("harness_commit", "b" * 40),
        ("diagnostic", True),
        ("diagnostic", 0),
        ("binary_sha256", "b" * 64),
        ("manifest_sha256", "b" * 64),
        ("result", "skipped"),
        ("exchange_requests", 1),
        ("exchange_requests", False),
        ("coverage", []),
    ],
)
def test_fail_closed_identity_partial_or_exchange(
    release: Release, tmp_path: Path, row: str, field: str, value: Any
) -> None:
    fixtures(tmp_path, release, row)
    path = next((tmp_path / row).glob("*.json"))
    body = json.loads(path.read_bytes())
    body[field] = value
    path.write_text(json.dumps(body))
    with pytest.raises(matrix.MatrixError):
        matrix.native_row(row, release, tmp_path)


@pytest.mark.parametrize("mutation", ["missing-route", "wrong-role", "wrong-mode", "symlink"])
def test_m1_requires_every_real_protected_route(
    release: Release, tmp_path: Path, mutation: str
) -> None:
    fixtures(tmp_path, release, "M1")
    path = tmp_path / "M1/windows-scm.json"
    body = json.loads(path.read_bytes())
    if mutation == "missing-route":
        path.unlink()
    elif mutation == "symlink":
        moved = path.with_suffix(".other")
        path.rename(moved)
        path.symlink_to(moved)
    else:
        body["wallet_role" if mutation == "wrong-role" else "mode"] = "approved"
        path.write_text(json.dumps(body))
    with pytest.raises(matrix.MatrixError):
        matrix.native_row("M1", release, tmp_path)


@pytest.mark.parametrize(
    "mutation", ["generic-error", "changed-log", "success-exit", "missing-case"]
)
def test_m2_does_not_credit_generic_or_missing_refusal(
    release: Release, tmp_path: Path, mutation: str
) -> None:
    fixtures(tmp_path, release, "M2")
    path = tmp_path / "M2/key-file-option.json"
    body = json.loads(path.read_bytes())
    log = path.with_suffix(".log")
    if mutation == "missing-case":
        path.unlink()
    elif mutation == "changed-log":
        log.write_bytes(b"tampered specific literal refusal")
    elif mutation == "generic-error":
        log.write_bytes(b"CLI option not understood")
        body["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        path.write_text(json.dumps(body))
    else:
        body["exit_code"] = 0
        path.write_text(json.dumps(body))
    with pytest.raises(matrix.MatrixError):
        matrix.native_row("M2", release, tmp_path)


@pytest.mark.parametrize(
    "mutation", ["none", "missing-wrapper", "wrong-network", "wrong-testnet-row"]
)
def test_m3_requires_authenticated_vectors_and_both_live_journeys(
    release: Release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    calls: list[str] = []
    digest = hashlib.sha256(release.asset("release-manifest.json")).hexdigest()

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        calls.append(bundle.name)
        if "signing" in bundle.name:
            platform = bundle.name.split(".")[0].split("-")[1]
            value = dict(
                schema=1,
                commit=release.commit,
                manifest_sha256=digest,
                result="passed",
                platform=platform,
                checks=sorted(matrix.SIGNING_CHECKS[platform]),
                networks=["mainnet", "testnet"],
            )
            if mutation == "missing-wrapper":
                value["checks"] = ["hl-protocol.sdk-vectors"]
            if mutation == "wrong-network":
                value["networks"] = ["testnet"]
        else:
            row = bundle.name.split(".")[0]
            value = dict(
                schema=1,
                journey="T1" if mutation == "wrong-testnet-row" else row,
                commit=release.commit,
                manifest_sha256=digest,
                result="passed",
                tier="e2e",
                coverage=["live-orders"],
            )
        return VerifiedPredicate(value, kwargs["workflow"], release.commit)

    monkeypatch.setattr(matrix, "verify_predicate", verify)
    if mutation == "none":
        assert matrix.signing_row(release, tmp_path, tmp_path)["journey"] == "M3"
        assert calls == [
            "signing-linux.sigstore.json",
            "signing-macos.sigstore.json",
            "signing-windows.sigstore.json",
            "T1.sigstore.json",
            "T2.sigstore.json",
        ]
    else:
        with pytest.raises(ValueError):
            matrix.signing_row(release, tmp_path, tmp_path)
