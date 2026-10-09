"""Offline coverage contract shared by release orchestration and publication review.

This module does not authenticate signatures, run adapters, access keys, or publish.
An independent verifier supplies authenticated payload bytes and producer identity.
A report is a coverage decision, never publication authority or a signed attestation.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import re


class Refused(ValueError):
    pass


def need(value, message):
    if not value:
        raise Refused(message)


def exact(value, fields):
    need(type(value) is dict and set(value) == set(fields), "Unexpected contract fields")


def digest(value, width=64):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % width, value), "Malformed immutable digest")
    return value


def decode(raw, maximum=65536):
    need(type(maximum) is int and 0 < maximum <= 1048576, "Bounded parser policy required")
    need(type(raw) is bytes and 0 < len(raw) <= maximum, "Evidence must be bounded bytes")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "Duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused("Unreadable evidence") from error


@dataclass(frozen=True)
class Binding:
    tag: str
    product_source: str
    manifest_sha256: str
    website_source: str
    staging_deployment_sha256: str
    production_deployment_sha256: str

    def __post_init__(self):
        need(type(self.tag) is str and re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", self.tag)
             and len(self.tag) <= 40, "Explicit stable tag required")
        digest(self.product_source, 40)
        digest(self.website_source, 40)
        for name in ("manifest_sha256", "staging_deployment_sha256", "production_deployment_sha256"):
            digest(getattr(self, name))

    def public(self):
        return dict(self.__dict__)


# Each producer must independently observe these facts. One check cannot stand in
# for another; restarted processes and booted kernels are deliberately separate.
OBSERVATIONS = {
    "source-ci": ("pr", "none", ("fmt", "clippy", "workspace-tests", "dependency-policy", "web-contracts")),
    "signed-artifacts": ("candidate", "none", ("all-subjects", "sigstore", "slsa-source", "oci-digest", "installed-bytes")),
    "staging-boundary": ("candidate", "testnet", ("same-website-source", "mainnet-signing-refused", "mainnet-backend-refused", "isolated-stores")),
    "owner-approvals": ("candidate", "testnet", ("funded-owner", "browser-signature", "accepted-agent", "agent-readback", "accepted-builder", "builder-readback", "revoke-readback")),
    "wallet-extension": ("candidate", "testnet", ("actual-extension", "connection", "confirmation", "user-rejection")),
    "staging-checkout": ("candidate", "testnet", ("actual-payment", "quote-bound-payment", "disposable-issuer", "independent-licence-verifier", "email-delivery", "order-recovery")),
    "official-activation": ("candidate", "paper", ("genuine-entitlement", "official-trust-anchor", "owner-binding", "activation", "restart-persistence")),
    "guard-mcp": ("candidate", "testnet", ("risk-approved-order", "venue-fill", "venue-stop", "owned-close", "complete-inventory-flat", "halt-persists")),
    "native-linux-amd64": ("candidate", "testnet", ("protected-key-store", "signed-install", "service-restart", "kernel-reboot", "state-persistence")),
    "native-linux-arm64": ("candidate", "testnet", ("protected-key-store", "signed-install", "service-restart", "kernel-reboot", "state-persistence")),
    "native-macos-arm64": ("candidate", "testnet", ("keychain", "signed-install", "service-restart", "kernel-reboot", "state-persistence")),
    "native-windows-amd64": ("candidate", "testnet", ("dpapi-acl", "signed-install", "service-restart", "kernel-reboot", "state-persistence")),
    "native-container": ("candidate", "testnet", ("protected-key-store", "signed-image", "service-restart", "kernel-reboot", "state-persistence")),
    "cleanup": ("candidate", "testnet", ("no-uncertain-writes", "approvals-restored", "owned-processes-gone", "owned-orders-gone", "complete-inventory-flat", "runner-restored", "owned-resources-removed")),
    "production-smoke": ("postpublication", "paper", ("canonical-downloads", "anonymous-image", "same-signed-bytes", "production-config", "paper-request", "no-mainnet-write")),
}


def plan(binding):
    need(type(binding) is Binding, "Validated binding required")
    return {"schema": 1, "kind": "release-test-plan", "binding": binding.public(),
            "release_ready": False, "publication_authorized": False,
            "checks": [{"id": name, "phase": phase, "network": network,
                        "observations": list(observations), "state": "requested"}
                       for name, (phase, network, observations) in OBSERVATIONS.items()]}


@dataclass(frozen=True)
class Producer:
    repository: str
    workflow: str
    control_source: str

    def __post_init__(self):
        need(self.repository == "zunderlabs/zunder-guard", "Canonical evidence repository required")
        need(type(self.workflow) is str and re.fullmatch(r"\.github/workflows/[a-z0-9-]+\.yml", self.workflow), "Exact workflow required")
        digest(self.control_source, 40)


@dataclass(frozen=True)
class Authenticated:
    """Return type of the independent signature/attestation verifier adapter.

    The adapter must derive identity from verified signer claims, bind raw payload
    bytes, require canonical repository IDs and protected execution, and reject an
    unexpected attempt. Never construct this from payload self-reported fields.
    """
    payload: bytes
    producer: Producer
    run_id: int
    attempt: int

    def __post_init__(self):
        need(type(self.payload) is bytes and 0 < len(self.payload) <= 65536, "Bounded authenticated payload required")
        need(type(self.producer) is Producer, "Authenticated producer required")
        need(type(self.run_id) is int and self.run_id > 0 and type(self.attempt) is int and self.attempt > 0, "Authenticated run required")


PAYLOAD_FIELDS = ("schema", "kind", "check", "binding", "network", "status", "started_ms", "finished_ms", "observations", "cleanup_complete", "uncertain_writes")


def evaluate(binding, phase, artifacts, expected_producers, verify, now_ms, max_age_ms=86400000):
    """Collect authenticated checks for exactly one phase; missing proof blocks.

    artifacts: {check_id: opaque attestation carrier}; verify(carrier) -> Authenticated
    expected_producers: independently reviewed literal identity per required check.
    max_age_ms is bounded; current time comes from the trusted controller.
    """
    need(type(binding) is Binding and phase in ("pr", "candidate", "postpublication"), "Validated phase binding required")
    need(type(artifacts) is dict and type(expected_producers) is dict and callable(verify), "Verifier integration required")
    need(type(now_ms) is int and now_ms > 0 and type(max_age_ms) is int and 0 < max_age_ms <= 86400000, "Bounded trusted clock required")
    required = {name for name, spec in OBSERVATIONS.items() if spec[0] == phase}
    need(set(artifacts) <= required and set(expected_producers) == required, "Exact check/producer policy required")
    for producer in expected_producers.values():
        need(type(producer) is Producer, "Reviewed producer policy required")
    report = {"schema": 1, "kind": "release-test-coverage", "phase": phase,
              "binding": binding.public(), "coverage_complete": False,
              "release_ready": False, "publication_authorized": False, "checks": []}
    for name in OBSERVATIONS:
        if name not in required:
            continue
        entry = {"id": name, "state": "missing"}
        if name in artifacts:
            try:
                authenticated = verify(artifacts[name])
                need(type(authenticated) is Authenticated, "Independent authentication failed")
                need(authenticated.producer == expected_producers[name], "Unexpected authenticated producer")
                value = decode(authenticated.payload)
                exact(value, PAYLOAD_FIELDS)
                need(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == "actual-release-check", "Actual observation schema required")
                need(value["check"] == name and value["binding"] == binding.public(), "Immutable subject binding differs")
                _, network, observations = OBSERVATIONS[name]
                need(value["network"] == network, "Network differs")
                need(value["status"] in ("passed", "failed", "unknown"), "Actual status required")
                start, finish = value["started_ms"], value["finished_ms"]
                need(type(start) is int and type(finish) is int and now_ms - max_age_ms <= start <= finish <= now_ms, "Stale or future evidence")
                exact(value["observations"], observations)
                need(all(type(v) is bool for v in value["observations"].values()), "Boolean observations required")
                need(type(value["cleanup_complete"]) is bool and type(value["uncertain_writes"]) is int and value["uncertain_writes"] >= 0, "Cleanup outcome required")
                passed = (value["status"] == "passed" and all(value["observations"].values())
                          and value["cleanup_complete"] and value["uncertain_writes"] == 0)
                entry.update(state="passed" if passed else "blocked", evidence_sha256=sha256(authenticated.payload).hexdigest(),
                             run_id=authenticated.run_id, attempt=authenticated.attempt)
            except Exception:
                # Attestation errors may contain credentials/payloads. Never emit them.
                entry["state"] = "unverified"
        report["checks"].append(entry)
    report["coverage_complete"] = all(entry["state"] == "passed" for entry in report["checks"])
    return report
