"""Registry behavior fixtures never count as hosted release evidence."""

import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from guard_harness import promotion_channels, promotion_registry
from guard_harness.attestation import AttestationError

ORIGINAL = "sha256:" + "c" * 64


def test_withdrawal_has_no_executable_children_and_binds_signed_identities() -> None:
    body = promotion_registry.sentinel("a" * 64, "b" * 64)
    value = json.loads(body)
    assert value["manifests"] == []
    assert value["annotations"] == {
        "com.zunderlabs.guard.withdrawn.manifest-sha256": "a" * 64,
        "com.zunderlabs.guard.withdrawn.state-sha256": "b" * 64,
    }
    with pytest.raises(AttestationError, match="exact signed"):
        promotion_registry.sentinel("", "b" * 64)


def test_registry_put_cannot_target_a_released_immutable_digest() -> None:
    with pytest.raises(AttestationError, match="not owned"):
        promotion_registry.put_sentinel(
            promotion_registry.sentinel("a" * 64, "b" * 64), reference=ORIGINAL
        )


def test_registry_auth_scope_and_put_only_owned_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = promotion_registry.sentinel("a" * 64, "b" * 64)
    digest = promotion_registry.body_digest(body)
    calls: list[Any] = []

    class Response:
        status = 200
        headers = {"docker-content-digest": digest}

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def read(self, size: int) -> bytes:
            return b'{"token":"fixture-scoped-registry-token"}'

    class Opener:
        def open(self, request: Any, **kwargs: Any) -> Response:
            calls.append(request)
            response = Response()
            if request.get_method() == "PUT":
                response.status = 201
            return response

    monkeypatch.setenv("GH_TOKEN", "fixture-job-token")
    monkeypatch.setenv("GITHUB_ACTOR", "fixture-actor")
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(promotion_channels, "image_digest", lambda reference: digest)
    promotion_registry.put_sentinel(body, reference=digest)
    assert len(calls) == 2
    assert calls[0].full_url == promotion_registry.TOKEN_URL
    assert calls[0].get_header("Authorization").startswith("Basic ")
    assert calls[1].full_url.endswith("/manifests/" + digest)
    assert calls[1].get_method() == "PUT" and calls[1].data == body
    assert calls[1].get_header("Authorization") == "Bearer fixture-scoped-registry-token"


def test_first_latest_preflight_preserves_original_image(monkeypatch: pytest.MonkeyPatch) -> None:
    body = promotion_registry.sentinel("a" * 64, "b" * 64)
    targets: list[str] = []
    monkeypatch.setattr(promotion_channels, "image_digest", lambda reference: ORIGINAL)
    monkeypatch.setattr(
        promotion_registry, "put_sentinel", lambda body, *, reference: targets.append(reference)
    )
    promotion_registry.prepare_sentinel(body, original=ORIGINAL)
    assert targets == [promotion_registry.body_digest(body)]


def test_withdrawal_never_replaces_unrelated_latest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        promotion_channels,
        "image_digest",
        lambda reference: ORIGINAL if reference == ORIGINAL else "sha256:" + "d" * 64,
    )
    mutations: list[str] = []
    monkeypatch.setattr(
        promotion_registry, "put_sentinel", lambda body, *, reference: mutations.append(reference)
    )
    with pytest.raises(AttestationError, match="identities differ"):
        promotion_registry.withdraw_latest(
            original=ORIGINAL,
            body=promotion_registry.sentinel("a" * 64, "b" * 64),
            log=tmp_path / "pull.log",
        )
    assert not mutations


@pytest.mark.parametrize(
    "returncode,output,passes",
    [
        (1, b"no matching manifest for linux/amd64 in the manifest list entries", True),
        (1, b"unauthorized: authentication required", False),
        (0, b"Downloaded newer image", False),
    ],
)
def test_withdrawal_requires_specific_fresh_pull_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, returncode: int, output: bytes, passes: bool
) -> None:
    body = promotion_registry.sentinel("a" * 64, "b" * 64)
    digest = promotion_registry.body_digest(body)
    mutations: list[str] = []
    monkeypatch.setattr(
        promotion_channels,
        "image_digest",
        lambda reference: ORIGINAL if reference == ORIGINAL else digest,
    )
    monkeypatch.setattr(
        promotion_registry, "put_sentinel", lambda body, *, reference: mutations.append(reference)
    )

    def pull(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert argv == [
            "docker",
            "pull",
            "--platform",
            "linux/amd64",
            promotion_channels.IMAGE + ":latest",
        ]
        assert "GH_TOKEN" not in kwargs["env"]
        return subprocess.CompletedProcess(argv, returncode, stdout=output, stderr=b"")

    monkeypatch.setattr(subprocess, "run", pull)
    if passes:
        promotion_registry.withdraw_latest(original=ORIGINAL, body=body, log=tmp_path / "pull.log")
    else:
        with pytest.raises(AttestationError, match="expected platform refusal"):
            promotion_registry.withdraw_latest(
                original=ORIGINAL, body=body, log=tmp_path / "pull.log"
            )
    assert mutations == ["latest"]
