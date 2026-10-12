import hashlib
import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from guard_harness import channel_head
from guard_harness.attestation import AttestationError


@pytest.mark.parametrize(
    "outcome",
    [
        "prelaunch",
        "stable",
        "missing-repository",
        "private-repository",
        "rate-limited",
        "redirect",
        "wrong-url",
        "malformed",
        "oversize",
        "prerelease",
        "wrong-tag",
        "missing-date",
    ],
)
def test_independent_public_launch_signal_distinguishes_positive_absence_from_unknown(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    api = "https://api.github.com/repos/zunderlabs/zunder-guard"
    seen: list[str] = []

    class Response(io.BytesIO):
        status = 200

        def __init__(self, body: bytes, url: str) -> None:
            super().__init__(body)
            self.url = url

        def geturl(self) -> str:
            return self.url

    class Opener:
        def open(self, request: Any, *, timeout: int) -> Response:
            assert timeout == 30 and request.get_method() == "GET"
            assert "Authorization" not in request.headers
            seen.append(request.full_url)
            if request.full_url == api:
                if outcome == "missing-repository":
                    raise urllib.error.HTTPError(api, 404, "fixture", Message(), None)
                return Response(
                    json.dumps(
                        {
                            "full_name": "zunderlabs/zunder-guard",
                            "private": outcome == "private-repository",
                        }
                    ).encode(),
                    api,
                )
            assert request.full_url == api + "/releases/latest"
            if outcome in {"prelaunch", "rate-limited", "redirect"}:
                raise urllib.error.HTTPError(
                    request.full_url,
                    {"prelaunch": 404, "rate-limited": 403, "redirect": 302}[outcome],
                    "fixture",
                    Message(),
                    None,
                )
            value = dict(
                tag_name="v1.0.0",
                draft=False,
                prerelease=False,
                published_at="2026-10-12T00:00:00Z",
                html_url="https://github.com/zunderlabs/zunder-guard/releases/tag/v1.0.0",
            )
            if outcome == "prerelease":
                value["prerelease"] = True
            elif outcome == "wrong-tag":
                value["tag_name"] = "v1.0.0-rc.7"
            elif outcome == "missing-date":
                value["published_at"] = ""
            body = (
                b"not JSON private-output-needle"
                if outcome == "malformed"
                else b"x" * (2 * 1024 * 1024 + 1)
                if outcome == "oversize"
                else json.dumps(value).encode()
            )
            return Response(
                body, "https://example.com/redirect" if outcome == "wrong-url" else request.full_url
            )

    monkeypatch.setattr(
        "guard_harness.channel_head.urllib.request.build_opener", lambda handler: Opener()
    )
    if outcome == "prelaunch":
        assert channel_head.published_stable() is None
        assert seen == [api, api + "/releases/latest"]
    elif outcome == "stable":
        assert channel_head.published_stable() == "v1.0.0"
    else:
        with pytest.raises(AttestationError) as error:
            channel_head.published_stable()
        assert "private-output-needle" not in str(error.value)


@pytest.mark.parametrize(
    "outcome", ["present", "absent", "redirect", "forbidden", "bad-digest", "oversize"]
)
def test_channel_read_distinguishes_absent_from_unknown(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    body = b'{"manifest_sha256":"' + b"a" * 64 + b'"}'

    class Response(io.BytesIO):
        status = 200
        headers = {"x-zunder-state-sha256": hashlib.sha256(body).hexdigest()}

    class Opener:
        def open(self, request: Any, *, timeout: int) -> Response:
            assert request.full_url == "https://zunderlabs.com/guard/release-staging.json"
            assert request.headers == {"User-agent": "zunder-guard-release/1.0"}
            assert timeout == 30
            if outcome in {"absent", "redirect", "forbidden"}:
                code = {"absent": 404, "redirect": 302, "forbidden": 403}[outcome]
                raise urllib.error.HTTPError(request.full_url, code, "fixture", Message(), None)
            response = Response(body if outcome != "oversize" else b"x" * 65537)
            if outcome == "bad-digest":
                response.headers = {"x-zunder-state-sha256": "b" * 64}
            return response

    monkeypatch.setattr(
        "guard_harness.channel_head.urllib.request.build_opener", lambda handler: Opener()
    )
    if outcome == "present":
        assert channel_head.read("staging") == (
            hashlib.sha256(body).hexdigest(),
            {"manifest_sha256": "a" * 64},
        )
    elif outcome == "absent":
        assert channel_head.read("staging") == (None, None)
    else:
        with pytest.raises(AttestationError):
            channel_head.read("staging")
