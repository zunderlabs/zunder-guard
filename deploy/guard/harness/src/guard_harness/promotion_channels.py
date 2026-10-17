"""Canonical channel mutations with captured identities and non-destructive rollback."""

import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.homebrew_stage import Tap, _sha
from guard_harness.native_release import Release
from guard_harness.promotion_registry import sentinel, withdraw_latest
from guard_harness.publication import USER_AGENT, _NoRedirect
from guard_harness.runner import RunError, run

IMAGE = "ghcr.io/zunderlabs/zunder-guard"
REPOSITORY = "zunderlabs/zunder-guard"


# Rollback re-reads GitHub latest this many times, this far apart, past its ~60 s cache.
LATEST_REREADS = 9
LATEST_REREAD_PAUSE = 10.0


def public_get(url: str, *, headers: dict[str, str] | None = None) -> tuple[bytes, Any] | None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=45) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if response.status != 200 or len(body) > 2 * 1024 * 1024:
                raise AttestationError("public channel snapshot response refused")
            return body, response.headers
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise AttestationError("public channel snapshot failed") from None
    except (OSError, urllib.error.URLError):
        raise AttestationError("public channel snapshot failed") from None


def _not_found(log: Path) -> bool:
    """Whether a failed `gh api` call's retained output is exactly GitHub's 404 answer."""
    try:
        text = log.read_text(encoding="utf-8")
        body, end = json.JSONDecoder().raw_decode(text)
    except (OSError, ValueError):
        return False
    return (
        isinstance(body, dict)
        and body.get("message") == "Not Found"
        and body.get("status") == "404"
        and text[end:] == "gh: Not Found (HTTP 404)\n"
    )


def image_snapshot(tag: str) -> tuple[str, bytes] | None:
    if tag != "latest" and not re.fullmatch(r"sha256:[0-9a-f]{64}", tag):
        raise AttestationError("OCI snapshot target refused")
    token_response = public_get(
        "https://ghcr.io/token?service=ghcr.io&scope=repository:zunderlabs/zunder-guard:pull"
    )
    if token_response is None:
        raise AttestationError("OCI anonymous read admission failed")
    token = json.loads(token_response[0]).get("token")
    if not isinstance(token, str) or not token or any(char.isspace() for char in token):
        raise AttestationError("OCI read credential malformed")
    response = public_get(
        "https://ghcr.io/v2/zunderlabs/zunder-guard/manifests/" + tag,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json",
        },
    )
    if response is None:
        return None
    digest = "sha256:" + hashlib.sha256(response[0]).hexdigest()
    if response[1].get("docker-content-digest") != digest:
        raise AttestationError("OCI digest header differs from captured manifest bytes")
    return digest, response[0]


def image_digest(tag: str) -> str | None:
    captured = image_snapshot(tag)
    return None if captured is None else captured[0]


class Channels:
    def __init__(
        self, release: Release, previous: Release | None, work: Path, tap: Tap | None
    ) -> None:
        self.release, self.previous, self.work, self._tap = release, previous, work, tap
        self.sequence = 0
        self.pause = time.sleep  # Tests replace it.

    @property
    def tap(self) -> Tap:
        if self._tap is None:
            raise AttestationError(
                "tap credential unavailable; other rollback channels remain independent"
            )
        return self._tap

    @tap.setter
    def tap(self, value: Tap) -> None:
        self._tap = value

    def github(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        self.sequence += 1
        argv = ["gh", "api", "--method", method, f"repos/{REPOSITORY}/{endpoint}"]
        if body is not None:
            argv += ["--input", "-"]
        env = {
            name: os.environ[name] for name in ("PATH", "HOME", "GH_TOKEN") if name in os.environ
        }
        result = run(
            argv,
            env=env,
            log=self.work / f"github-{self.sequence}.log",
            timeout=45,
            stdin=json.dumps(body).encode() if body is not None else b"",
            secrets=[env.get("GH_TOKEN", "")],
        )
        return json.loads(result.output)

    def github_latest(self) -> Any | None:
        """GitHub latest through the authenticated API, never the ~60 s public cache.

        gh api exits 1 on any HTTP error. Only GitHub's exact 404 answer (no latest
        release) is None; every other failure stays a failure. A 404 also answers a
        repository the token cannot read, so callers read a positive control first.
        """
        try:
            return self.github("GET", "releases/latest")
        except RunError:
            if _not_found(self.work / f"github-{self.sequence}.log"):
                return None
            raise

    def snapshot(self) -> dict[str, Any]:
        head = self.tap.request("GET", "git/ref/heads/main")
        old = _sha(head["object"]["sha"])
        tree = _sha(self.tap.request("GET", f"git/commits/{old}")["tree"]["sha"])
        latest = image_digest("latest")
        expected = None
        if latest is not None and self.previous is None:
            captured = image_snapshot("latest")
            if captured is None or captured[0] != latest:
                raise AttestationError("OCI latest snapshot raced")
            index = json.loads(captured[1])
            annotations = index.get("annotations", {})
            try:
                empty = sentinel(
                    annotations.get("com.zunderlabs.guard.withdrawn.manifest-sha256", ""),
                    annotations.get("com.zunderlabs.guard.withdrawn.state-sha256", ""),
                )
            except AttestationError:
                empty = b""
            if captured[1] == empty:
                latest = None
        if self.previous:
            build = json.loads(self.previous.asset("release-manifest.json"))
            expected = build["distribution"]["docker"]["digest"]
        if latest != expected:
            raise AttestationError("OCI latest differs from prior authenticated canonical release")
        # The candidate read is the positive control that makes a latest 404 mean "none".
        candidate = self.github("GET", "releases/tags/" + self.release.tag)
        if candidate.get("tag_name") != self.release.tag or candidate.get("draft"):
            raise AttestationError("candidate release is not the staged public release")
        github_latest = self.github_latest()
        if self.previous is None:
            if github_latest is not None:
                raise AttestationError(
                    "GitHub latest exists without a prior promoted canonical release"
                )
        elif (
            github_latest is None
            or github_latest.get("tag_name") != self.previous.tag
            or github_latest.get("draft")
            or github_latest.get("prerelease")
        ):
            raise AttestationError(
                "GitHub latest differs from prior authenticated canonical release"
            )
        return {
            "tap_before": old,
            "tap_tree_before": tree,
            "image_before": latest,
            "github_before": github_latest,
            "candidate_release_id": candidate["id"],
        }

    def tap_tree(self, base: str, formula: bytes) -> str:
        blob = self.tap.request(
            "POST",
            "git/blobs",
            {"encoding": "base64", "content": base64.b64encode(formula).decode("ascii")},
        )
        tree = self.tap.request(
            "POST",
            "git/trees",
            {
                "base_tree": base,
                "tree": [
                    {
                        "path": "Formula/zunder-guard.rb",
                        "mode": "100644",
                        "type": "blob",
                        "sha": _sha(blob["sha"]),
                    }
                ],
            },
        )
        return _sha(tree["sha"])

    def tap_commit(self, parent: str, tree: str, message: str) -> str:
        commit = self.tap.request(
            "POST", "git/commits", {"message": message, "tree": tree, "parents": [parent]}
        )
        target = _sha(commit["sha"])
        result = self.tap.request("PATCH", "git/refs/heads/main", {"sha": target, "force": False})
        if result.get("ref") != "refs/heads/main" or _sha(result["object"]["sha"]) != target:
            raise AttestationError("tap mutation outcome unknown; reconcile its head")
        return target

    def image(self, digest: str) -> None:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise AttestationError("immutable OCI digest required")
        run(
            [
                "docker",
                "buildx",
                "imagetools",
                "create",
                "--tag",
                IMAGE + ":latest",
                IMAGE + "@" + digest,
            ],
            log=self.work / "image-latest.log",
            timeout=180,
        )
        if image_digest("latest") != digest:
            raise AttestationError("OCI latest differs after digest publication")

    def promote(self, snapshot: dict[str, Any]) -> None:
        tree = self.tap_tree(snapshot["tap_tree_before"], self.release.asset("zunder-guard.rb"))
        snapshot["tap_after"] = self.tap_commit(
            snapshot["tap_before"], tree, "Promote zunder-guard " + self.release.tag
        )
        self.save(snapshot)
        build = json.loads(self.release.asset("release-manifest.json"))
        self.image(build["distribution"]["docker"]["digest"])
        self.github(
            "PATCH",
            f"releases/{snapshot['candidate_release_id']}",
            {"draft": False, "prerelease": False, "make_latest": "true"},
        )
        current = self.github("GET", "releases/latest")
        if current.get("tag_name") != self.release.tag or current.get("prerelease"):
            raise AttestationError("GitHub latest promotion readback differs")
        self.save(snapshot)

    def rollback_tap(self, snapshot: dict[str, Any]) -> None:
        if self._tap is None:
            # No tap credential, so no restoration; but a tap this promotion never moved
            # needs none. Its live head, read with the job's token as prepare reads the
            # public tap, must still be exactly the signed pre-mutation head; anything
            # else, a failed read included, stays a tap failure.
            reader = Tap(token=os.environ.get("GH_TOKEN", ""), logs=self.work / "logs/tap-read")
            current = _sha(reader.request("GET", "git/ref/heads/main")["object"]["sha"])
            if current != _sha(snapshot["tap_before"]):
                raise AttestationError("tap moved and its rollback credential is unavailable")
            return
        current = _sha(self.tap.request("GET", "git/ref/heads/main")["object"]["sha"])
        if current == snapshot["tap_before"]:
            return
        commit = self.tap.request("GET", f"git/commits/{current}")
        parents = [item["sha"] for item in commit["parents"]]
        promoted_tree = self.tap_tree(
            snapshot["tap_tree_before"], self.release.asset("zunder-guard.rb")
        )
        already_restored = False
        if commit["tree"]["sha"] == snapshot["tap_tree_before"] and len(parents) == 1:
            parent = self.tap.request("GET", f"git/commits/{parents[0]}")
            already_restored = [item["sha"] for item in parent["parents"]] == [
                snapshot["tap_before"]
            ] and parent["tree"]["sha"] == promoted_tree
        if not already_restored and (
            parents != [snapshot["tap_before"]] or commit["tree"]["sha"] != promoted_tree
        ):
            raise AttestationError("tap head changed outside this promotion")
        if not already_restored:
            self.tap_commit(
                current,
                snapshot["tap_tree_before"],
                "Rollback zunder-guard " + self.release.tag,
            )

    def rollback(self, snapshot: dict[str, Any]) -> list[str]:
        failures: list[str] = []
        try:
            self.rollback_tap(snapshot)
        except Exception:
            failures.append("tap")
        try:
            if snapshot["image_before"] is None:
                if image_digest("latest") is not None:
                    build = json.loads(self.release.asset("release-manifest.json"))
                    withdraw_latest(
                        original=build["distribution"]["docker"]["digest"],
                        body=sentinel(
                            hashlib.sha256(self.release.asset("release-manifest.json")).hexdigest(),
                            hashlib.sha256(
                                (self.work / "promoted.predicate.json").read_bytes()
                            ).hexdigest(),
                        ),
                        log=self.work / "image-withdrawal-pull.log",
                    )
            else:
                build = json.loads(self.release.asset("release-manifest.json"))
                if image_digest("latest") not in {
                    snapshot["image_before"],
                    build["distribution"]["docker"]["digest"],
                }:
                    raise AttestationError("OCI latest changed outside this promotion")
                if image_digest("latest") != snapshot["image_before"]:
                    self.image(snapshot["image_before"])
        except Exception:
            failures.append("image")
        try:
            # Candidate first: the positive control for an authenticated latest 404.
            candidate = self.github("GET", f"releases/{snapshot['candidate_release_id']}")
            if (
                candidate.get("id") != snapshot["candidate_release_id"]
                or candidate.get("tag_name") != self.release.tag
            ):
                raise AttestationError("captured GitHub release identity changed")
            current_latest = self.github_latest()
            latest_id = None if current_latest is None else current_latest.get("id")
            allowed = {
                None if snapshot["github_before"] is None else snapshot["github_before"]["id"],
                snapshot["candidate_release_id"],
            }
            if latest_id not in allowed:
                raise AttestationError("GitHub latest changed outside this promotion")
            if snapshot["github_before"] is not None:
                old = self.github("GET", f"releases/{snapshot['github_before']['id']}")
                if (
                    old.get("id") != snapshot["github_before"]["id"]
                    or old.get("tag_name") != snapshot["github_before"]["tag_name"]
                ):
                    raise AttestationError("prior GitHub release identity changed")
            self.github(
                "PATCH",
                f"releases/{snapshot['candidate_release_id']}",
                {"prerelease": True, "make_latest": "false"},
            )
            if snapshot["github_before"] is not None:
                self.github(
                    "PATCH", f"releases/{snapshot['github_before']['id']}", {"make_latest": "true"}
                )
            # The unauthenticated read can be served from a cache for about a minute after the
            # PATCH; re-read (bounded) until it shows the restored latest, then judge it.
            restored = (
                None if snapshot["github_before"] is None else snapshot["github_before"]["id"]
            )
            for _ in range(LATEST_REREADS):
                observed = public_get(f"https://api.github.com/repos/{REPOSITORY}/releases/latest")
                latest_id = None if observed is None else json.loads(observed[0]).get("id")
                if latest_id == restored:
                    break
                self.pause(LATEST_REREAD_PAUSE)
            if restored is None:
                if latest_id is not None:
                    raise AttestationError("first GitHub latest remains available after withdrawal")
            elif latest_id != restored:
                raise AttestationError("prior GitHub latest was not restored")
        except Exception:
            failures.append("github-latest")
        return failures

    def save(self, value: dict[str, Any]) -> None:
        target = self.work / "channels.json"
        temporary = target.with_suffix(".new")
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
        temporary.replace(target)
