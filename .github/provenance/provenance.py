#!/usr/bin/env python3
"""Provenance check for the public Zunder Guard repository.

Every commit in this repository is written by one export tool from a private source tree. This
script checks that, and that the tree holds no identifier from the private side:

  provenance.py commits [--repo DIR] [--rev REV]   every commit reachable from REV (default HEAD)
                                                  carries the export identity and valid trailers
  provenance.py tree [--root DIR] [--hashes FILE]  no file name or content matches a structural
                                                  private pattern or a hashed private identifier
  provenance.py all [--repo DIR]                   both (the default for CI)

The private identifiers are stored only as salted SHA-256 hashes of their normalised form
(identifiers.json next to this script), so the check reveals nothing beyond what a guess could
confirm. A finding is reported as file, line and category; the matched text is never printed.

CI needs the full history (`fetch-depth: 0`). Standard library only, Python 3.11 or newer.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

EXPORT_NAME = "Zunder Labs"
EXPORT_EMAIL = "export@zunderlabs.com"
TRAILER_KEYS = ("Zunder-Source", "Zunder-Export-Tree", "Zunder-Export-Manifest")
HASH_SALT = "zunder-guard-provenance-v1:"
HASHES_FILE = Path(__file__).resolve().parent / "identifiers.json"
# Identifiers of up to this many words are matched as phrases.
MAX_PHRASE_WORDS = 3

SUBJECT = re.compile(r"^Export (?P<short>[0-9a-f]{7,40}): \S.*$")
OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]*")

# Shapes that are private wherever they appear. Written so that this file does not match them.
STRUCTURAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("an AWS ARN with an account id", re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:")),
    ("a KMS key ARN", re.compile(r"arn:aws[a-z-]*:kms:")),
    ("an EC2 instance id", re.compile(r"\bi-(?:[0-9a-f]{17}|[0-9a-f]{8})\b")),
    ("a Cloudflare Pages project host", re.compile(r"\b[a-z0-9-]+\.pages\.dev\b", re.I)),
    # GitHub's runner accounts and documentation placeholders are not anyone's home.
    ("a macOS home directory",
     re.compile(r"/Users/(?!(?:runner|runneradmin|Shared|you|user|username|example)\b)[A-Za-z0-9._-]+")),
]
# A parameter-store path of the private side; allowed prefixes come from identifiers.json.
PARAMETER_PATH = re.compile(r"(?<![\w.~/-])/zunder[/][\w./-]*")


@dataclass(frozen=True)
class Finding:
    where: str
    what: str

    def __str__(self) -> str:
        return f"{self.where}: {self.what}"


@dataclass
class Identifiers:
    """The public form of the private identifier list: hashes, categories, allowed prefixes."""

    hashes: dict[str, str] = field(default_factory=dict)
    allowed_parameter_prefixes: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> Identifiers:
        data = json.loads(path.read_text())
        if data.get("version") != 1 or data.get("salt") != HASH_SALT:
            raise ValueError(f"{path}: unknown identifier file format")
        hashes = {str(k): str(v) for k, v in data["hashes"].items()}
        bad = [h for h in hashes if not SHA256_HEX.match(h)]
        if bad:
            raise ValueError(f"{path}: {len(bad)} entries are not SHA-256 hex digests")
        prefixes = tuple(str(p) for p in data.get("allowed_parameter_prefixes", []))
        return cls(hashes=hashes, allowed_parameter_prefixes=prefixes)


# ---------------------------------------------------------------- normalisation and hashing


def normalise(text: str) -> list[str]:
    """Lower-case words of letters, digits, dots, hyphens and underscores; `_` reads as `-`."""
    return [_clean(t) for t in TOKEN.findall(text.lower()) if _clean(t)]


def _clean(token: str) -> str:
    return token.replace("_", "-").strip(".-")


def identifier_digest(identifier: str) -> str:
    """The hash an identifier is stored under (what the private side writes)."""
    return digest(" ".join(normalise(identifier)))


@functools.lru_cache(maxsize=None)
def digest(normalised: str) -> str:
    return hashlib.sha256((HASH_SALT + normalised).encode()).hexdigest()


def token_variants(token: str) -> set[str]:
    """A word, each dot suffix (so a subdomain matches its host), each dot-separated part and
    each hyphen-separated piece of a part (so `name-notes.txt` matches `name`)."""
    parts = [p for p in token.split(".") if p]
    variants = {token, *parts}
    variants.update(".".join(parts[i:]) for i in range(1, len(parts)))
    for part in parts:
        variants.update(piece for piece in part.split("-") if piece)
    return variants


@dataclass(frozen=True)
class Located:
    text: str
    line: int


def candidates(text: str) -> Iterator[Located]:
    """Every string an identifier could be: word variants and phrases of up to three words."""
    words: list[Located] = []
    line, cursor = 1, 0
    lowered = text.lower()
    for match in TOKEN.finditer(lowered):
        line += lowered.count("\n", cursor, match.start())
        cursor = match.start()
        cleaned = _clean(match.group())
        if cleaned:
            words.append(Located(cleaned, line))
    for index, word in enumerate(words):
        for variant in token_variants(word.text):
            yield Located(variant, word.line)
        for size in range(2, MAX_PHRASE_WORDS + 1):
            window = words[index:index + size]
            if len(window) == size:
                yield Located(" ".join(w.text for w in window), word.line)


# ---------------------------------------------------------------- tree scan


def scan_text(text: str, where: str, identifiers: Identifiers) -> list[Finding]:
    findings: list[Finding] = []
    for label, pattern in STRUCTURAL_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(Finding(f"{where}:{_line_of(text, match.start())}", label))
    for match in PARAMETER_PATH.finditer(text):
        if not any(match.group().startswith(p) for p in identifiers.allowed_parameter_prefixes):
            findings.append(Finding(f"{where}:{_line_of(text, match.start())}", "a private parameter-store path"))
    seen: set[tuple[int, str]] = set()
    for candidate in candidates(text):
        category = identifiers.hashes.get(digest(candidate.text))
        if category and (candidate.line, category) not in seen:
            seen.add((candidate.line, category))
            findings.append(Finding(f"{where}:{candidate.line}", f"a private identifier ({category})"))
    return findings


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def tree_files(root: Path) -> Iterator[tuple[str, Path]]:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] == ".git" or not path.is_file():
            continue
        yield relative.as_posix(), path


def scan_tree(root: Path, identifiers: Identifiers) -> list[Finding]:
    """Scan every file name and every text file under root (binary files are only named)."""
    findings: list[Finding] = []
    for relative, path in tree_files(root):
        findings += scan_text(relative, f"{relative} (file name)", identifiers)
        raw = path.read_bytes()
        if b"\0" in raw:
            continue
        findings += scan_text(raw.decode(errors="replace"), relative, identifiers)
    return findings


# ---------------------------------------------------------------- commits


@dataclass(frozen=True)
class Commit:
    sha: str
    author: str
    committer: str
    parents: tuple[str, ...]
    tree: str
    message: str


def parse_trailers(message: str) -> dict[str, list[str]] | None:
    """The trailer block (last paragraph) as key -> values, or None if a line is not a trailer."""
    paragraphs = message.strip("\n").split("\n\n")
    if len(paragraphs) < 2:
        return None
    trailers: dict[str, list[str]] = {}
    for line in paragraphs[-1].splitlines():
        key, sep, value = line.partition(": ")
        if not sep or not re.fullmatch(r"[A-Za-z][A-Za-z-]*", key):
            return None
        trailers.setdefault(key, []).append(value.strip())
    return trailers


def check_commit(commit: Commit) -> list[str]:
    """Why this commit was not written by the export, or nothing."""
    problems: list[str] = []
    identity = f"{EXPORT_NAME} <{EXPORT_EMAIL}>"
    if commit.author != identity:
        problems.append(f"author is {commit.author!r}, not {identity!r}")
    if commit.committer != identity:
        problems.append(f"committer is {commit.committer!r}, not {identity!r}")
    if len(commit.parents) > 1:
        problems.append("a merge commit")
    paragraphs = commit.message.strip("\n").split("\n\n")
    subject = SUBJECT.match(paragraphs[0])
    if subject is None or "\n" in paragraphs[0]:
        problems.append("the subject is not 'Export <short sha>: <subject>'")
    if len(paragraphs) != 2:
        problems.append("the message is not one subject line and one trailer block")
    trailers = parse_trailers(commit.message)
    if trailers is None or list(trailers) != list(TRAILER_KEYS) or any(len(v) != 1 for v in trailers.values()):
        problems.append("the trailers are not exactly " + ", ".join(TRAILER_KEYS) + " in this order")
        return problems
    source, tree, manifest = (trailers[k][0] for k in TRAILER_KEYS)
    if not OBJECT_ID.match(source):
        problems.append("Zunder-Source is not a full commit id")
    elif subject is not None and not source.startswith(subject.group("short")):
        problems.append("the subject's short sha is not Zunder-Source's")
    if tree != commit.tree:
        problems.append(f"Zunder-Export-Tree {tree} is not the commit's tree {commit.tree}")
    if not SHA256_HEX.match(manifest):
        problems.append("Zunder-Export-Manifest is not a SHA-256 hex digest")
    return problems


def read_commits(repo: Path, rev: str, limit: int | None = None) -> list[Commit]:
    fields = "%H%x00%an <%ae>%x00%cn <%ce>%x00%P%x00%T%x00%B%x00%x01"
    args = ["git", "-c", "log.showSignature=false", "log", f"--format={fields}"]
    if limit is not None:
        args.append(f"--max-count={limit}")
    out = subprocess.run([*args, rev, "--"], cwd=repo, check=True, capture_output=True, text=True).stdout
    commits = []
    for record in out.split("\x00\x01"):
        record = record.lstrip("\n")
        if not record:
            continue
        sha, author, committer, parents, tree, message = record.split("\x00")[:6]
        commits.append(Commit(sha, author, committer, tuple(parents.split()), tree, message))
    return commits


def check_history(repo: Path, rev: str) -> list[Finding]:
    shallow = subprocess.run(["git", "rev-parse", "--is-shallow-repository"], cwd=repo, check=True,
                             capture_output=True, text=True).stdout.strip()
    findings = []
    if shallow == "true":
        findings.append(Finding("repository", "a shallow clone: check out with fetch-depth 0"))
    for commit in read_commits(repo, rev):
        findings += [Finding(f"commit {commit.sha[:12]}", p) for p in check_commit(commit)]
    return findings


# ---------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("commits", "tree", "all"), nargs="?", default="all")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="the repository (commits, all)")
    parser.add_argument("--rev", default="HEAD", help="the commit whose history is checked")
    parser.add_argument("--root", type=Path, help="the tree to scan (default: --repo)")
    parser.add_argument("--hashes", type=Path, default=HASHES_FILE, help="the hashed identifier list")
    args = parser.parse_args(argv)
    findings: list[Finding] = []
    if args.command in ("commits", "all"):
        findings += check_history(args.repo, args.rev)
    if args.command in ("tree", "all"):
        findings += scan_tree(args.root or args.repo, Identifiers.load(args.hashes))
    for finding in findings:
        print(finding)
    print(f"provenance: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
