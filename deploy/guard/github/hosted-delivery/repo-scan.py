"""Public rescan: exact existing export scan policy, encoded to avoid self-matching.
No exporter allow-list changes. Generated policy is compared against its private source
by the focused test before source integration. Diagnostics never disclose payload text.
"""
import base64,json,re
from pathlib import Path
POLICY = json.loads(base64.b64decode('eyJTRUNSRVRfUEFUVEVSTlMiOltbInByaXZhdGUga2V5IGJsb2NrIiwiLS0tLS1CRUdJTiBbQS1aMC05IF0qUFJJVkFURSBLRVktLS0tLSIsMzJdLFsiQVdTIGFjY2VzcyBrZXkgaWQiLCJcXGIoQUtJQXxBU0lBKVswLTlBLVpdezE2fVxcYiIsMzJdLFsiQVdTIHNlY3JldCBrZXkgbmFtZSIsImF3c19zZWNyZXRfYWNjZXNzX2tleSIsMzRdLFsiQVdTIGFjY291bnQgQVJOIiwiYXJuOmF3czpbYS16MC05LV0rOlthLXowLTktXSo6XFxkezEyfToiLDMyXSxbIkVDMiBpbnN0YW5jZSBpZCIsIlxcYmktMFswLTlhLWZdezE2fVxcYiIsMzJdLFsiR2l0SHViIHRva2VuIiwiXFxiKGdocHxnaG98Z2hzfGdodXxnaXRodWJfcGF0KV9bQS1aYS16MC05X117MjAsfSIsMzJdLFsiU2xhY2sgdG9rZW4iLCJcXGJ4b3hbYWJwcnNdLVtBLVphLXowLTktXXsxMCx9IiwzMl0sWyJhIGtleSBhc3NpZ25lZCBpbiBhbiBlbnYgZmlsZSIsIl5cXHMqKGV4cG9ydFxccyspP1tBLVowLTlfXSooS0VZfFNFQ1JFVHxUT0tFTilbQS1aMC05X10qPVxcU3sxNix9Iiw0MF0sWyJhIGhvbWUgZGlyZWN0b3J5IG9uIEpvbmFzJ3MgbWFjaGluZSIsIi9Vc2Vycy9qb25hc2dyb3NjaCIsMzJdLFsiYSBwZXJzb25hbCBlLW1haWwgYWRkcmVzcyIsImpvbmFzXFwuZ3Jvc2NoQHxAY29ueGFpXFwuY29tIiwzNF0sWyJ0aGUgYnVpbGQgYm94IGFuZCBBV1MgcHJvZmlsZSIsIlxcYnp1bmRlcl9hd3NcXGJ8XFxic2FuZGJveC1hZG1cXGJ8enVuZGVyLWJ1aWxkYm94IiwzMl0sWyJ0aGUgdGVzdG5ldCBydW5uZXIncyBob3N0IiwienVuZGVyLWV4ZWMtdGVzdG5ldCIsMzJdLFsiYSBsZWZ0b3ZlciBwcml2YXRlLXNlY3Rpb24gbWFya2VyIiwiZXhwb3J0OnByaXZhdGU6KHN0YXJ0fGVuZCkiLDMyXV0sIkRFVkVMT1BNRU5UX1BBVFRFUk5TIjpbWyJhIENsYXVkZSByZWZlcmVuY2UiLCJjbGF1ZGV8YW50aHJvcGljIiwzNF0sWyJkZXZlbG9wbWVudC1hc3Npc3RhbnQgaW5zdHJ1Y3Rpb25zIiwiXFxiQUdFTlRTKD86XFwub3ZlcnJpZGUpP1xcLm1kXFxifFxcYlNLSUxMXFwubWRcXGJ8XFxic3ViYWdlbnRcXGJ8XFxibWFpbiBzZXNzaW9uXFxiIiwzNF0sWyJkZXZlbG9wbWVudC1hc3Npc3RhbnQgYXR0cmlidXRpb24iLCJcXGJjb2RleFxcYnwoPzpjby1hdXRob3JlZC1ieXxnZW5lcmF0ZWRbLSBdYnl8d3JpdHRlblstIF1ieSlbXlxcbl0qKD86b3BlbmFpfFxcYkFJXFxifFxcYkxMTVxcYikiLDM0XSxbInByaXZhdGUgYnVpbGQgd3JhcHBlciIsImRlcGxveS8oPzpidWlsZGJveHxsYXRlbmN5LXRva3lvKSg/Oi98YCl8cmVwb3J0cy9sYXRlbmN5LXRva3lvL3x3ZWIvbGl2ZS8iLDMyXSxbInByaXZhdGUgZGV2ZWxvcG1lbnQgZG9jdW1lbnQiLCJkb2NzLyg/OmRlY2lzaW9uc3xndWFyZC1mbG93cy1zcGVjfGd1YXJkLWpvdXJuYWwtc3BlY3xndWFyZC1tYWlubmV0LXBpbG90fGFnZW50LXBsYXlib29rfHJpc2stcmV2aWV3fHRlc3RuZXR8cm9hZG1hcClcXC5tZCIsMzJdXSwiV0FSTl9QQVRURVJOUyI6W1siYW4gaW50ZXJuYWwgZG9jdW1lbnQiLCJkb2NzLyhkZWNpc2lvbnN8cm9hZG1hcHx0ZXN0bmV0fGRlcGxveXxidWlsZGJveHxhcmNoaXRlY3R1cmV8cGFwZXJ8c3RyYXRlZ3ktcmVzZWFyY2h8cmlzay1yZXZpZXd8bGF1bmNoLXJlYWRpbmVzc3xmb3VuZGluZy1wbGFuKVxcLm1kfHJlc2VhcmNoL3xDTEFVREVcXC5tZCIsMzJdLFsiSm9uYXMiLCJcXGJKb25hc1xcYiIsMzJdLFsiYSBwcml2YXRlIGNyYXRlIGJ5IG5hbWUiLCJ6dW5kZXItKHN0cmF0ZWdpZXN8ZW5naW5lfHJ1bm5lcnxzaW18cGFwZXJ8cmVzZWFyY2h8Y2xpfHJlY29yZGVyfG5ld3N8cmVnaW1lfGdvc3NpcHxsZWRnZXJ8dGlja3xoZWFsdGh8bGlnaHRlcnxleGVjfGh5cGVybGlxdWlkfGRhdGEpXFxifHp1bmRlcl8oc3RyYXRlZ2llc3xlbmdpbmV8cnVubmVyfHNpbXxwYXBlcnxyZXNlYXJjaHxleGVjfGh5cGVybGlxdWlkfGRhdGEpXFxiIiwzMl0sWyJhIHN0cmF0ZWd5IGJ5IG5hbWUiLCJjaGFubmVsLXRyZW5kfGRvbmNoaWFuIiwzNF0sWyJ0aGUgdHJhZGluZyBzbGVldmUiLCJFVVIgMiwwMDAiLDMyXSxbImEgaG9zdCBwYXRoIG9mIFp1bmRlcidzIG93biIsIi92YXIvbGliL3p1bmRlci98L2V0Yy96dW5kZXItbWFpbm5ldCIsMzJdLFsiQVdTIFNTTSIsIlxcYlNTTVxcYnxhd3Mgc3NtIiwzMl1dLCJQVUJMSUNfSEVYIjpbIjAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjMiLCIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIl0sIlBVQkxJQ19GSUxFX0hFWCI6eyJjcmF0ZXMvenVuZGVyLWd1YXJkL3Rlc3RzL2pvdXJuYWwucnMiOlsiMDIyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMyJdfSwiUFVCTElDX0NSQVRFUyI6WyJ6dW5kZXItY29yZSIsInp1bmRlci1ndWFyZCIsInp1bmRlci1ndWFyZC1jb3JlIiwienVuZGVyLWd1YXJkLW1jcCIsInp1bmRlci1ndWFyZC1ydWxlcyIsInp1bmRlci1yZWR0ZWFtIiwienVuZGVyLXJpc2siLCJ6dW5kZXItdmVudWUiXX0='))
for name in ['SECRET_PATTERNS','DEVELOPMENT_PATTERNS','WARN_PATTERNS']:
    globals()[name] = [(label,re.compile(pattern,flags)) for label,pattern,flags in POLICY[name]]
PUBLIC_HEX=set(POLICY['PUBLIC_HEX'])
PUBLIC_FILE_HEX={k:set(v) for k,v in POLICY['PUBLIC_FILE_HEX'].items()}
PUBLIC_CRATES=set(POLICY['PUBLIC_CRATES'])
HEX64=re.compile(r'(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])')
nearby_pattern=re.compile(r'key|secret|priv|seed|mnemonic|wallet',re.I)

def scan(root: Path, accepted: set[str] = frozenset()) -> tuple[list[str], list[dict]]:
    findings, warnings = [], []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts):
        rel = path.relative_to(root).as_posix()
        if rel == "THIRD_PARTY_LICENSES.md":
            continue  # third-party texts, generated
        name = path.name
        development_names = {("age" + "nts.md"), ("age" + "nts.override.md"), ("ski" + "ll.md"), ("clau" + "de.md"), ("clau" + "de.local.md")}
        if name.lower() in development_names or any(part.lower() in {(".clau" + "de"), (".co" + "dex"), ".agents"} for part in path.relative_to(root).parts):
            findings.append(f"{rel}: development-assistant file")
        if name == ".env" or name.startswith(".env.") or name.endswith((".pem", ".key")):
            findings.append(f"{rel}: a secret's file name")
        raw = path.read_bytes()
        if b"\0" in raw:
            findings.append(f"{rel}: a binary file (the public tree is text only)")
            continue
        text = raw.decode(errors="replace")
        for label, rx in SECRET_PATTERNS + DEVELOPMENT_PATTERNS:
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append(f"{rel}:{line}: {label}")
        for number, line in enumerate(text.splitlines(), 1):
            if nearby_pattern.search(line):
                for m in HEX64.finditer(line):
                    if m.group(1).lower() not in PUBLIC_HEX | PUBLIC_FILE_HEX.get(rel, set()):
                        findings.append(f"{rel}:{number}: a 64-hex value next to the word key/secret/wallet")
            for label, rx in WARN_PATTERNS:
                if rx.search(line):
                    warnings.append({"file": rel, "line": number, "kind": label})
        if rel in {"Cargo.toml", "Cargo.lock"}:
            for m in re.finditer(r'(?m)^name = "(zunder-[a-z-]+)"|^(zunder-[a-z-]+)\s*=', text):
                if (m.group(1) or m.group(2)) not in PUBLIC_CRATES | accepted:
                    findings.append(f"{rel}: names the private crate {m.group(1) or m.group(2)}")
    return findings, warnings

