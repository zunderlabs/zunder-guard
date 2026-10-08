#!/usr/bin/env python3
"""Drives the loader and install.sh through a terminal, as a person over `ssh -t` would
(deploy/guard/test/installer.sh runs it). Uses pexpect (ISC licence), a test tool only.

    installer_test.py install-only # offline release fixtures, no Rust binary or services
    installer_test.py container   # in a throwaway container: no systemd, non-root user
    installer_test.py bootstrap   # in a container without cosign: the pinned cosign download
    installer_test.py systemd     # on the Linux build host itself: unit, credentials, clean-up
    installer_test.py docker      # `docker run -it … init --interactive` on the box

Release under test: $REL (a directory holding the fake release), version v0.0.0.
"""
import base64
import hashlib
from pathlib import Path
import shlex
import tarfile
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile



REL = os.environ.get("REL", "/rel")
VERSION = "v0.0.0"
FAKE_COSIGN_DIR = os.environ.get("FAKE_COSIGN_DIR", "/t/bin")
# The default rules (Rules::default().encode(), reconciled schema v1).
RULES = ("zr1_eyJ2IjoxLCJtYXhMZXZlcmFnZSI6NSwibWF4TG9zc0F0U3RvcFBjdCI6Miwic3RvcFBvbGljeSI6ImF0dGFjaCIsImRlZmF1bHRTdG9w"
         "RGlzdGFuY2VQY3QiOjIsIm1pbkxpcURpc3RhbmNlUGN0IjoxMCwibWF4UG9zaXRpb25QY3QiOjIwMCwibWF4T3BlblJpc2tQY3QiOjYsImRhaWx5"
         "TG9zc1N0b3BQY3QiOjYsImRyYXdkb3duSGFsdFBjdCI6MjUsIm1hcmtldHMiOlsiKiJdfQ")
# A fake key: no venue knows it, so the real binary's check with Hyperliquid (`userRole`)
# refuses it. That refusal is what the keyed cases test: nothing is stored, the key never shows.
# The keyed success paths need a real API wallet key and are checked by hand (docs/guard.md).
KEY = "ab" * 32
# Public accounts in standard mode, read-only (their equity starts the paper and testnet risk
# journals): one on mainnet for paper, one on testnet. Nothing is ever sent for them.
PAPER_ACCOUNT = "0x67f7aa8fb95c47e6ea9c517b623e0701cbf9d9ba"
TESTNET_ACCOUNT = "0x5972698398d8c5bbe67c0db74906236691020417"
REFUSED_KEY = "is not an API wallet of"
# The fake key's address, as the venue check names it (filled in by the first refusal).
KEY_ADDRESS = {}
FAILED = []


def ok(name, _detail=""):
    print(f"  ok: {name}", flush=True)


def fail(name, detail=""):
    print(f"  FAIL: {name}\n{detail}", flush=True)
    FAILED.append(name)


def env_for(home, release=None, fake_cosign=True):
    path = os.environ["PATH"]
    if fake_cosign:
        path = f"{FAKE_COSIGN_DIR}:{path}"
    return {
        "PATH": path,
        "HOME": home,
        "TERM": "dumb",
        "ZUNDER_GUARD_BASE_URL": f"file://{release or REL}/{VERSION}",
        "LC_ALL": "C.UTF-8",
    }


def piped(args, release=None):
    """The website's one-liner, with the loader read from a local file instead of curl."""
    loader = f"{release or REL}/{VERSION}/i"
    return ["sh", "-c", f'cat "{loader}" | sh -s -- {args}']


def spawn(cmd, env, timeout=120):
    child = pexpect.spawn(cmd[0], cmd[1:], env=env, encoding="utf-8", timeout=timeout)
    child.logfile_read = Transcript()
    return child


class Transcript:
    def __init__(self):
        self.text = ""

    def write(self, s):
        self.text += s

    def flush(self):
        pass


def finish(child):
    child.expect(pexpect.EOF)
    child.close()
    return child.exitstatus, child.logfile_read.text


def run(cmd, env, stdin=subprocess.DEVNULL):
    """Without a controlling terminal (setsid), as cloud-init or a pipe would run it."""
    p = subprocess.run(["setsid", "-w"] + cmd, env=env, stdin=stdin, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def rules_json(guard, home):
    out = subprocess.run([guard, "config", "get", "rules"], env={"ZUNDER_GUARD_HOME": home},
                         capture_output=True, text=True, check=True).stdout.strip()
    body = out[len("zr1_"):]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def fresh_home():
    return tempfile.mkdtemp(prefix="home-", dir=os.environ.get("HOME_BASE", "/tmp"))


def tampered_release(change):
    root = tempfile.mkdtemp(prefix="rel-")
    shutil.copytree(f"{REL}/{VERSION}", f"{root}/{VERSION}")
    change(f"{root}/{VERSION}")
    return root


# ---------------------------------------------------------------- container cases

def guided_paper(c, account=PAPER_ACCOUNT):
    """Answer the account, the mode (paper) and the paper network (mainnet)."""
    c.expect("Hyperliquid account address")
    c.sendline(account)
    c.expect("Mode: paper")
    c.sendline("")
    c.expect("Paper mode reads which network's account")
    c.sendline("")


def case_paper_interactive_through_the_pipe():
    home = fresh_home()
    c = spawn(piped(f"--rules {RULES}"), env_for(home))
    c.expect(r"Keep these\? \[Y/edit\]")
    c.sendline("")
    guided_paper(c)
    status, text = finish(c)
    guard = f"{home}/.local/bin/zunder-guard"
    good = (status == 0 and "signature: SHA256SUMS signed by" in text and "checksum:  zunder-guard" in text
            and "Client key for your bot" in text and os.path.exists(guard))
    (ok if good else fail)("paper, interactive, through `curl | sh -s --` with the loader", text)
    if good:
        net = subprocess.run([guard, "config", "get", "network"], env={"ZUNDER_GUARD_HOME": f"{home}/.zunder-guard"},
                             capture_output=True, text=True).stdout.strip()
        (ok if net == "paper" else fail)(f"configured network is paper ({net})")


def case_edit_with_bounds():
    home = fresh_home()
    c = spawn(piped(f"--rules {RULES}"), env_for(home))
    c.expect(r"Keep these\? \[Y/edit\]")
    c.sendline("edit")
    c.expect(r"max leverage \(x\) \(empty keeps it\):")
    c.sendline("11")
    c.expect("refused: max_leverage must be above 0 and at most 10")
    c.expect(r"max leverage \(x\) \(empty keeps it\):")
    c.sendline("3")
    c.expect(r"max loss at the stop")
    c.sendline("")
    c.expect("without a stop: attach or refuse")
    c.sendline("refuse")
    for _ in range(6):
        c.expect(r"\(empty keeps it\):")
        c.sendline("")
    c.expect("markets: all, or coins separated by commas")
    c.sendline("BTC, ETH")
    c.expect("Rules now:")
    guided_paper(c)
    status, text = finish(c)
    guard_home = f"{home}/.zunder-guard"
    (ok if status == 0 else fail)("edit with bounds checking, then paper", text)
    if status == 0:
        r = rules_json(f"{home}/.local/bin/zunder-guard", guard_home)
        good = r["maxLeverage"] == 3 and r["markets"] == ["BTC", "ETH"] and r["stopPolicy"] == "refuse"
        (ok if good else fail)(f"edited rules saved: {r}")


def case_testnet_key_hidden_and_checked():
    home = fresh_home()
    c = spawn(piped(f"--rules {RULES}"), env_for(home))
    c.expect(r"Keep these\? \[Y/edit\]")
    c.sendline("")
    c.expect("Hyperliquid account address")
    c.sendline(TESTNET_ACCOUNT)
    c.expect("Mode: paper")
    c.sendline("main")
    status, text = finish(c)
    good = status != 0 and "is not paper, testnet or mainnet" in text and not os.path.exists(f"{home}/.zunder-guard/guard.toml")
    (ok if good else fail)("a mode not typed in full is refused, nothing written", text)
    c = spawn(piped(f"--rules {RULES}"), env_for(home))
    c.expect(r"Keep these\? \[Y/edit\]")
    c.sendline("")
    c.expect("Hyperliquid account address")
    c.sendline(TESTNET_ACCOUNT)
    c.expect("Mode: paper")
    c.sendline("testnet")
    c.expect(r"API wallet private key \(not shown while typing\):")
    c.sendline(KEY)
    status, text = finish(c)
    guard_home = f"{home}/.zunder-guard"
    good = (status != 0 and REFUSED_KEY in text and not os.path.exists(f"{guard_home}/guard.toml")
            and not os.path.exists(f"{guard_home}/api-wallet-key"))
    (ok if good else fail)("testnet: a key that is no API wallet of the account is refused by the venue check, nothing written", text)
    (ok if KEY not in text else fail)("the key never appears on the terminal", text)


def case_mainnet_refused_without_the_service():
    """Without systemd (here: a container, non-root) mainnet cannot be set up: init refuses it
    right after the mode, before the confirmation or a key, and writes nothing. (The typed
    confirmation and the equity cap are tested in init's own tests and in the systemd case.)"""
    home = fresh_home()
    c = spawn(piped(f"--rules {RULES} --account {PAPER_ACCOUNT}"), env_for(home))
    c.expect(r"Keep these\?")
    c.sendline("")
    c.expect("Mode: paper")
    c.sendline("mainnet")
    status, text = finish(c)
    good = (status != 0 and "mainnet is set up only as a systemd service" in text
            and "Nothing was written" in text and not os.path.exists(f"{home}/.zunder-guard/guard.toml")
            and "input hidden" not in text and "not shown while typing" not in text)
    (ok if good else fail)("mainnet without the systemd unit: refused before the confirmation or a key, nothing written", text)


def case_no_tty_refused():
    home = fresh_home()
    code, out = run(piped(f"--rules {RULES}"), env_for(home))
    good = code != 0 and "no terminal" in out and not os.path.exists(f"{home}/.local/bin/zunder-guard")
    (ok if good else fail)("without a terminal and without --non-interactive: refused, nothing installed", out)


def case_non_interactive():
    home = fresh_home()
    code, out = run(piped(f"--non-interactive --rules {RULES} --network paper --account {PAPER_ACCOUNT}"), env_for(home))
    (ok if code == 0 else fail)("non-interactive paper (cloud-init style)", out)
    notices = f"{home}/.local/share/licenses/zunder-guard"
    good = all(os.path.isfile(f"{notices}/{name}") and os.stat(f"{notices}/{name}").st_mode & 0o777 == 0o644
               for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"))
    (ok if good else fail)("user installation retains all distribution notices (0644)", out)
    code, out = run(piped(f"--non-interactive --rules {RULES} --network testnet --account {TESTNET_ACCOUNT}"), env_for(home))
    (ok if code != 0 and "--key-file" in out else fail)("non-interactive testnet without --key-file refused", out)
    key_file = f"{home}/key"
    with open(key_file, "w") as f:
        f.write(KEY + "\n")
    os.chmod(key_file, 0o600)
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network testnet --account {TESTNET_ACCOUNT} "
                          f"--key-file {key_file}"), env_for(home))
    (ok if code != 0 and REFUSED_KEY in out and KEY not in out else fail)(
        "non-interactive testnet with --key-file: the venue check refuses a key that is no API wallet, never shown", out)
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network mainnet --account {PAPER_ACCOUNT} "
                          f"--key-file {key_file}"), env_for(home))
    (ok if code != 0 and "--confirm-mainnet" in out else fail)("non-interactive mainnet without confirmation refused", out)
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network mainnet --account {PAPER_ACCOUNT} "
                          f"--confirm-mainnet {PAPER_ACCOUNT} --key-file {key_file}"), env_for(home))
    (ok if code != 0 and "--equity-cap" in out else fail)("non-interactive mainnet without an equity cap refused", out)
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network mainnet --account {PAPER_ACCOUNT} "
                          f"--confirm-mainnet {PAPER_ACCOUNT} --equity-cap 2000 --key-file {key_file}"), env_for(home))
    good = code != 0 and "set up only as a systemd service" in out and "Nothing was set up" in out and KEY not in out
    (ok if good else fail)("non-interactive mainnet without the systemd unit: refused before init", out)
    (ok if "still holds the API wallet key in plain text" not in out else fail)("(no key-file warning when nothing ran)", out)
    # --licence: the shape checked by install.sh, the key by the binary, before anything is saved.
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network paper --account {PAPER_ACCOUNT} "
                          "--licence nonsense"), env_for(home))
    (ok if code != 0 and "starts with zgl1_" in out else fail)("a licence key of the wrong shape is refused", out)
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network paper --account {PAPER_ACCOUNT} "
                          "--licence zgl1_e30.AAAA"), env_for(home))
    (ok if code != 0 and "licence key is refused" in out else fail)("a licence key that does not verify is refused", out)


def case_invalid_rules():
    home = fresh_home()
    c = spawn(piped("--rules zr1_eyJ2IjoyfQ"), env_for(home))
    status, text = finish(c)
    (ok if status != 0 and "rules code is refused" in text else fail)("an invalid rules string is refused", text)


def refused(name, release, needle):
    home = fresh_home()
    code, out = run(piped(f"--non-interactive --rules {RULES} --network paper", release), env_for(home, release))
    good = code != 0 and needle in out and not os.path.exists(f"{home}/.local/bin/zunder-guard")
    (ok if good else fail)(f"{name}: refused, nothing installed", out)


def case_tampering():
    def archive(d):
        with open(f"{d}/zunder-guard-{VERSION}-linux-{arch()}.tar.gz", "ab") as f:
            f.write(b"\0")
    refused("archive changed after signing", tampered_release(archive), "checksum mismatch")

    def sums(d):
        with open(f"{d}/SHA256SUMS", "a") as f:
            f.write("0" * 64 + "  extra\n")
    refused("SHA256SUMS changed after signing", tampered_release(sums), "does not verify")

    def installer(d):
        with open(f"{d}/install.sh", "a") as f:
            f.write("\necho pwned\n")
    refused("install.sh changed", tampered_release(installer), "install.sh does not match")

    def other_identity(d):
        with open(f"{d}/SHA256SUMS.sigstore.json") as f:
            b = f.read()
        with open(f"{d}/SHA256SUMS.sigstore.json", "w") as f:
            f.write(b.replace(f"refs/tags/{VERSION}", "refs/tags/v9.9.9").replace("zunderlabs/", "someone-else/"))
    refused("signed by another workflow or tag", tampered_release(other_identity), "does not verify")


def arch():
    return {"x86_64": "amd64", "aarch64": "arm64"}[os.uname().machine]


def case_bootstrap_real_cosign():
    """No cosign installed: the loader fetches the pinned release and checks its SHA-256. The
    real cosign then rejects the test release's fake bundle, which is the expected refusal."""
    home = fresh_home()
    code, out = run(piped(f"--non-interactive --rules {RULES} --network paper"), env_for(home, fake_cosign=False))
    good = code != 0 and "does not verify" in out and "pinned SHA-256" not in out
    (ok if good else fail)("pinned cosign downloaded, hash matched, real cosign refuses a fake bundle", out)


# ---------------------------------------------------------------- systemd on the box

def sh(cmd, check=False):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def systemd_cleanup():
    sh("sudo systemctl disable --now zunder-guard 2>/dev/null; sudo rm -rf /etc/systemd/system/zunder-guard.service "
       "/etc/systemd/system/zunder-guard.service.d /etc/zunder-guard /var/lib/zunder-guard "
       "/etc/credstore.encrypted/zunder-guard.hl-api-wallet-key /usr/local/bin/zunder-guard "
       "/usr/local/share/licenses/zunder-guard; "
       "sudo systemctl daemon-reload; id zunder-guard >/dev/null 2>&1 && sudo userdel zunder-guard; true")


def case_systemd_paper():
    systemd_cleanup()
    home = fresh_home()
    c = spawn(piped(f"--rules {RULES}"), env_for(home), timeout=180)
    c.expect(r"Keep these\?")
    c.sendline("")
    guided_paper(c)
    status, text = finish(c)
    good = status == 0 and "Guard is running (paper)" in text and "Client key for your bot" in text
    (ok if good else fail)("systemd, paper, guided", text)
    # Pair mutates guard.toml; its last printed key must precede the start that loads it.
    (ok if text.rfind("Client key for your bot") < text.index("Guard is running (paper)")
     else fail)("all displayed client keys paired before the service starts", text)
    active = sh("systemctl is-active zunder-guard").stdout.strip()
    (ok if active == "active" else fail)(f"unit active ({active})", sh("sudo journalctl -u zunder-guard -n 30 --no-pager").stdout)
    local_addrs = sh("sudo ss -Hltn sport = :8547 | awk '{print $4}'").stdout.split()
    (ok if local_addrs == ["127.0.0.1:8547"] else fail)(f"listens on 127.0.0.1 only: {local_addrs}")
    health = sh("curl -fsS http://127.0.0.1:8547/healthz").stdout
    status_json = sh("curl -fsS http://127.0.0.1:8547/guard/status").stdout
    (ok if '"ok"' in health and '"mode":"paper"' in status_json else fail)(f"healthy in paper mode: {health}")
    score = sh("systemd-analyze security zunder-guard --no-pager | tail -1").stdout.strip()
    print(f"  info: systemd-analyze security: {score}")
    procs = sh("ps -eo user:20,args | grep '[z]under-guard run'").stdout.strip()
    (ok if procs.startswith("zunder-guard") else fail)(f"runs as the zunder-guard user: {procs}")


def case_systemd_testnet_key_refused():
    """Guided testnet under systemd with a key the venue does not know: refused at the key check,
    nothing stored (no credential, no plain file, no drop-in naming one), the key never shown."""
    systemd_cleanup()
    home = fresh_home()
    c = spawn(piped(f"--rules {RULES}"), env_for(home), timeout=180)
    c.expect(r"Keep these\?")
    c.sendline("")
    c.expect("Hyperliquid account address")
    c.sendline(TESTNET_ACCOUNT)
    c.expect("Mode: paper")
    c.sendline("testnet")
    c.expect(r"API wallet private key for 0x[0-9a-f]+ on testnet \(input hidden\): ")
    c.sendline(KEY)
    status, text = finish(c)
    good = status != 0 and REFUSED_KEY in text and "nothing was stored" in text
    (ok if good else fail)("systemd, testnet: the venue check refuses the key, nothing stored", text)
    found = re.search(r"(0x[0-9a-f]{40}) " + REFUSED_KEY, text)
    if found:
        KEY_ADDRESS["testnet"] = found.group(1)
    (ok if KEY not in text else fail)("the key never appears on the terminal", text)
    leaks = sh(f"sudo grep -rl {KEY} /etc /var/lib/zunder-guard /usr/local/bin 2>/dev/null").stdout.strip()
    (ok if leaks == "" else fail)("the key is nowhere on disk", leaks)
    stored = sh("sudo ls /etc/credstore.encrypted/zunder-guard.hl-api-wallet-key /etc/zunder-guard/hl-api-wallet-key 2>&1").stdout
    (ok if stored.count("No such file") == 2 else fail)("no credential and no key file", stored)


def case_systemd_credential_reaches_stdin():
    """The plumbing the installer writes for a keyed network (an encrypted credential handed to
    the binary on standard input), with the fake key: the service reads the key, checks it with
    the venue and refuses it. That refusal in the log proves the key arrived on standard input;
    the key itself is in no log, no argument list and nowhere on disk in plain text."""
    home_conf = sh("sudo cat /var/lib/zunder-guard/guard.toml").stdout
    if 'mode = "testnet"' not in home_conf or "testnet" not in KEY_ADDRESS:
        fail("credential plumbing: needs the testnet setup and the key's address from the previous case", home_conf)
        return
    # `run` checks the key against the config's api_wallet before it asks the venue: record the
    # fake key's address, as `key check` would for a real one, so the run reaches the venue check.
    sh(f"sudo sed -i '1i api_wallet = \"{KEY_ADDRESS['testnet']}\"' /var/lib/zunder-guard/guard.toml")
    sh("sudo install -d -m 0700 /etc/credstore.encrypted")
    enc = sh(f"printf '%s\\n' {KEY} | sudo systemd-creds encrypt --name=hl-api-wallet-key - "
             "/etc/credstore.encrypted/zunder-guard.hl-api-wallet-key")
    if enc.returncode != 0:
        fail("credential plumbing: systemd-creds encrypt", enc.stderr)
        return
    unit = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "systemd", "zunder-guard.service")
    sh(f"sudo install -m 0644 {unit} /etc/systemd/system/zunder-guard.service")
    dropin = ("[Service]\nEnvironment=ZUNDER_GUARD_NETWORK=testnet\n"
              "LoadCredentialEncrypted=hl-api-wallet-key:/etc/credstore.encrypted/zunder-guard.hl-api-wallet-key\n"
              "ExecStart=\nExecStart=/bin/sh -c 'exec /usr/local/bin/zunder-guard run --network testnet --key-stdin < \"$$CREDENTIALS_DIRECTORY/hl-api-wallet-key\"'\n")
    sh("sudo install -d -m 0755 /etc/systemd/system/zunder-guard.service.d")
    with open("/tmp/guard-dropin.conf", "w") as f:
        f.write(dropin)
    sh("sudo install -m 0644 /tmp/guard-dropin.conf /etc/systemd/system/zunder-guard.service.d/10-install.conf")
    os.remove("/tmp/guard-dropin.conf")
    sh("sudo chown -R zunder-guard:zunder-guard /var/lib/zunder-guard; sudo systemctl daemon-reload; "
       "sudo systemctl restart zunder-guard")
    log = ""
    for _ in range(30):
        log = sh("sudo journalctl -u zunder-guard -n 40 --no-pager").stdout
        if REFUSED_KEY in log:
            break
        sh("sleep 1")
    (ok if REFUSED_KEY in log else fail)("the credential reaches the binary on standard input (the venue check refuses the fake key)", log)
    (ok if KEY not in log else fail)("the key is in no log line", log)
    leaks = sh(f"sudo grep -rl {KEY} /etc /var/lib/zunder-guard /usr/local/bin 2>/dev/null").stdout.strip()
    (ok if leaks == "" else fail)("the key is nowhere on disk in plain text (the credential is encrypted)", leaks)
    sh("sudo systemctl stop zunder-guard")


def case_systemd_mainnet_needs_systemd_creds(shim_dir):
    """Without systemd-creds, mainnet under systemd is refused before the key is asked for."""
    systemd_cleanup()
    home = fresh_home()
    env = env_for(home)
    env["PATH"] = f"{shim_dir}:{env['PATH']}"
    code, out = run(piped(f"--non-interactive --rules {RULES} --network mainnet --account {PAPER_ACCOUNT} "
                          f"--confirm-mainnet {PAPER_ACCOUNT} --equity-cap 2000 --key-file /dev/null"), env)
    good = code != 0 and "mainnet under systemd needs systemd-creds" in out and "Nothing was set up" in out
    (ok if good else fail)("mainnet under systemd without systemd-creds: refused before init and any key", out)


def case_systemd_mainnet_key_checked_never_stored():
    """With systemd-creds, non-interactive mainnet: init reads the key once to check it with the
    venue (the fake key is refused there), nothing is written or stored, nothing starts."""
    systemd_cleanup()
    home = fresh_home()
    key_file = f"{home}/key"
    with open(key_file, "w") as f:
        f.write(KEY + "\n")
    os.chmod(key_file, 0o600)
    code, out = run(piped(f"--non-interactive --rules {RULES} --network mainnet --account {PAPER_ACCOUNT} "
                          f"--confirm-mainnet {PAPER_ACCOUNT} --equity-cap 2000 --key-file {key_file}"), env_for(home))
    good = code != 0 and REFUSED_KEY in out and KEY not in out
    (ok if good else fail)("systemd, mainnet: the key is checked with the venue (refused here), never shown", out)
    stored = sh("sudo ls /var/lib/zunder-guard/guard.toml /etc/credstore.encrypted/zunder-guard.hl-api-wallet-key "
                "/etc/zunder-guard/hl-api-wallet-key /var/lib/zunder-guard/api-wallet-key 2>&1").stdout
    (ok if stored.count("No such file") == 4 else fail)("nothing written: no config, no credential, no key file", stored)
    active = sh("systemctl is-active zunder-guard").stdout.strip()
    (ok if active != "active" else fail)(f"nothing started ({active})")


def case_systemd_back_to_paper():
    home = fresh_home()
    code, out = run(piped(f"--non-interactive --force --rules {RULES} --network paper --account {PAPER_ACCOUNT}"), env_for(home))
    dropin = sh("cat /etc/systemd/system/zunder-guard.service.d/10-install.conf").stdout
    good = (code == 0 and "LoadCredential" not in dropin and "ZUNDER_GUARD_NETWORK=paper" in dropin
            and "run --network paper" in dropin)
    (ok if good else fail)("reconfigured to paper: no credential in the drop-in", out + dropin)


def case_docker_interactive():
    vol = "guard-it-test"
    sh(f"docker volume rm -f {vol}")
    c = spawn(["docker", "run", "-it", "--rm", "-v", f"{vol}:/data", "zunder-guard:test",
               "init", "--interactive", "--rules", RULES], dict(os.environ))
    c.expect(r"Keep these\?")
    c.sendline("")
    c.expect("Hyperliquid account address")
    c.sendline(TESTNET_ACCOUNT)
    c.expect("Mode: paper")
    c.sendline("testnet")
    c.expect(r"API wallet private key \(not shown while typing\):")
    c.sendline(KEY)
    status, text = finish(c)
    good = status != 0 and KEY not in text and REFUSED_KEY in text
    (ok if good else fail)("docker run -it … init --interactive: guided, key hidden, checked with the venue (refused here)", text)
    c = spawn(["docker", "run", "-it", "--rm", "-v", f"{vol}:/data", "zunder-guard:test",
               "init", "--interactive", "--rules", RULES], dict(os.environ))
    c.expect(r"Keep these\?")
    c.sendline("")
    guided_paper(c)
    status, text = finish(c)
    (ok if status == 0 and "Client key for your bot" in text else fail)("docker run -it … init --interactive: paper", text)
    sh(f"docker volume rm -f {vol}")


def case_install_only_offline():
    """Synthetic verified release: exercise installation without a key, venue or service.

    fake-cosign verifies fixture identity/hash, not a real Sigstore signature. The fake
    Guard only supports --version and logs every invocation; anything else fails.
    """
    source = Path(__file__).resolve().parents[1] / "install.sh"
    if not source.is_file():
        source = Path(REL) / VERSION / "install.sh"  # existing /t-only container mount
    with tempfile.TemporaryDirectory(prefix="guard-upgrade-") as temporary:
        root = Path(temporary)
        release = root / "release"
        release.mkdir()
        fakebin = root / "fakebin"
        fakebin.mkdir()
        prefix = root / "bin"
        prefix.mkdir()
        home = root / "home"
        home.mkdir()
        state = home / ".zunder-guard"
        state.mkdir()
        for name in ("guard.toml", "risk-mainnet.jsonl", "api-wallet-key", "client-key", "renewal-token"):
            (state / name).write_text("synthetic preserved " + name)
            (state / name).chmod(0o600)
        before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in state.iterdir()}
        calls = root / "calls"
        guard = release / "zunder-guard"
        guard.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$INSTALL_TEST_CALLS"\n'
                         '[ "$#" -eq 1 ] && [ "$1" = --version ] || exit 91\n'
                         'echo "zunder-guard 0.0.0"\n')
        guard.chmod(0o755)
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
            (release / name).write_text("fixture " + name)
        system = subprocess.check_output(["uname", "-s"], text=True).strip()
        arch = subprocess.check_output(["uname", "-m"], text=True).strip()
        os_name = "darwin" if system == "Darwin" else "linux"
        arch = "arm64" if arch in ("arm64", "aarch64") else "amd64"
        archive = release / f"zunder-guard-{VERSION}-{os_name}-{arch}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name in ("zunder-guard", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
                tar.add(release / name, arcname=name)
        sums = release / "SHA256SUMS"
        sums.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
        bundle = release / "SHA256SUMS.sigstore.json"
        identity = f"https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/{VERSION}"
        bundle.write_text(json.dumps({"identity": identity, "sha256": hashlib.sha256(sums.read_bytes()).hexdigest()}))
        shutil.copy(Path(__file__).with_name("fake-cosign"), fakebin / "cosign")
        (fakebin / "cosign").chmod(0o755)
        # Refuse network URLs even if installer control flow regresses.
        curl = shutil.which("curl")
        (fakebin / "curl").write_text('#!/bin/sh\nfor arg do case "$arg" in http:* | https:*) exit 92;; esac; done\nexec ' + shlex.quote(curl) + ' "$@"\n')
        (fakebin / "curl").chmod(0o755)
        for command in ("sudo", "systemctl", "systemd-creds", "useradd", "chown"):
            shim = fakebin / command
            shim.write_text('#!/bin/sh\necho "UNEXPECTED ' + command + '" >> "$INSTALL_TEST_CALLS"\nexit 93\n')
            shim.chmod(0o755)
        script = root / "install.sh"
        script.write_text(source.read_text().replace("@VERSION@", VERSION))
        env = {"PATH": str(fakebin) + os.pathsep + os.environ["PATH"], "HOME": str(home),
               "ZUNDER_GUARD_BASE_URL": release.as_uri(), "INSTALL_TEST_CALLS": str(calls)}
        def execute(extra=()):
            return subprocess.run(["sh", str(script), "--install-only", "--prefix", str(prefix), *extra],
                                  env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  start_new_session=True)
        old = prefix / "zunder-guard"
        old.write_text("previous version")
        with old.open() as previous_inode:
            result = execute()
            preserved_inode = previous_inode.read() == "previous version"
        good = (result.returncode == 0 and preserved_inode and old.read_bytes() == guard.read_bytes()
                and calls.read_text().splitlines() == ["--version"]
                and before == {p.name: (p.read_bytes(), p.stat().st_mode) for p in state.iterdir()})
        (ok if good else fail)("install-only atomically replaces verified binary, preserves all state, no setup/service", result.stdout + result.stderr)
        result = execute(["--non-interactive"])
        (ok if result.returncode == 0 else fail)("install-only needs no setup values without a terminal", result.stderr)
        for args in (["--force"], ["--network", "mainnet"], ["--licence", "zgl1_fixture"], ["--key-file", "/not-read"]):
            count = calls.read_text()
            result = execute(args)
            (ok if result.returncode != 0 and "cannot be combined" in result.stderr and calls.read_text() == count else fail)("install-only rejects setup flags: " + args[0], result.stderr)
        pristine = old.read_bytes()
        archive_bytes = archive.read_bytes()
        bundle_bytes = bundle.read_bytes()
        archive.write_bytes(archive.read_bytes() + b"tamper")
        result = execute()
        (ok if result.returncode != 0 and "checksum mismatch" in result.stderr and old.read_bytes() == pristine else fail)("install-only refuses tampered archive before replacement", result.stderr)
        bundle.write_text(json.dumps({"identity": identity + "-wrong", "sha256": hashlib.sha256(sums.read_bytes()).hexdigest()}))
        result = execute()
        (ok if result.returncode != 0 and "signature check FAILED" in result.stderr and old.read_bytes() == pristine else fail)("install-only refuses wrong signing identity before replacement", result.stderr)
        archive.write_bytes(archive_bytes)
        bundle.write_bytes(bundle_bytes)
        old.unlink()
        target = root / "outside-binary"
        target.write_bytes(pristine)
        old.symlink_to(target)
        result = execute()
        (ok if result.returncode != 0 and old.is_symlink() and target.read_bytes() == pristine
         else fail)("install-only refuses a symlink destination", result.stderr)
        old.unlink()
        old.mkdir()
        result = execute()
        (ok if result.returncode != 0 and old.is_dir() and not list(old.iterdir())
         else fail)("install-only refuses a directory destination", result.stderr)
        old.rmdir()
        old.write_bytes(pristine)
        mv = shutil.which("mv")
        (fakebin / "mv").write_text('#!/bin/sh\ncase "$2" in */.zunder-guard.*) exit 94;; esac\nexec ' + shlex.quote(mv) + ' "$@"\n')
        (fakebin / "mv").chmod(0o755)
        result = execute()
        (ok if result.returncode != 0 and old.read_bytes() == pristine and not list(prefix.glob(".zunder-guard.*"))
         else fail)("failed replacement keeps previous binary and cleans staging", result.stderr)


def case_init_options_offline():
    """Execute the installer's actual init-argument block with an inert Guard.

    This checks the explicit network selected in the website command reaches the
    interactive CLI without carrying noninteractive account consent or a key file.
    No installer setup, system service, credential or venue call is executed.
    """
    source = Path(__file__).resolve().parents[1] / "install.sh"
    script = source.read_text()
    block = script.split("\nset -- init\n", 1)[1].split("\nNET=$(guard config get network)", 1)[0]
    # Only replace the controlling-terminal input boundary, not argument logic.
    block = "set -- init\n" + block.replace("</dev/tty", "</dev/null")
    capture = 'guard() { printf "%s\\n" "$@"; }\n'
    base = {"PATH": os.environ["PATH"], "RULES": "zr1_fixture", "SERVICE": "1",
            "NO_MAINNET": "", "FORCE": "0", "LISTEN": "", "SHARE": "", "LICENCE": "",
            "CAP": "100", "ACCOUNT": PAPER_ACCOUNT, "CONFIRM": PAPER_ACCOUNT, "KEY_FILE": "/dev/null"}
    for network in ("", "paper", "testnet", "mainnet"):
        env = {**base, "NONINTERACTIVE": "0", "NETWORK": network}
        result = subprocess.run(["sh", "-eu", "-c", capture + block], env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True)
        args = result.stdout.splitlines()
        expected = ["init", "--rules", "zr1_fixture", "--no-key", "--equity-cap", "100",
                    "--account", PAPER_ACCOUNT]
        if network:
            expected += ["--network", network]
        expected += ["--interactive"]
        (ok if result.returncode == 0 and args == expected else fail)(
            "interactive selected mode forwarded with explicit consent still in CLI: " + (network or "ask"),
            result.stdout + result.stderr)
    env = {**base, "NONINTERACTIVE": "1", "NETWORK": "mainnet"}
    result = subprocess.run(["sh", "-eu", "-c", capture + block], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True)
    expected = ["init", "--rules", "zr1_fixture", "--no-key", "--equity-cap", "100",
                "--non-interactive", "--network", "mainnet", "--account", PAPER_ACCOUNT,
                "--confirm-mainnet", PAPER_ACCOUNT, "--key-stdin"]
    (ok if result.returncode == 0 and result.stdout.splitlines() == expected else fail)(
        "noninteractive explicit account-consent and stdin contract preserved", result.stdout + result.stderr)


def main():
    mode = sys.argv[1]
    if mode not in ("install-only", "init-options"):
        global pexpect
        import pexpect
    if mode == "init-options":
        case_init_options_offline()
    elif mode == "install-only":
        case_init_options_offline()
        case_install_only_offline()
    elif mode == "container":
        case_paper_interactive_through_the_pipe()
        case_edit_with_bounds()
        case_testnet_key_hidden_and_checked()
        case_mainnet_refused_without_the_service()
        case_no_tty_refused()
        case_non_interactive()
        case_invalid_rules()
        case_tampering()
        case_install_only_offline()
    elif mode == "bootstrap":
        case_bootstrap_real_cosign()
    elif mode == "systemd":
        try:
            case_systemd_paper()
            case_systemd_back_to_paper()
            case_systemd_testnet_key_refused()
            case_systemd_credential_reaches_stdin()
            case_systemd_mainnet_key_checked_never_stored()
            shim = tempfile.mkdtemp()
            with open(f"{shim}/systemd-creds", "w") as f:
                f.write("#!/bin/sh\necho 'systemd-creds test shim: an old systemd'\n")
            os.chmod(f"{shim}/systemd-creds", 0o755)
            try:
                case_systemd_mainnet_needs_systemd_creds(shim)
            finally:
                shutil.rmtree(shim, ignore_errors=True)
        finally:
            systemd_cleanup()
    elif mode == "docker":
        case_docker_interactive()
    if FAILED:
        print(f"{len(FAILED)} FAILED: {FAILED}")
        sys.exit(1)
    print(f"installer tests ({mode}) passed")


if __name__ == "__main__":
    main()
