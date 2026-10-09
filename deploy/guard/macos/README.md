# macOS managed sending services

This directory implements native mainnet and explicitly selected testnet services. Publication is gated on the native security and lifecycle checks in the reviewed specification; the presence of these files alone does not make the route released.

The authenticated macOS installer uses the signed `install-macos-service.sh` release asset internally. Never run a Homebrew Cellar executable under sudo to provision the service. Guard's privileged credential broker lives in a root-owned immutable release directory; the trading child runs as `_zunder_guard`. The System Keychain holds the API wallet credential, supplied on the child's anonymous stdin pipe at each start. No login-Keychain or interactive session is intended to be required after macOS boots and the disk is unlocked.

## Finish installation

The installer prompts for explicit mainnet account confirmation, cap and API wallet key, then stores an account- and release-bound encrypted item. It prints the exact journal and startup commands. It does not initialize the mainnet journal or start trading automatically.

Only for a newly configured account whose mainnet journal does not yet exist, run the printed `journal-init --mode mainnet --note ...` command as `_zunder_guard` with the account's explicit `ZUNDER_MAINNET_CONFIRM`. An existing journal is preserved; do not recreate or resume it as an installation step.

Then start the prepared service:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.zunderlabs.guard.mainnet.plist
GUARD_SERVICE_EXE=$(plutil -extract executable raw -o - '/Library/Application Support/Zunder Guard/bindings/active.json')
sudo -u _zunder_guard "$GUARD_SERVICE_EXE" --home '/Library/Application Support/Zunder Guard/state' health
sudo -u _zunder_guard "$GUARD_SERVICE_EXE" --home '/Library/Application Support/Zunder Guard/state' status
```

Check the intended account, mainnet mode, risk state and licence before starting the bot. `launchctl` loading a job is not evidence that its credential or journal was accepted. The root-only log is `/var/log/zunder-guard.log`; it must never contain a private key.

## Pair and activate

Setup already prints a bot client key and browser pairing code. For an additional bot, stop your bots, unload Guard, add the client and start again:

```sh
sudo launchctl bootout system/com.zunderlabs.guard.mainnet
GUARD_SERVICE_BINDING='/Library/Application Support/Zunder Guard/bindings/active.json'
sudo "$GUARD_SERVICE_EXE" service pair --binding "$GUARD_SERVICE_BINDING" --confirm-mainnet 0xYOUR_ACCOUNT
sudo "$GUARD_SERVICE_EXE" service readmit --binding "$GUARD_SERVICE_BINDING" --confirm-mainnet 0xYOUR_ACCOUNT
sudo launchctl bootstrap system /Library/LaunchDaemons/com.zunderlabs.guard.mainnet.plist
```

Pairing changes the configuration admitted by the service. The explicit `service readmit` step admits that client change with the same release and account confirmation before loading the service again. It retains credential scope, journals and licence. Never edit immutable binding JSON by hand.

Licence changes are different: the admitted fingerprint excludes only `licence`, `licence_auto_update` and `licence_renewal_token`, so licence activation and renewal do not require readmission:

```sh
sudo "$GUARD_SERVICE_EXE" service licence-set --binding '/Library/Application Support/Zunder Guard/bindings/active.json' --key 'zgl1_REPLACE_WITH_YOUR_EMAIL_KEY'
sudo "$GUARD_SERVICE_EXE" service licence-show --binding '/Library/Application Support/Zunder Guard/bindings/active.json'
```

A changed licence applies on the next sync without restarting. Check the running instance reports `fee_free`. Enabling automatic renewal requires a restart; subsequent renewed keys apply without one.

## Upgrade

Stop bots and boot out the service first. Run the verified installer for the new release. It retains configuration, pairings, licence and journals. The old root-owned broker reads its own Keychain item and passes the key over an anonymous pipe to the new verified broker; the new release creates and checks a separate item under its own code identity. No command exports the key to a terminal or file.

The installer leaves the new service stopped and retains the old release, binding and credential. Start the new service explicitly, then check health, account, mode and licence. Do not delete the old items until the new service is validated. A failed migration leaves its old credential available; never broaden the Keychain ACL to make an upgrade work.

## Stop and remove

`sudo launchctl bootout system/com.zunderlabs.guard.mainnet` unloads the service. Stop bots first. Removing the root-owned plist afterwards removes service registration but keeps the state, old releases, bindings and encrypted credentials.

Credential deletion is a separate explicit operation while the job is unloaded:

```sh
sudo "$GUARD_SERVICE_EXE" service remove-credential --binding '/Library/Application Support/Zunder Guard/bindings/active.json'
```

Old releases have separate items and require their own admitted versioned binding/executable to remove them. Keep configuration and journals for a future installation and records. Never delete them as a workaround for a journal or admission error.

If configuration changed after an upgrade, the old binding may no longer match it. Credential removal then refuses. With Guard stopped, explicitly readmit that old binding against the current account before removing its item; retain the encrypted item if the old release cannot validate the current configuration. Never edit a binding fingerprint by hand or broaden a Keychain ACL.

## Protected testnet installation

The signed helper accepts explicit `testnet` from its authenticated installer,
with hidden interactive input or paired `--non-interactive --key-stdin` input.
This support requires a new signed release; it is
not available in v1.0.1. Older helper invocations retain the mainnet route and its
interactive confirmation.

Testnet uses `_zunder_guard_testnet`, the `testnet-native` credential ID,
`state-testnet` and `bindings-testnet` under the protected application directory,
`com.zunderlabs.guard.testnet-native` as its launchd label, and the root-only log
`/var/log/zunder-guard-testnet.log`. Its System Keychain service namespace is
`com.zunderlabs.guard.testnet.v2`; mainnet's existing namespace and credential
identifiers remain unchanged. Root-owned immutable release binaries are shared,
not credentials or state.

Interactive installation validates the key through Guard's hidden terminal prompt
without saving it in a user credential store. Its separate provisioning prompt
passes the key directly to the admitted System Keychain broker. An explicit equity
cap is required; when absent, the helper asks for it before key validation.

Unattended fresh installation requires explicit rules, account and cap. A licence
is optional for Testnet. When supplied, Guard validates and preserves it; invalid
keys fail setup. A staging-issued disposable key cannot activate official Guard.
The
provider supplies two newline-terminated key frames through a private anonymous
stdin pipe. The unprivileged setup consumes the first frame only to validate and
record the public API-wallet address, with `--service-key-check --non-interactive
--no-key --key-stdin`. The admitted root-owned broker consumes the second frame
and creates its System Keychain item. No plaintext wallet key is stored in the
service state, shell variable, argument, environment or log. A regular input file
or terminal is refused for the unattended input path; interactive setup requires
an actual terminal. Paid activation is proved separately with a genuine entitlement.

The service remains stopped after installation. A test controller may explicitly
initialize a missing testnet journal and load the prepared launchd job. It must
preserve an existing journal and halt. Testnet management uses `--confirm-account`
with the bound account. It does not use or generate `ZUNDER_MAINNET_CONFIRM`.
Pairing still requires stopped-service readmission, and licence changes retain
the same fingerprint exclusions as mainnet.

An existing testnet installation is reinstalled or upgraded without setup
options. A same-release reinstall preserves its admitted binding and only checks
the existing credential; an upgrade migrates the credential between the two
admitted root-owned processes. Neither operation accepts another network's state
or changes mainnet's service registration. Cleanup must unload the exact owned
job before credential removal and must retain journals unless their disposal was
separately authorized. Installation and offline fixture checks alone do not
prove a real Keychain admission, native restart or host reboot.
