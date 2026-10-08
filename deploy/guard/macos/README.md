# macOS managed mainnet service

This directory is the native mainnet service implementation. Publication is gated on the native security and lifecycle checks in the reviewed specification; the presence of these files alone does not make the route released.

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
