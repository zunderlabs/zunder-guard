# Windows mainnet installation candidate

This verified machine-service path is prepared for the first signed v1.0.0 release. It is not yet a native-tested released installer. Do not replace already signed/versioned assets. Publication requires independent code review, Windows 5.1/7 tests, the native service checks and released-image install/upgrade proof. Pre-login reboot is a separate gate.

Open an elevated, trusted Windows PowerShell console explicitly, then run the verified published loader:

```powershell
& ([scriptblock]::Create((irm https://zunderlabs.com/i.ps1))) -Network mainnet -Rules zr1_YOUR_RULES
```

`-Account 0x...`, `-EquityCap 100` and a public `-Licence zgl1_...` can prefill setup. Missing account and cap are prompted; mainnet account confirmation must be explicitly supplied through `-ConfirmAccount` or typed again. The loader never derives consent from an environment variable. Omit `-Rules` only to use Rust's existing defaults, with the same mainnet ceiling checks. Native x64 is required. The mainnet branch refuses `-NonInteractive`, `-InstallOnly`, `-Force` and per-user `-InstallDir`; paper/testnet/install-only remain separate paths.

The loader creates protected machine staging, pins the verifier bytes and authenticates the exact tag's archive and `install-windows-service.ps1` before executing the helper. It retains a verified helper/cache under `%ProgramData%\ZunderGuard\management\releases`. **Use the exact helper path printed by installation**, not a script fetched later from `main`. The Guard image lives at `%ProgramFiles%\ZunderGuard\guard\zunder-guard.exe`; the runtime home is `%ProgramData%\ZunderGuard\guard\runtime`. Rust handles hidden wallet-key prompts; PowerShell does not capture a private key. The API wallet remains encrypted for the machine's dedicated virtual service account.

Only the fixed machine PowerShell process running the already verified, protected helper gets `-ExecutionPolicy Bypass`. No CurrentUser/LocalMachine setting or Group Policy is changed. MachinePolicy/UserPolicy still take precedence; incompatible organization policies produce a refusal. The outer loader imports OS binary modules only, keeping script-based NetTCPIP imports inside the verified helper. Retained-helper commands use the same process-scoped invocation.

Preparation leaves the service stopped with startup **Disabled**. The initial bot secret/pairing code is printed once. Initialize the scoped mainnet journal only after reviewing the account; an existing journal is never recreated or automatically resumed. Then explicitly choose startup behavior:

```powershell
$Helper = '<exact verified helper path printed by the loader>'
$PowerShell = [IO.Path]::Combine([Environment]::GetFolderPath('Windows'),'System32','WindowsPowerShell','v1.0','powershell.exe')
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action JournalInit -Id guard -ConfirmAccount 0xYOUR_ACCOUNT -Note 'who reviewed the account and why'
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Start -Id guard -ConfirmAccount 0xYOUR_ACCOUNT -Startup DelayedAuto
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Status -Id guard
```

Use `-Startup Manual` to run without boot autostart. During activation startup is Demand; DelayedAuto is enabled only after owned loopback health and account/network/risk/licence checks succeed and the activation record is committed. SCM Running alone is not trading readiness. Approved, unblocked builder mode or an active fee-free licence is required for trading-ready wording. A service with unchecked, missing approval at the venue, or a venue-refused builder remains guarded and reports the exact approval state with a Mainnet main-wallet approval link at https://zunderlabs.com/approve; it never approves automatically. No orders are needed to prove installation. A risk halt is never resumed by this helper.

The machine binding is `%ProgramData%\ZunderGuard\guard\binding.json`. Licence operations use that binding, preserving the service's runtime configuration and renewal fields:

```powershell
$Exe = "$env:ProgramFiles\ZunderGuard\guard\zunder-guard.exe"
$Binding = "$env:ProgramData\ZunderGuard\guard\binding.json"
& $Exe service licence-set --binding $Binding --key zgl1_FROM_YOUR_EMAIL
& $Exe service licence-show --binding $Binding
```

A supplied licence must be active and `fee_free` in structured running status before activation reports that state. Without a licence, the helper records and reports the actual pay-per-order approval state; unknown/missing fee fields fail admission. Existing renewal metadata is retained; normal Rust licence checks and atomic config updates apply.

## Interrupted setup and upgrades

The protected transaction records intent before each mutation. Resume only an owned pending transaction using the printed helper:

```powershell
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Resume -Id guard -ConfirmAccount 0xYOUR_ACCOUNT
```

A committed config is reused without init or pairing again. A present credential is not overwritten. Presence does not prove decryption: runtime startup supplies that evidence. If setup committed but the terminal closed before you recorded the one-time bot secret, deliberately add a new client later with `service pair` and `service readmit` while disabled; Resume never pairs automatically. A leftover uncommitted `.new` or unknown file is retained for explicit inspection, never silently deleted or promoted.

Re-running the loader does not silently upgrade a completed instance. Run the same loader command after the new exact release is published. It verifies and retains the new cache, prints its exact helper and Upgrade command, and leaves the existing service running or stopped as it was. Use that verified cached helper with `-Action Upgrade -ReleaseDir <verified cache> -Tag <exact tag> -Id guard -ConfirmAccount <account>`. Upgrade disables startup and confirms no owned runtime before replacing the image/binding. It preserves credentials, configuration, licence, client pairings and journals and never restarts because the old service was running. Use explicit Start afterwards.

An interrupted upgrade resumes while disabled using its exact retained transaction/helper. `-Action Recover -Recovery RollbackImage` is limited to a not-yet-started new runtime and an unchanged journal; it restores only the old verified image/binding. It never rolls back accounting/risk journals, configuration or credentials. Old release caches and backups remain until separately reviewed cleanup.

## Stop and uninstall

```powershell
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Stop -Id guard -ConfirmAccount 0xYOUR_ACCOUNT
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Uninstall -Id guard -ConfirmAccount 0xYOUR_ACCOUNT
```

Stop disables boot startup before stopping. Uninstall unregisters only the exact owned service and retains the encrypted credential, licence, configuration, journals and transaction history. Credential deletion is a separate explicit `service remove-credential --binding ...` operation after the service is stopped. Do not delete state to bypass an admission/risk error.

## Evidence boundaries

`test/windows-mainnet-loader.ps1` runs real function state transitions with synthetic native boundaries and temporary files under Windows PowerShell 5.1/PowerShell 7. It distinguishes phase-interruption simulation from real power-loss/pre-login reboot evidence. Runtime SCM/DPAPI/Job/stop tests remain owned by the shared native service workflow. The Rust SVC-M1 configuration snapshot and SVC-M2 stop/recovery fixes are required dependencies. No test bypass, alternate verifier pin or plaintext credential route exists in the production entry point.
