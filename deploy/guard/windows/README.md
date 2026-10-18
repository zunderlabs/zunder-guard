# Windows mainnet installation candidate

This machine service, the only Windows route to mainnet, ships in Guard 1.0.2; Guard 1.0 and 1.0.1 on Windows are the per-user installation for paper and testnet. 1.0.2 fixes the three defects that held the service back: `init` now writes the runtime `guard.toml` with the exact ACL service admission requires, the owner-only check maps SDDL aliases such as `SY` (installs run as SYSTEM), and `service run` connects to the SCM dispatcher before admitting its binding, so a refusal is a stopped service with its failure instead of error 1053. The installer also lets Authenticated Users read and list the two shared folders (`%ProgramData%\ZunderGuard`, `%ProgramFiles%\ZunderGuard`, this folder only), which the service re-checks at every start. If anything else later adds an entry to either folder, the service refuses to start (a stopped service, fail closed); the retained helper's `-Action Upgrade` (or `-Action Resume` of a pending setup) rewrites both folders to this form. Its native SCM checks are part of the 1.0.2 gate (row I4).

This machine-service source includes an additive protected Testnet candidate for a future signed release; signed v1.0.1 draft assets remain immutable. It is not yet a native-tested released installer. Do not replace already signed/versioned assets. Publication requires independent code review, Windows 5.1/7 tests, the native service checks and released-image install/upgrade proof. Pre-login reboot is a separate gate.

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

### A refused instance lock

Each helper action takes an exclusive lock file, `%ProgramData%\ZunderGuard\management\<id>.lock` (`<id>` is the instance, `guard` by default). Helpers from 1.0.2 create it owned by Administrators. A helper before 1.0.2 created it with the owner of the process that ran it, which can be your own account (an ordinary desktop console, or Git Bash); every later action then refuses it with `Untrusted machine path owner (protected-path, owner=current-user).` To recover, close every PowerShell window running the helper, then in a plain elevated PowerShell either delete the lock or give it to Administrators:

```powershell
Remove-Item -LiteralPath "$env:ProgramData\ZunderGuard\management\guard.lock"
# or
icacls "$env:ProgramData\ZunderGuard\management\guard.lock" /setowner "*S-1-5-32-544"
```

Deleting it is safe: the lock holds no state, it is only the handle that keeps two helpers apart, and a 1.0.2 helper creates it again with the right owner. A retained helper from before 1.0.2 recreates it with the owner of the process that runs it, so until the instance is upgraded to 1.0.2 run that helper only from a plain elevated PowerShell, never from Git Bash, MSYS or Cygwin. If `icacls` still shows your own account as the lock's owner after such a run (a desktop edition of Windows can default new files to their creator), give it to Administrators again as above before the next action.

`Another helper holds this instance's lock.` means the lock file is held right now: usually another helper still running for this instance (wait for it or close it), or briefly an antivirus scanner reading the new file, in which case simply run the action again.

An interrupted upgrade resumes while disabled using its exact retained transaction/helper. `-Action Recover -Recovery RollbackImage` is limited to a not-yet-started new runtime and an unchanged journal; it restores only the old verified image/binding. It never rolls back accounting/risk journals, configuration or credentials. Old release caches and backups remain until separately reviewed cleanup.

## Stop and uninstall

```powershell
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Stop -Id guard -ConfirmAccount 0xYOUR_ACCOUNT
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Uninstall -Id guard -ConfirmAccount 0xYOUR_ACCOUNT
```

Stop disables boot startup before stopping. Uninstall unregisters only the exact owned service and retains the encrypted credential, licence, configuration, journals and transaction history. Credential deletion is a separate explicit `service remove-credential --binding ...` operation after the service is stopped. Do not delete state to bypass an admission/risk error.

## Evidence boundaries

`test/windows-mainnet-loader.ps1` runs real function state transitions with synthetic native boundaries and temporary files under Windows PowerShell 5.1/PowerShell 7. It distinguishes phase-interruption simulation from real power-loss/pre-login reboot evidence. Runtime SCM/DPAPI/Job/stop tests remain owned by the shared native service workflow. The Rust SVC-M1 configuration snapshot and SVC-M2 stop/recovery fixes are required dependencies. No test bypass, alternate verifier pin or plaintext credential route exists in the production entry point.

`test/windows-download.ps1` runs the loaders' real download loops (`Get-ZgAsset` and the per-user `Get-Asset`) under Windows PowerShell 5.1 and PowerShell 7 against a loopback fixture (`test/download-fixture-server.py`: slow, stalled, cut and reset bodies, refused connections, 404s, an existing destination) and fetches one public HTTPS file with the unmodified functions. Only the test's own copy accepts `http://`, records its pauses and, for the stall cases, uses a shorter read timeout.

## Protected Testnet automation candidate

The additive Testnet SCM path requires a newly signed release and its native Windows gates.
The ordinary per-user interactive Testnet installer remains available. To request the protected
machine-service route, an elevated controller invokes the verified saved loader with explicit
public arguments:

```powershell
& .\i.ps1 -Network testnet -ManagedService -NonInteractive -KeyStdin -Id testnet-journey `
  -Account 0xYOUR_TESTNET_ACCOUNT -ConfirmAccount 0xYOUR_TESTNET_ACCOUNT `
  -Rules zr1_YOUR_RULES -EquityCap 100
```

The controller must start PowerShell with redirected private stdin containing two LF-terminated
API wallet key frames for fresh setup. Rust consumes the first to validate the Testnet wallet's
role and records its public address without using a per-user key store. Rust consumes the second
to provision the existing machine-bound DPAPI protection. PowerShell does not read either key.
Private keys must never appear in command arguments, environment variables, files or logs.
Initial pairing output must stay in private controller memory. Resume consumes only frames for
steps not already committed; inspect the owned transaction before supplying them.

Testnet requires a `testnet-` instance ID, producing distinct state, binary, binding, SCM virtual
account and encrypted credential paths. Its binding and protected transaction identify Testnet;
legacy records without a mode remain Mainnet and cannot be adopted. Mainnet retains its default
ID, hidden interactive setup and explicit consent. Unattended flags never select Mainnet.

Preparation remains stopped with startup Disabled. Fresh Testnet init creates `risk.jsonl` once;
never run `JournalInit` for Testnet. The controller starts the exact retained helper explicitly:

```powershell
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Action Start `
  -Network testnet -Id testnet-journey -ConfirmAccount 0xYOUR_TESTNET_ACCOUNT -Startup DelayedAuto
```

Every subsequent helper action must name `-Network testnet` and the same instance. Upgrade,
stop, recovery and uninstall preserve the existing protections and ownership checks. Readiness
requires the exact owned SCM child and loopback listener, matching account/network/cap, fresh
synchronization, active risk, a ready journal, no kill/error and Testnet fee mode `off`. An expected
licence must be active. No key or Mainnet confirmation environment is forwarded on Testnet.
Neither a halt nor a missing journal is repaired automatically. Use distinct loopback ports if
running multiple instances; the default port can have only one owner.
