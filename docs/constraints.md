# Sentinel - Constraints

**Version: 2.5.6**

---

## Hard Rules " Never Violate

| Constraint | Rationale |
|-----------|-----------|
| No kernel drivers | Keeps the tool transparent, safe, and installable without admin trust |
| No direct syscalls | Maintains standard Windows API contract; no bypass of security boundaries |
| No persistence mechanisms | The tool must not survive reboots unless the user explicitly installs it as a service |
| No self-hiding behavior | Must be visible in process list, task manager, and event logs |
| No string-built JSON | All JSON output via `System.Text.Json` serialization only " no concatenation |
| No `Thread.Sleep` without cancellation | All waits must respect `CancellationToken` |
| No static mutable state | All shared state via `ConcurrentDictionary`, `Channel<T>`, or `SemaphoreSlim` |
| No shelling out to system tools | No `Process.Start("cmd.exe", ...)` for detection or response logic |
| Tier2 can never trigger action | Enforced unconditionally in `AdvancedResponseEngine.HandleAsync` " no exceptions, no config override |
| Active response armed, observe-until-chain default | `ActiveResponse` stays true so chain-confirmed nukes can fire. Default `ObserveUntilChain=true` demotes all single-signal actions to LogOnly. `EnforceActiveResponse` is **locked `true`** and marked `[Obsolete]` - it cannot be set to false (v2.5.5+). |
| Observe-until-chain (v1.8.6) | Kill / quarantine / isolate / host mutation ONLY after multi-signal or composite proof of a **kill-grade terminal**: token theft, credential dump, reverse shell, C2 beaconing. **v2.5.2/2.5.3 exception:** `IsAttackClassTerminal` (mesh/webhook, potato, kernel EoP loader, ClickFix, Hell's Gate, unmapped thread, CS pipes, classic RAT ports, tunneling tools, impostor AMSI, **ALLOCVM_REMOTE** v2.5.6) solo-confirms at >= 0.85 on PID > 4. **v2.5.4:** cross-PID staged attacks accumulate in a shared `RootBuffers` ancestry buffer - `ResponsePolicy.GetAttackRootPid` walks the ancestry cache to find the attacker's non-system loader; all its children's signals count together. Enforced in `ResponsePolicy` + `AdvancedResponseEngine`. Steam DirectX / System32 redistributable writes are never terminal. Skip lists are **identity** (path or Authenticode), never a stolen process name. |
| Tier1 = kill-grade only | `ResponsePolicy.ApplyTierLaw`: Tier1 only for high-confidence (>=`MinTier1Confidence`, default 0.85) token theft / cred dump / reverse shell / C2, or multi-signal composites that prove those. **Exception:** `DLL Injection: Foreign Module Unloaded` is permanent Tier1 LogOnly (already unloaded; never demote, never kill-promote). All other monitor signals are Tier2 + LogOnly observe fuel. Critical score alone must not promote noise to Tier1. |
| DirectX / redist = Tier2 observe only | Steam DirectX, VC++, GPU redistributables may emit **1-2 Tier2** signals (e.g. System32 write). They must **never** be Tier1, never chain-seed, never composite legs (`IsBenignInstallerNoise` / `IsNonCorrelatingObserveNoise`). |
| Weak observe seeds never chain-nuke (v1.9.3) | Cast observe, module-count growth, screen/UX heuristics, outbound-whitelist noise (`IsWeakObserveSeed` / `IsPureUxObserveNoise`) never classify as terminal and never fill the PID chain buffer. Pure UX also skips composites. Attack-adjacent weak signals (SeImpersonate, PPID) may still feed composites but not alone complete a chain nuke. Terminal chain legs require conf >= `MinTier1Confidence`. |
| Chain-confirmed packs always (v1.9.3) | When a chain-confirmed nuke fires, `AutoIncidentReporter` MUST write a sealed evidence pack. Do not drop packs because the seed rule had low confidence or local-only kill flags. |
| Digital coercion toolkit = host tools only (v1.9.4) | Defend remote-control, stalkerware, session-theft, exfil toolkits used in online harassment/sexual coercion. NEVER claim chat moderation, offender identity, or offline sexual assault detection. Marketing and packs must stay technical. |
| Graceful degradation on barebone Windows (v1.9.5) | Optional features (Windows Event Log, ETW, toast, TI proxy, custom channels) MUST fail soft: disable permanently for the process after hard failure, keep JSONL + core detection, never throw out of response/pack/service paths. Prefer Application log over custom Event Log channels. |
| Windows Event Log = critical only (v1.9.5) | When Event Log is available, write lifecycle + chain response + pack + heartbeat only. Never flood with Tier2 observe. Rate-limit writes. |
| Never ASR-block our own installer (v1.9.6) | Do not enforce Defender ASR `c1db55ab` (advanced ransomware protection) in Block - it breaks Inno TEMP extract and is not "Sentinel is ransomware". Delete if present; keep ASROnlyExclusions for install dir. |
| **HARDENING IS ALWAYS-ON (v2.5.5)** | IPSec port lockdown, ASR Block rules, RPC/DCOM firewall, remote session guard, registry hardening, credential hardening (LSASS PPL, WDigest off), browser hardening, and LGPO security policy run on every Sentinel startup. `RestrictivePortHardening` is always `true`; the setter is a no-op. `ProductPosture.AllowsProactiveHostLockdown` always returns `true`. There is no work-first mode. **`IsAttackClassTerminal` exceptions:** Campaign-IOC filename carve-out  `SecurityPDF.exe` / `Afd4Eop12_x64.dll` are excluded from skip lists. |
| Never FreeLibrary OS servicing (v1.9.8) | `DllUnloadEngine` must not unload/quarantine DismHost, TrustedInstaller, TiWorker, NTLite, or modules under NLTmpScratch/WinSxS/CBS. Temp load is only hostile for classic sideload **target names** (version.dll, ...), not every Temp DLL. |
| DLL unloaders exempt | `DllUnloadEngine` remediates immediately on **identity failure** (foreign path, user-writable drop, unsigned sideload plant) and on proven sideload load. Module *count* is not a signal. All other monitors observe until chain. |
| Module identity unload is permanent (v2.2.7 / v2.4.6) | `MemoryBehaviorAnalyzer` + `ModuleIdentity` + `DllUnloadEngine` scan **every mapped PE** (startup `EnumModules` baseline + Kernel-Process ImageLoad). Authenticode/`Evaluate` is first-sight per `(pid, path)` - not a 5s re-hash of every image. Foreign mapped PEs are FreeLibrary-APC unloaded immediately. Hijack-name plants (`dbghelp`/`version`/...) outside the OS tree are **quarantined on drop** (file only, no process kill, no same-name stub). `DLL Injection: Foreign Module Unloaded` and `DLL Sideloading: Hijack-Name Plant Quarantined` are **permanent Tier1**. **No config flag** may disable this. Games/anti-cheat skip is **handle safety only** (no VM_READ) - disk plants in steamapps are still quarantined. Never FreeLibrary lsass/csrss/wininit/DISM/NTLite. |
| Adversarial mindset: no attacker-controllable trust | Sentinel exists to defeat attackers, so no "allow" path may rest on a signal the attacker controls. A filename, filename prefix, or folder name **alone** must never self-authorize a module. Filename/prefix/vendor-folder trust (GPU ICDs like `nvapi*`/`amdocl*`/`igc64*`, servicing names, `\amd\`/`\intel\`/`\nvidia corporation\` trees) MUST be combined with a non-attacker-controllable anchor: a trusted-root load location (OS keep-tree / Program Files) that is **not** user-writable, a valid Authenticode signature, and/or a proven legitimate loading host (e.g. Roslyn/SDK build host for `.nuget\packages` and analyzer shadow-copy). Any default-writable directory is a **drop, not a trusted tree** - including writable subdirs *under* the Windows root (`Windows\Tasks`, `Windows\tracing`, `Windows\registration\CRMLog`, `System32\spool\drivers\color`, `System32`/`SysWOW64` `Tasks`/`COM\dmp`/`FxsTmp`, `Windows\PLA\*`, `Windows\debug\WIA`) and the per-user `.nuget\packages` cache. In a keep-tree writable drop, only Microsoft-signed / Authenticode-trusted modules are spared; sideload names are always denied. When adding any new allow rule, first ask "how does an attacker abuse this?" and close that path before merging. Fail closed. |
| Silent observe (v1.8.6 / v1.9.3) | `SilentObserve=true`: no toasts / auto evidence packs until chain-confirmed. Detection logging always continues. Chain-confirmed nukes always produce packs + critical toast. |
| Observe-first for user activity (v1.8.3) | Weak single-signal heuristics (shell+port, Downloads network, SeImpersonate alone, cloud-sync tools) MUST be LogOnly. IPSec default MUST be attack-only ports - not SSH/RDP/SMB. Full lockdown only via `RestrictivePortHardening`. |
| Observe-first: no touch until proven malicious | Detection scanners stay fully armed. Single-signal identity/path noise -> LogOnly. Proven terminal chains -> full nuke. Games: skip process-memory handles only (Denuvo) - fail-closed when path unresolved. |
| Process-memory defenses stay armed | Do not disable Hell's Gate, injection, ETW-patch, or DLL unload **capability**. Workaround for Denuvo: skip handle opens via `IsGameOrAntiCheatPath` / `IsGameOrAntiCheatProcess` only - **fail closed** when image path is unresolved (no `PROCESS_VM_READ` on unknown PIDs). `OpenRemoteHandle` must refuse `VM_READ` unless `CanInspect` passes. Name/path skips are **not** trust grants. Workaround for AV PE-import heuristics: `NativeProcessMemory` dynamic resolve - never gut the feature. Do not "fix" Denuvo by turning off system-wide module identity. |
| All file reads use `FileShare.Delete` | All file I/O opens with `FileShare.ReadWrite | FileShare.Delete` - Sentinel never blocks user file deletion, even during active scanning or hashing. Only exception: intentional DLL lock files from response actions. |
| Monitors registered in groups | All background monitors must be registered via `MonitorGroup` with appropriate priority, start delay, and restart policy - no flat `AddHostedService` for monitors. |
| Monitor source files match groups | Each monitor class lives in the group file it belongs to under `Monitors/` (CriticalMonitors.cs, CoreDetectionMonitors.cs, etc.). No monolith files - new monitors go into their group file. |
| No user-session response mode toggle | The Agent MUST NOT expose any mechanism (menu item, API, named pipe, etc.) to disable ActiveResponse from user-level context. Only the Service (SYSTEM) controls response mode. |
| No async/await on STA thread | The Agent's WinForms STA message pump MUST NOT have async continuations posted to its SynchronizationContext. All background work (log tailing, file I/O, network) MUST run on dedicated `Thread` instances or `Task.Run` with `ConfigureAwait(false)`. Violations freeze the tray icon. |
| No Win32 notification API calls | `ShowBalloonTip` and toast notification APIs MUST NOT be called - `WpnService` is removed by hardening. These calls silently deadlock the STA pump without throwing. |
| Critical group: no heavy I/O at startup | Monitors in the Critical group (0ms start delay) MUST NOT perform registry enumeration, subprocess spawning, or disk-wide scanning in their constructor or early `ExecuteAsync`. Heavy-I/O monitors belong in SystemIntegrity (10s delay) or later groups. |
| Absence != safety in reputation | Hash reputation services MUST return `Unknown` (not `Safe`) when a hash is absent from all databases. Only a positive trust signal (e.g., CIRCL trust > 60) can confirm Safe. |
| No string interpolation into shell commands | All PowerShell/cmd invocations MUST use `-EncodedCommand` or `ArgumentList` - never string-interpolate untrusted data into `-Command` strings. |
| Minimum-privilege process handles | `OpenProcess` calls MUST request only the access rights actually used. Never open with `PROCESS_ALL_ACCESS` unless every right is exercised. |
| Signed threat report requests | All outbound threat intelligence reports MUST be HMAC-signed with the installation entropy key. Unsigned requests to the proxy are forbidden. |
| Validate all external process output | Data from `Process.Start` stdout (docker inspect, netsh, sc.exe, etc.) is untrusted. MUST be validated before use in subsequent commands or logic. |
| Compiled config only | Operational defaults and the threat-proxy HMAC live in the binary. Disk JSON is not loaded. Uninstall is the off switch. |

---

## Detection Integrity Constraints (v1.1.0)

| Constraint | Rationale |
|-----------|-----------|
| No placeholder/fake data in detection rules | If a hash list, IOC set, or signature database isn't real, remove it. False confidence is worse than no feature. |
| No filename-based primary detection | Process names are trivially spoofed. Filename lists are metadata enrichment / observe fuel only, never a President's Law kill (v2.2.0: `EdrKillerDetectionMonitor` is LogOnly). |
| No security theater features | If a feature doesn't work against an attacker who reads the source code, it must be removed or honestly documented as limited. |
| Settings is native (v2.2.2) | Tray Settings opens `AgentDashboardForm`. Do not ShellExecute `http://` for Settings. The localhost web dashboard is not started. |
| Kernel CVEs are OS patches (v2.2.3) | Do not claim to patch `afd.sys` / Cloud Files Mini Filter / User Profile Service. Hunt the userland campaign and toast KEV posture. Do not disable OneDrive or WinSock. |
| Generic CVE-class, not one detector per CVE (v2.2.4) | New Patch Tuesday bugs are covered by exploit-host / MOTW / installer / KEV-match sensors. Do not add a named campaign pack as the only coverage for a kernel EoP. |
| Monitor types live in `Sentinel.Core` (v2.2.4) | The `Monitors/` folder is layout. Do not put runtime monitor classes in `Sentinel.Core.Monitors` (that hid V217 types behind a second using). |
| Dashboard Referer is not auth (v2.2.0) | If the HTTP dashboard is ever re-enabled: authenticate with a bearer token. A client-controlled `Referer` header never grants access. Secrets are not embedded in `GET /`. |
| No self-sideload decoys (v2.2.0) | Honeypot `version.dll` / `winhttp.dll` / `winmm.dll` MUST NOT be planted in the Sentinel exe directory. Decoys live in `{install}\honeypot\`. |
| Game reputation skip is not a trust grant (v2.2.0) | `ShouldSkipReputationForGamePath` refuses user-profile / Temp / Downloads / Desktop trees. Memory-inspect skip (`IsGameOrAntiCheatPath`) is separate and is not a reputation skip. |
| Kiosk LGPO must not weaken the host (v2.2.0) | `GSecurity.inf` must not set password length 0, complexity off, all audit off, or force FIPS off. |
| Behavioral signals only for kill authority | President's Law rules must detect what processes DO (API calls, file operations, network behavior), not what they ARE (name, path, hash). |
| Hash reputation via live API only | Static hash lists in source code are immediately visible to attackers and impossible to keep current. Use HashReputationService (3-API lookup) instead. |

---

## Transparency Requirements

- Must not hide itself from the process list, task manager, or ETW
- Must not self-replicate or copy itself to other locations
- Must be fully user-controlled " no autonomous behavior beyond what is configured
- All actions taken (including process kills) must be logged before execution

---

## Code Quality Constraints

- **Dependency Injection** required for all services " no service locator, no `new` for injected dependencies
- **CancellationToken** must be threaded through every async method
- **All disposable objects** must implement `IAsyncDisposable` and be disposed in `StopAsync` / `DisposeAsync`
- **No silent exception swallowing** " every `catch` block must log the exception (debug level minimum)
- **Graceful degradation** " if a monitor fails to start, log the error and continue; do not crash the host

---

## Testing Constraints

- Every Tier1 rule must have at least one test that verifies it fires and returns `Tier1Behavioral`
- Every Tier2 rule must have at least one test that verifies it returns `Tier2Indicator`
- The `ResponseEngine` Tier2 contract must be verified by automated test: Tier2 detection with `activeResponseEnabled: true` must still produce `LogOnly`
- Composite detection rules must be testable with a mock `IDetectionEngine` (no live system access)
- Tests must not require elevation, network access, or specific file system state

---

## Deception Constraints (v1.7.0)

| Constraint | Rationale |
|-----------|-----------|
| Deception time budget: 2 seconds maximum | Kill must never be significantly delayed by deception. Attacker is still active during deception window. |
| Deception failure never prevents kill | Deception is a bonus, not a gate. All tactic failures are caught and logged; kill proceeds unconditionally. |
| Never deceive own PID or PID  4 | Self-protection and system stability. Deception targets only confirmed malicious processes. |
| No deception on Tier2 detections | Deception only fires on President's Law kills. Tier2 is log-only " no action of any kind. |
| Beacon flooding only targets public IPs | Never flood private/loopback addresses. Prevents accidental DoS of local services. |
| All deception actions logged before execution | Full forensic trail. User can review exactly what was done and revert if needed. |
| Environment poisoning is HKCU-scoped only | Never modify HKLM (system-wide). Limits blast radius to the compromised user session. |
| Honeypot files use non-standard names (.bak, backup) | Prevents confusion with real credentials. Legitimate applications won't read these files. |
| Sparse files and symlinks are deployed in hidden/cache directories | Minimizes user-visible filesystem clutter. |
| Ransomware bypasses deception | Ransomware kills proceed instantly without running deception tactics to minimize file encryption damage. |
| Thread suspension for context queries | Thread context queries on x64 must suspend target threads to avoid random access violations or stack corruption. |
| Async execution for network/off-host deception | Network-based deception (BeaconFlooder, NetworkHoneypotDeployer) must run asynchronously in the background so they do not block process termination or exhaust the pre-kill budget. |

---

## Operational Constraints

- Must run on Windows 10 / Windows Server 2019 or later
- Must target `net48-windows` for product binaries (Core / Service / Agent / Tests)
- Optional offline tools may target modern TFMs (e.g. MlTrainer `net10.0-windows`) without changing product runtime
- Must function as a standard user (reduced capability, no crash)
- Must function as an elevated user (full capability)
- Log files must not grow unbounded - rotation required (20 MB / 5 files for `events.jsonl`)
- Detection deduplication required - same signal must not flood the log
- File reputation verdicts must not pollute user/system directories with adjacent `*.sentinel_verdict` sidecars; use central ProgramData cache (and optional NTFS ADS only)


