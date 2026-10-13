# Implementation Plan — TrustedHostModuleIntegrityMonitor

Target worktree (all paths absolute): `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules`
Step agents' cwd is NOT the worktree — every command below uses an absolute path or `--project`/`-C` with an absolute path.

---

## Design decisions (made here, grounded in the code I read)

These are decisions, not open questions. The implementer follows them.

1. **Scope of registration points — audio APOs + print monitors + print processors (NOT Winsock, NOT the print driver store).**
   - I read `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Core\PrintSpoolerMonitor.cs`. It covers the **filesystem driver store** (`...\System32\spool\drivers\x64\3|4`, `W32X86\3`) for PrintNightmare DLL plants and spooler child processes. It does **NOT** read the registry keys `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\{name}\Driver` or `...\Print\Environments\{env}\Print Processors\{name}\Driver`. A print monitor/processor can register a DLL **by registry value** that points anywhere; PrintSpoolerMonitor never inspects those values. Therefore print monitors and print processors are **in scope** for this new monitor and are **not** a duplicate of PrintSpoolerMonitor. The plan documents this distinction in the monitor's XML doc comment.
   - `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Core\WinsockLspIntegrityMonitor.cs` fully owns the Winsock2 catalog (protocol + namespace LSP providers). This monitor **excludes** Winsock LSP entirely. Documented in the doc comment.
   - Net coverage statement to put in the class doc comment: *covers (1) audio APO FxProperties DLLs, (2) print monitor Driver DLLs, (3) print processor Driver DLLs. Excludes Winsock LSP (WinsockLspIntegrityMonitor) and the print filesystem driver store / PrintNightmare child-process surface (PrintSpoolerMonitor).*

2. **Reuse existing trust primitives — do not reinvent location/signature logic.**
   - Signature: `SignerTrustService.IsSignedFile(path)` + `GetSignerName(path)` (injected), which internally calls `SecurityValidation.VerifyAuthenticodeSignature` with the WinVerifyTrust + catalog-store fallback. Fail-closed: `File.Exists`→false or verify→false means "unsigned/untrusted".
   - User-writable location: `ModuleIdentity.IsUserWritableDrop(path)` (static, already covers Users/AppData/Temp/Downloads/Public and writable Windows subdirs). OS-trusted location: `ModuleIdentity.IsKeepTree(path) && !IsUserWritableDrop(path)` OR `ModuleIdentity.IsProgramFilesTree(path) && !IsUserWritableDrop(path)` OR `ModuleIdentity.IsOsServicingPath(path)`. I read `ModuleIdentity.IsUserWritableDrop` (src\Sentinel.Core\ModuleIdentity.cs line ~245) and confirmed its coverage. ProgramData is treated as user-writable per the task: add an explicit `\programdata\` check in the monitor's own classifier (ModuleIdentity does not list ProgramData), so the plan adds that.
   - **Trust rule (signature/location ONLY, never name):** a registered DLL is EXONERATED only if `IsSignedFile(resolvedPath)` is true, OR the resolved path is in an OS-trusted non-user-writable location as above. Everything else (unsigned, user-writable path, unresolved path) is flagged. No filename or key-name is ever a trust input. Fail closed when the path cannot be resolved to an existing file.

3. **Signal shape — Tier2Indicator / LogOnly, no fake attribution.**
   - Registry-driven DLL registration has no owning PID that userland can attribute, matching `WinsockLspIntegrityMonitor` and `InputIntegrityGuard`. Emit `ProcessName = "SYSTEM"`, `ProcessId = 0`.
   - Per constraints and the task: a newly-registered unsigned/user-writable DLL is **`DetectionTier.Tier2Indicator` + `ResponseAction.LogOnly`**. This is observe fuel; the correlation engine chains it. Never Tier1, never any kill/delete. `SignalType = SignalType.Generic` (the enum has no persistence/registry type; `Generic` is honest — see `Models.cs`). Confidence modest (0.55 unsigned-and-user-writable, 0.45 unsigned-elsewhere, 0.40 user-writable-but-signed) — tuning only; the Tier/response contract is what the tests pin.
   - *Rationale for Tier2 over "Tier1 with AuthorizedResponse=LogOnly":* the task permits either, but Tier2Indicator is the stronger invariant (Tier2 can NEVER act, enforced unconditionally in `AdvancedResponseEngine.HandleAsync`), so it is the fail-safe choice and matches `InputIntegrityGuard`.

4. **Testable seam — pure static classifiers + injected `SignerTrustService` + `AddTestOverride`.**
   - Registry enumeration is wrapped behind a small injectable interface `IRegisteredModuleSource` (default impl reads HKLM via `Microsoft.Win32.Registry`). Tests inject a fake source that returns in-memory `(registrationPoint, dllPath)` tuples — no machine registry, no elevation.
   - Signature determinism uses the existing `SignerTrustService.AddTestOverride(path, isSigned, signer)` (confirmed in `SignerTrustService.cs`) so a test file on disk can be forced signed/unsigned.
   - The flag decision is a **pure static method** `TrustedHostModuleIntegrityMonitor.ClassifyModule(...)` returning an enum/struct, unit-tested with `[Theory]/[InlineData]` exactly like `LolbinCanonicalPaths` tests — no OS state.
   - Detection events come from **`internal static` factory methods** (`BuildUnsignedModuleEvent`, `BuildUserWritableModuleEvent`), tested directly for the Tier/response contract, mirroring `WinsockLspIntegrityMonitor.Build*Event` and `InputIntegrityGuard.Build*Event`.

5. **Polling + lifecycle.** `BackgroundService` (matches every SystemIntegrity-group monitor). 20s startup delay, then baseline the currently-registered DLLs into a `ConcurrentDictionary`, then poll every 45s (within the 30–60s window). Each poll re-reads the three registration-point sets; any key/DLL not in the baseline is evaluated and, if flagged, emitted once (dedup via `ConcurrentDictionary`). ACL-denied reads on audio FxProperties log at `LogDebug` and continue (never crash). Whole poll body wrapped; `OperationCanceledException` breaks the loop. `await Task.Delay(ct)` only.

---

## Ordered implementation items

- [ ] 1. **Add the registry-source seam interface and its default HKLM implementation.**
      Create `IRegisteredModuleSource` with one method returning the current set of registered DLL modules across the three registration points as `IReadOnlyList<RegisteredModule>` (record/struct: `RegistrationPoint` string e.g. `"AudioAPO"`/`"PrintMonitor"`/`"PrintProcessor"`, `KeyPath` string, `RawDllValue` string, `ResolvedPath` string?). Implement `HklmRegisteredModuleSource` that reads, best-effort and read-only:
      (a) audio APOs: enumerate `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render` and `...\Capture`, for each `{endpoint}` open `\FxProperties` and collect the APO CLSID/DLL-bearing values — wrap each endpoint read in try/catch logging `LogDebug` on access-denied (ACL-protected) and continue;
      (b) print monitors: enumerate `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\{name}`, read the `Driver` value;
      (c) print processors: enumerate `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\{env}\Print Processors\{name}`, read the `Driver` value.
      Resolve each raw DLL value to a full path: expand env vars (`Environment.ExpandEnvironmentVariables`); a bare filename for print monitor/processor resolves against `...\System32\spool\{...}` best-effort; `null` ResolvedPath if it cannot be resolved to an existing file (fail-closed downstream). Open registry keys with `writable:false`. No static mutable state.
      Files: `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Core\TrustedHostModuleIntegrityMonitor.cs` (put the interface, the record, and the HKLM impl in this one file alongside the monitor, matching the single-file-per-monitor convention).
      Verify: `dotnet build e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release` — 0 errors (type compiles; no behavior yet).

- [ ] 2. **Add the pure location/trust classifier and the static detection-event factories.**
      In the same file add `internal static ModuleVerdict ClassifyModule(string? resolvedPath, bool isSigned)` where `ModuleVerdict` is an enum `{ Trusted, Unsigned, UserWritablePath, Unresolved }`. Logic (signature/location ONLY, fail-closed): if `resolvedPath` is null/empty or file missing → `Unresolved` (flag); else compute `userWritable = ModuleIdentity.IsUserWritableDrop(resolvedPath) || resolvedPath.ToLowerInvariant().Contains(@"\programdata\")`; `osTrusted = !userWritable && (ModuleIdentity.IsOsServicingPath(resolvedPath) || (ModuleIdentity.IsKeepTree(resolvedPath)) || ModuleIdentity.IsProgramFilesTree(resolvedPath))`; then: if `userWritable` → `UserWritablePath`; else if `!isSigned && !osTrusted` → `Unsigned`; else if `isSigned || osTrusted` → `Trusted`; else `Unsigned`. (A valid signature OR an OS-trusted non-writable location exonerates; nothing else does.)
      Add `internal static DetectionEvent BuildUnsignedModuleEvent(RegisteredModule m, ModuleVerdict v, bool signed, string? signer)` and `BuildUserWritablePathEvent(...)` (or one factory keyed by verdict) returning `Tier = DetectionTier.Tier2Indicator`, `AuthorizedResponse = ResponseAction.LogOnly`, `ProcessName="SYSTEM"`, `ProcessId=0`, `SignalType=SignalType.Generic`, a System.Text.Json-free `Metadata` dict (RegistrationPoint, KeyPath, DllPath, Verdict, Signed, Signer), descriptive `Evidence`/`Reasoning`. No string-built JSON.
      Files: `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Core\TrustedHostModuleIntegrityMonitor.cs`.
      Verify: `dotnet build e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release` — 0 errors.

- [ ] 3. **Implement the `TrustedHostModuleIntegrityMonitor : BackgroundService` body (DI, baseline, poll loop).**
      Constructor injects `DetectionEngine`, `SignerTrustService`, `ILogger<TrustedHostModuleIntegrityMonitor>`, and `IRegisteredModuleSource` (all required). `ExecuteAsync(CancellationToken ct)`: log start; `await Task.Delay(TimeSpan.FromSeconds(20), ct)` (OCE→return); baseline all currently-registered DLL paths into a `ConcurrentDictionary<string,byte>` keyed by `RegistrationPoint|ResolvedPath`; then `while(!ct.IsCancellationRequested)` → try { `await ScanAsync(ct)` } catch(OCE){break} catch(Exception ex){ `_logger.LogDebug(ex, ...)` } then `await Task.Delay(TimeSpan.FromSeconds(45), ct)`.
      `ScanAsync`: get current modules from the source; for each not in baseline and not already alerted (dedup dict), resolve signed via `_signerTrust.IsSignedFile`, call `ClassifyModule`, and if verdict != `Trusted` `await _detectionEngine.EmitAsync(factory(...))`; add to baseline+alerted so it is not re-emitted. Add newly-seen Trusted modules to baseline too (so they are not re-evaluated). Write an `internal Task ScanAsync(CancellationToken)` (internal, so a test can drive one pass deterministically) and have `ExecuteAsync` call it. Thread `ct` through every method. Add a doc comment stating the covered vs excluded registration points per Design decision 1.
      Files: `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Core\TrustedHostModuleIntegrityMonitor.cs`.
      Verify: `dotnet build e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release` — 0 errors.

- [ ] 4. **Register the monitor in the Service composition root via the SystemIntegrity MonitorGroup.**
      In `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Service\Program.cs`: add `services.AddSingleton<IRegisteredModuleSource, HklmRegisteredModuleSource>();` and `services.AddSingleton<TrustedHostModuleIntegrityMonitor>();` in the SystemIntegrity singleton block (near the other `services.AddSingleton<...Monitor>()` lines ~797–827), and add the tuple `("TrustedHostModuleIntegrityMonitor", s => s.GetRequiredService<TrustedHostModuleIntegrityMonitor>())` to the `SafeMonitorResolver.Build(sp, ...)` list inside the `Name = "SystemIntegrity", Category = MonitorCategory.SystemIntegrity` group (the resolver list ending ~line 779). Do NOT use `AddHostedService`. Match the existing `RegistryMonitor`/`WmiPersistenceMonitor` entries exactly.
      Files: `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\src\Sentinel.Service\Program.cs`.
      Verify: `dotnet build e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release` — 0 errors (DI graph resolves at build; group wiring compiles).

- [ ] 5. **Add the unit tests under `tests\Sentinel.Tests\Monitors` matching the existing monitor-test pattern.**
      Create `TrustedHostModuleIntegrityMonitorTests.cs` (namespace `Sentinel.Tests.Monitors`). Model after `InputIntegrityGuardTests.cs` and `WinsockLspIntegrityMonitorTests.cs`. Include:
      (a) `[Theory]` over `ClassifyModule` with `[InlineData]`: unsigned DLL in `C:\Users\...\AppData\Local\Temp\evil.dll` → `UserWritablePath`; unsigned DLL in `C:\ProgramData\x\evil.dll` → `UserWritablePath`; signed DLL in `C:\Windows\System32\apo.dll` → `Trusted`; unsigned DLL in `C:\Windows\System32\new.dll` → `Unsigned`; null/missing path → `Unresolved`. Pass `isSigned` as the bool arg (pure, no OS).
      (b) Factory contract tests: `BuildUnsignedModuleEvent`/`BuildUserWritablePathEvent` return `Tier2Indicator`, `LogOnly`, `KillAuthorized==false`, `ProcessId==0`, `ProcessName=="SYSTEM"` — and assert they are **not** `Tier1Behavioral`.
      (c) `ResponsePolicy.ApplyTierLaw(ev)` keeps the event `Tier2Indicator` + `LogOnly` (static-law pin, like InputIntegrityGuard).
      (d) End-to-end: build a real `DetectionEngine`/`AdvancedResponseEngine` via a `CreateMinimalEngine(tempDir, activeResponse:true)` helper (copy from `InputIntegrityGuardTests`), emit an unsigned-DLL event, assert it stays `LogOnly` after `EmitAsync` even with ActiveResponse enabled (the Tier2-never-acts contract).
      (e) Deterministic monitor pass: a fake `IRegisteredModuleSource` returning one in-memory module whose `ResolvedPath` is a temp file created by the test; use `SignerTrustService.AddTestOverride(path, isSigned:false, "")` on an injected `SignerTrustService` to force unsigned; construct the monitor, call the internal `ScanAsync(CancellationToken.None)`, and assert exactly one Tier2/LogOnly event was emitted (capture via a recording `DetectionEngine` or by reading the JSONL event log the minimal engine writes). Also assert a **signed DLL in an OS-trusted location does NOT emit** (second fake module, `AddTestOverride(path, isSigned:true, "Microsoft Windows")`, path under the real System32 or a path `ClassifyModule` treats as trusted). Tests must not require elevation/network/machine-registry — all state is in-memory + temp files.
      Files: `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\tests\Sentinel.Tests\Monitors\TrustedHostModuleIntegrityMonitorTests.cs`.
      Verify: `dotnet test e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release --filter TrustedHostModule` — all new tests green.

- [ ] 6. **Full-build + targeted-test gate and no-regression check.**
      Confirm the whole solution builds in Release and the new tests pass, and that no NEW test failures were introduced (the suite has 2 PRE-EXISTING unrelated `TlsCertificateMonitorTests` failures — do not touch them, do not count them as new).
      Files: none (verification only).
      Verify:
      `dotnet build e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release` → 0 errors;
      then `dotnet test e:\Gorstak\Sentinel\.worktrees\trusted-host-modules\Sentinel.sln -c Release --filter TrustedHostModule` → green.
      Optionally run the broader monitor tests to confirm no regressions, but the only pre-existing failures permitted are the 2 `TlsCertificateMonitorTests` ones. Do NOT edit `version.txt`; do NOT run any release/push script.

---

## Constraints checklist (the implementer must satisfy all)

- Userland only; no kernel/syscalls/self-hiding. (Registry reads via `Microsoft.Win32.Registry`, read-only.)
- Tier2Indicator + LogOnly unconditionally; never kill, never delete a registry key or DLL. Correlation engine chains.
- Trust by signature OR OS-trusted non-user-writable location ONLY; never by name/key-name. Fail closed on unresolved path/signature.
- DI: `DetectionEngine`, `SignerTrustService`, `ILogger<T>`, `IRegisteredModuleSource` all constructor-injected.
- `CancellationToken` through every async method; `await Task.Delay(ct)`, never `Thread.Sleep`.
- No static mutable state — baseline/dedup via `ConcurrentDictionary`.
- No silent catch — every catch logs ≥ `LogDebug`; poll body wrapped; ACL-denied audio reads log + continue; a failing scan never crashes the host.
- Any file reads use `FileShare.ReadWrite | FileShare.Delete` (signature verification already does; if the monitor opens a DLL directly, use these share flags).
- `System.Text.Json` only; no string-built JSON (use the `Metadata` dictionary).
- No security theater — classification works against a renamed binary because trust is signature/location, not name.

## Gaps / assumptions

- The task's referenced findings file lives at `e:\Gorstak\Sentinel\.agents\tasks\perception-io-gap-findings.md` (main repo), not inside the worktree; it documents a different monitor investigation but accurately captures the IMonitor/BackgroundService + DetectionEngine.EmitAsync + DetectionEvent + MonitorGroup contract used above. Assumption: that contract is authoritative and unchanged in the worktree (verified against the worktree's `Models.cs`, `Program.cs`, `SignerTrustService.cs`, `WinsockLspIntegrityMonitor.cs`).
- Exact audio APO FxProperties value names/format for the backing DLL vary by endpoint; the HKLM source reads them best-effort and resolves CLSID→DLL where present, logging and continuing on anything unreadable (ACL or format). This is graceful degradation, not a correctness gap for the Tier/response contract the tests pin.
- `ProgramData` is added as a user-writable location in the monitor's own classifier because `ModuleIdentity.IsUserWritableDrop` does not list it; this matches the task's explicit "ProgramData" instruction.

---

## Verification note (implementation iteration 1)

Implemented `TrustedHostModuleIntegrityMonitor` per this plan. Scope as decided: audio APOs + print monitors + print processors; excludes Winsock LSP (WinsockLspIntegrityMonitor) and the print filesystem driver store / PrintNightmare surface (PrintSpoolerMonitor). Registered in `src\Sentinel.Service\Program.cs` SystemIntegrity MonitorGroup (AddSingleton + SafeMonitorResolver tuple), not a flat AddHostedService. `IRegisteredModuleSource` + `HklmRegisteredModuleSource` registered for DI.

Implementation detail vs plan: `ClassifyModule` is a pure path+signature function and does NOT re-`File.Exists` the path — the module source only populates `ResolvedPath` when the file exists (`ResolveDllPath` returns null otherwise), so a path reaching the classifier is already a real file; null/empty → `Unresolved` (fail-closed). This keeps the classifier deterministically unit-testable with representative paths and preserves the fail-closed contract.

Commands run from `e:\Gorstak\Sentinel\.worktrees\trusted-host-modules`:
- `dotnet build Sentinel.sln -c Release` → **Build succeeded, 0 Error(s)**.
- `dotnet test Sentinel.sln -c Release --filter TrustedHostModule --no-build` → **Passed! Failed: 0, Passed: 19, Skipped: 0, Total: 19**.
- `dotnet test Sentinel.sln -c Release --no-build` (full suite) → **Failed: 2, Passed: 2662, Total: 2664**. The only 2 failures are the PRE-EXISTING unrelated `TlsCertificateMonitorTests` (`AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored`, `AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence`) — not touched, no new failures introduced.

`version.txt` NOT bumped; no release/push script run.
