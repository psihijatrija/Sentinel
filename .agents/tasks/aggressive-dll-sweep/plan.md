# Implementation Plan — Aggressive Unsigned-DLL Sweep + IDS Command-Line Rule

All work happens in the worktree `e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep`
(branch `feature/aggressive-dll-sweep`). Relative paths land in the parent repo — always use
absolute worktree paths. Target framework `net48-windows`. Do NOT bump `version.txt` or run
release/push scripts.

## Design decisions (grounded in the code I read)

- **DllUnloadEngine process-kill routing: DO NOT route through it.** `DllUnloadEngine` is
  injectable (registered `AddSingleton<DllUnloadEngine>()` in both Service and Agent Program.cs)
  and exposes `OnSideloadDllDroppedAsync(string dllPath, int writerPid, string? writerName)`.
  But that method short-circuits unless the file is a *hijack-name* plant
  (`IsHijackPlantPath` → `SideloadTargets` set: dbghelp/version/winmm/…) or a COM-hijack payload
  (`ComHijackEvaluator.ShouldQuarantinePayload`). A generic unsigned `*.dll`/`*.winmd` that is
  not a sideload-target *name* returns a no-op result and never kills anything. There is no
  general "kill every process holding this arbitrary DLL" public API on `DllUnloadEngine`
  (`CheckAndUnloadAsync`/`UnloadInjectedDllAsync` are PID-keyed and gated by `ModuleIdentity`
  on mapped modules, not by "is this unsigned"). So per the task's explicit fallback
  ("if no in-process kill API fits cleanly, quarantine-with-delete-on-reboot alone is
  acceptable"), the sweep relies on `QuarantineManager.QuarantineFileAtomicAsync(path,
  forceQuarantineSigned: true)`, whose MoveFileEx delete-on-reboot handles locked files. We do
  NOT shell out to taskkill (hard constraint). Rationale recorded here so the coder does not
  inject DllUnloadEngine into the new monitor.
- **MonitorGroup: SystemIntegrity** (Service `Program.cs`, `StartDelay = 10s`). The monitor does
  disk-wide scanning, which the constraints forbid in the Critical group (0ms, no heavy I/O at
  startup). SystemIntegrity is the first group that permits it.
- **Service only, not Agent.** The task says register in the Agent only if other PsPortedMonitors
  are registered there. `LnkUncGuard` is NOT registered in the Agent (the Agent only hosts
  `CursorTakeoverMonitor` + `CookieIntegrityMonitor` from that file). The Service is the SYSTEM
  process that performs quarantine. So the sweep monitor is registered in Service `Program.cs`
  only. The IDS rule, by contrast, is registered in BOTH (matching `UnsignedBinaryRule`).
- **ShouldSkipPath strategy: internal static pure predicate** `ShouldSkipPath(string path)` on
  `AggressiveUnsignedDllSweepMonitor`, taking only the path so it is unit-testable with no DI.
  It returns true (skip) when any of: `SecurityValidation.IsOsCriticalPath(path)` (the primary
  safety net — covers the whole `\Windows\` tree except `\Windows\Temp`, plus Defender/WindowsApps/
  PowerShell program dirs); `ModuleIdentity.IsOsServicingPath(path)`; `ModuleIdentity.IsKeepTree(path)`;
  or a case-insensitive substring match against an explicit skip-fragment list:
  `\windows\system32\`, `\windows\syswow64\`, `\windows\winsxs\`, `\windows\servicing\`,
  `\program files\`, `\program files (x86)\`, `\assembly\` (GAC), plus Sentinel's own install dir,
  the quarantine dir, and the honeypot subdir (`HoneypotDllMonitor.HoneypotSubdir`). Compare on
  `Path.GetFullPath(path).ToLowerInvariant()` inside try/catch (return true/skip on error — fail
  closed toward not quarantining). `IsOsCriticalPath` already covers most of these, but the
  explicit list keeps the predicate self-documenting and independently testable, mirroring the
  script's `Should-ExcludeDLLFile`.
- **DetectionCategory for the IDS rule: `SecurityEvasion`.** The IDS patterns are LOLBin/evasion
  command lines (certutil/bitsadmin download, encoded PowerShell, iex, regsvr32 /s, mshta http,
  etc.). `SecurityEvasion` is the closest existing enum value. (`UnsignedBinary` and
  `AttackOnUser` are used by the neighboring rules; `SecurityEvasion` is the honest fit.)
- **Confidence/Tier**: sweep emits `Tier1Behavioral` + `ResponseAction.Quarantine` (mirrors
  `LnkUncGuard`). IDS rule emits `Tier2Indicator` + `ResponseAction.LogOnly`, `Confidence = 0.6`.

## Verification (coder runs these; reviewer reads the recorded evidence, does not re-run)

- Build: `dotnet build e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\Sentinel.sln -c Debug`
- Test:  `dotnet test e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\tests\Sentinel.Tests`
- Both must succeed; new tests must pass. Tests must not require elevation, network, or specific
  filesystem state (use temp dirs only).

---

- [ ] 1. Add the opt-in config flag to `SentinelConfig`.
      Add `public bool EnableAggressiveUnsignedDllSweep { get; set; } = false;` next to
      `EnableHardwarePmuMonitor` / `EnableDynamicSandboxing` (the "Optional modern detection
      extensions" block, ~line 228-233). Default MUST be false. Add a one-line doc comment noting
      it is a deliberate opt-in aggressive non-default mode (disk JSON does not enable it —
      compiled config only).
      Files: `src/Sentinel.Core/Models.cs`
      Verify: part of the Debug build in step 5.

- [ ] 2. Add `AggressiveUnsignedDllSweepMonitor` to the EXISTING `PsPortedMonitors.cs`.
      New `public sealed class AggressiveUnsignedDllSweepMonitor : BackgroundService` added to
      `src/Sentinel.Core/Monitors/PsPortedMonitors.cs` (do NOT create a new file). Model exactly
      on `LnkUncGuard`: ctor-inject `DetectionEngine`, `QuarantineManager`,
      `ILogger<AggressiveUnsignedDllSweepMonitor>`, AND `SentinelConfig` (needed to read the flag;
      inject it — do not `new` it; `SentinelConfig` is DI-registered via
      `services.AddSingleton(config)`). `ConcurrentDictionary<string,DateTime>` alert-cooldown
      keyed by path (OrdinalIgnoreCase), plus a `ConcurrentDictionary<string,byte>` quarantined-
      hash cache so re-detections re-quarantine (mirrors the script's hash cache). `ExecuteAsync`:
      if `!_config.EnableAggressiveUnsignedDllSweep` log "[AggressiveUnsignedDllSweep] disabled"
      and `return` immediately; else log start, `await Task.Delay(settle, ct)` (catch
      OperationCanceledException → return), then the `while (!ct.IsCancellationRequested)` loop
      calling `ScanAllAsync(ct)` with a periodic `Task.Delay(ScanInterval, ct)` — same shape and
      same catch/log discipline as `LnkUncGuard` (every catch logs at Debug minimum).
      Implement:
        - `internal async Task<int> ScanAllAsync(CancellationToken ct = default)` — the testable
          entry point. Enumerates roots, enumerates `*.dll` and `*.winmd`, caps at 500 files per
          drive (`Take(500)`), and for each candidate calls `EvaluateAndQuarantineAsync`.
        - drive enumeration via `System.IO.DriveInfo.GetDrives()` filtered to
          `DriveType.Fixed | Removable | Network` and `d.IsReady`; also add an explicit
          `C:\Windows\System32` pass (as the script does) — note those files will be skipped by
          `ShouldSkipPath` but the pass is kept for parity.
        - `internal static bool ShouldSkipPath(string path)` — the pure predicate described in the
          design section above (IsOsCriticalPath || IsOsServicingPath || IsKeepTree || explicit
          fragment list incl. Sentinel install/quarantine/honeypot dirs). Fail closed on error.
        - signature check: `SecurityValidation.VerifyAuthenticodeSignature(path)` → if validly
          signed, skip; else candidate.
        - remediation: `await _quarantine.QuarantineFileAtomicAsync(path, forceQuarantineSigned:
          true)`. Do NOT reimplement quarantine. The manager still refuses `IsOsCriticalPath`
          internally even with the force flag — that is the safety net; rely on it.
        - emission: on a non-null quarantine result, `await _detectionEngine.EmitAsync(new
          DetectionEvent{ RuleName = "DLL Sweep: Unsigned Module Quarantined", Tier =
          Tier1Behavioral, AuthorizedResponse = ResponseAction.Quarantine, Confidence ~0.85,
          ProcessName="dllsweep", ProcessId=0, SignalType=SignalType.SuspiciousProcess,
          Evidence/Reasoning naming path + signature status + quarantine result, Metadata with
          Path, SignatureStatus, Quarantined, QuarantinePath })` — mirror `LnkUncGuard`'s emit.
          Record the quarantined file hash in the cache. Honor alert-cooldown so the same path is
          not re-emitted within the cooldown window (but a re-dropped file whose hash is in the
          cache re-quarantines).
      All async methods thread `ct`. No static mutable state (the cooldown/hash caches are instance
      `ConcurrentDictionary`). No shelling out. Every catch logs.
      Files: `src/Sentinel.Core/Monitors/PsPortedMonitors.cs`
      Verify: part of the Debug build in step 5; guard logic covered by test step 6.

- [ ] 3. Register the sweep monitor in the Service's SystemIntegrity group.
      In `src/Sentinel.Service/Program.cs`: add `services.AddSingleton<AggressiveUnsignedDllSweepMonitor>();`
      next to the other SystemIntegrity singletons (the block starting ~line 795 with
      `services.AddSingleton<StateReconciliationMonitor>();` etc.), AND add the tuple
      `("AggressiveUnsignedDllSweepMonitor", s => s.GetRequiredService<AggressiveUnsignedDllSweepMonitor>())`
      to the `SafeMonitorResolver.Build(sp, …)` list inside the "Group 5: System Integrity"
      `AddSingleton<IHostedService>` factory (the list that ends with `StateReconciliationMonitor`).
      Do NOT add it to the Critical group. Do NOT register it in the Agent (LnkUncGuard is not in
      the Agent). Follow the exact tuple + singleton pattern already in that group.
      Files: `src/Sentinel.Service/Program.cs`
      Verify: part of the Debug build in step 5.

- [ ] 4. Add `IdsCommandLineRule : IDetectionRule` to `Rules.PathProvenance.cs`.
      New `public class IdsCommandLineRule : IDetectionRule` in
      `src/Sentinel.Core/Rules.PathProvenance.cs` (same file as `UnsignedBinaryRule`). Model on
      `UnsignedBinaryRule`: `Name => "IdsCommandLineRule"`, `[RuleCategory(DetectionCategory.SecurityEvasion)]`
      attribute, `public DetectionEvent? Evaluate(FusedTelemetryContext context)`. Guard:
      `if (context.TriggeringEvent is not ProcessTelemetry pt) return null;` then
      `if (string.IsNullOrEmpty(pt.CommandLine)) return null;`. Match `pt.CommandLine` against a
      `static readonly (string Name, Regex Rx)[]` compiled with
      `RegexOptions.IgnoreCase | RegexOptions.Compiled`, covering the script's patterns:
      certutil -urlcache; bitsadmin /transfer; powershell -enc / -encodedcommand; powershell -w
      hidden; invoke-expression / `iex(`; downloadstring; downloadfile; net.webclient;
      -executionpolicy bypass; wmic process call create; `reg add HKLM...Run`; schtasks /create;
      netsh firewall; sc create; `rundll32 ...dll`; regsvr32 /s; mshta http. On first match return
      `new DetectionEvent { RuleName = Name, Tier = DetectionTier.Tier2Indicator, AuthorizedResponse
      = ResponseAction.LogOnly, Confidence = 0.6, ProcessName = pt.ProcessName, ProcessId =
      pt.ProcessId, SignalType = SignalType.SuspiciousProcess, Evidence = matched-pattern-name +
      truncated command line (cap length, e.g. first ~200 chars), Reasoning = explains it feeds
      the correlation engine }`. Return null when no pattern matches. Regexes are static readonly.
      Files: `src/Sentinel.Core/Rules.PathProvenance.cs`
      Verify: part of the Debug build in step 5; behavior covered by test step 7.

- [ ] 5. Register `IdsCommandLineRule` as a transient `IDetectionRule` in BOTH programs.
      Add `services.AddTransient<IDetectionRule, IdsCommandLineRule>();` right next to the existing
      `services.AddTransient<IDetectionRule, UnsignedBinaryRule>();` in BOTH
      `src/Sentinel.Service/Program.cs` and `src/Sentinel.Agent/Program.cs`. Match that exact
      pattern.
      Files: `src/Sentinel.Service/Program.cs`, `src/Sentinel.Agent/Program.cs`
      Verify: `dotnet build e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\Sentinel.sln -c Debug`
      compiles with no errors.

- [ ] 6. Add `AggressiveUnsignedDllSweepMonitor` guard tests.
      New test file `tests/Sentinel.Tests/AggressiveUnsignedDllSweepMonitorTests.cs` (xUnit,
      `[Fact]`/`[Theory]`, no elevation/network/fixed-FS). Primary tests target the pure static
      `AggressiveUnsignedDllSweepMonitor.ShouldSkipPath(string)`:
        - returns true for OS-critical / system paths (e.g. `C:\Windows\System32\kernel32.dll`,
          `C:\Windows\SysWOW64\x.dll`, `C:\Windows\WinSxS\x.dll`, `C:\Program Files\app\x.dll`),
          asserting it refuses to quarantine them;
        - returns false for a plain user-writable drop path (e.g.
          `C:\Users\x\Downloads\evil.dll`) so the sweep would consider it a candidate.
      Keep it filesystem-light; `ShouldSkipPath` is pure so no temp files are strictly needed.
      Files: `tests/Sentinel.Tests/AggressiveUnsignedDllSweepMonitorTests.cs`
      Verify: `dotnet test e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\tests\Sentinel.Tests`
      — the new guard tests pass.

- [ ] 7. Add `IdsCommandLineRule` tests.
      New test file `tests/Sentinel.Tests/IdsCommandLineRuleTests.cs` following the
      `AttackPatternTests.cs` construction pattern (`new FusedTelemetryContext { ProcessId,
      ProcessName, TriggeringEvent = new ProcessTelemetry { ProcessName, ProcessId, ImagePath,
      CommandLine } }`):
        - malicious command lines (`powershell -enc <base64>`, `certutil -urlcache -f http://evil/x`)
          → `Evaluate` returns non-null with `Tier == DetectionTier.Tier2Indicator` and
          `AuthorizedResponse == ResponseAction.LogOnly`;
        - a benign command line (e.g. `notepad.exe C:\Users\x\doc.txt`) → `Evaluate` returns null;
        - null/empty CommandLine → returns null.
      Files: `tests/Sentinel.Tests/IdsCommandLineRuleTests.cs`
      Verify: `dotnet test e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\tests\Sentinel.Tests`
      — the new rule tests pass (Tier2 LogOnly contract honored).

- [ ] 8. Full build + test gate.
      Run the full build and the full test project; fix any integration seams.
      Verify: `dotnet build e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\Sentinel.sln -c Debug`
      succeeds and `dotnet test e:\Gorstak\Sentinel\.worktrees\aggressive-dll-sweep\tests\Sentinel.Tests`
      reports all tests passing. Do NOT bump `version.txt`; do NOT run release/push scripts.
