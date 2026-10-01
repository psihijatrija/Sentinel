# State Baseline & Reconciliation (Drift Detection) - Design

Implements `./requirements.md`. Adds a **state-driven** detection axis: snapshot -> diff ->
attribute -> observe-only emit, with a reboot-durable baseline. Surface #1 is the loaded-module
inventory of long-lived, low-churn processes.

Authoritative references: `#[[file:../../../docs/constraints.md]]`,
`#[[file:../../../docs/requirements.md]]`.

---

## Components (all new, `Sentinel.Core`)

### 1. `ModuleBaselineStore` - reboot-durable baseline persistence
Mirrors the `kev_cache.json` pattern (System.Text.Json under `%ProgramData%\Sentinel`), NOT
`SecureCacheStore` (whose HMAC key is boot-bound and would invalidate every reboot -> re-flag
everything as new).

```
public sealed class ModuleBaselineStore
{
    public ModuleBaselineStore(string? customPath = null);   // default %ProgramData%\Sentinel\baseline
    public ModuleBaselineSnapshot Load();                    // empty snapshot if missing/unreadable
    public void Save(ModuleBaselineSnapshot snapshot);       // System.Text.Json, restricted ACL
}

public sealed class ModuleBaselineSnapshot
{
    // process name (lower) -> set of normalized module identities
    public Dictionary<string, HashSet<string>> ModulesByProcess { get; set; } = new(...);
    // signer CN (lower) -> first-seen UTC on this machine  (R4 rule 3)
    public Dictionary<string, DateTime> KnownPublishers { get; set; } = new(...);
    // module identity -> "unexplained since" UTC (R3 durable side-ledger)
    public Dictionary<string, DateTime> UnexplainedSince { get; set; } = new(...);
    public int SchemaVersion { get; set; } = 1;
}
```
- File: `%ProgramData%\Sentinel\baseline\module_baseline.json`, dir created with SYSTEM+Admins ACL
  (reuse the ACL helper pattern from `Program.EnsureRestrictedProgramDataDir` / `SecureCacheStore`).
- Load failure -> empty snapshot (learn mode). Save failure -> `LogDebug`, continue (NFR-2).
- Module identity string = `ModuleIdentity.Normalize(path)` (already lowercases, strips `\\?\`).

### 2. `StateReconciliationMonitor : BackgroundService` - the engine
Ctor (DI): `DetectionEngine`, `SignerTrustService`, `ModuleBaselineStore`, `ILogger<T>`.

`ExecuteAsync` (template from `AppDnsExfilMonitor` + `ReinfectionCorrelator`):
```
Load baseline (learn mode if absent)
await Task.Delay(SettleDelay, ct)          // 30s boot-settle, like ReinfectionCorrelator
while (!ct.IsCancellationRequested)
{
    try { await ReconcileOnceAsync(ct); await Task.Delay(Cadence, ct); }  // Cadence >= 5 min
    catch (OperationCanceledException) { break; }
    catch (Exception ex) { _logger.LogDebug(ex, "[StateReconciliation] pass error"); }
}
```

`ReconcileOnceAsync`:
1. Resolve the fixed long-lived process set by name (enumerate `Process.GetProcesses()`, filter to
   the target name set). For each matching PID:
   - `if (!NativeProcessMemory.CanInspect(pid, imagePath)) continue;`  (R1; do NOT touch baseline
     for it - and CanInspect avoids the empty-cache clobber because we simply don't call
     EnumModules).
   - `modules = NativeProcessMemory.EnumModules(pid)`  (two-pass, cross-bitness).
2. For each module not in `baseline.ModulesByProcess[procName]`:
   - Run **attribution** (see below). If attributed -> add to baseline set silently.
   - If unattributable -> emit Tier2 observe (R5), stamp `UnexplainedSince[identity] = now` if new,
     and add to baseline set (so we don't recompute attribution every pass; the durable ledger
     tracks that it's unexplained).
3. Re-emit durable unexplained observations whose last emit is older than `ReEmitCadence` (R6),
   so they can chain in the 60s correlation window.
4. Update `KnownPublishers` with signer CNs of all **attributed/accepted** modules (first-seen
   ledger grows only from trusted acceptances - a surviving-unexplained module does NOT get its
   signer trusted).
5. Save the snapshot.

### 3. Attribution - `TryAttribute(procImagePath, modulePath) -> (bool attributed, string reason)`
Order (cheapest first; reuse existing machinery, R4):
1. `ModuleIdentity.Evaluate(procImagePath, modulePath, DllUnloadEngine-style isMsSigned)` returns
   `Allowed` -> attributed, reason = `"identity:" + verdict.Reason`. This one call already covers
   os-servicing, keep-tree, signed-Program-Files, Roslyn shadow-copy, GPU ICD, app-directory.
2. `ServicingWindow.IsActiveOrRecent()` -> attributed `"servicing-window"`. (Lift
   `FileActivityMonitor.IsServicingProcessActive` into a shared `ServicingWindow` helper; optional
   short recent-grace timestamp.)
3. Signer known on this machine: `signer = SignerTrustService.GetSignerName(modulePath);
   if (signer != null && baseline.KnownPublishers.ContainsKey(signer.ToLower()))` -> attributed
   `"known-publisher"`. (Stolen-cert nuance: a signer *new to this host* is NOT attributed here -
   it must first be accepted via rule 1/2, which is what makes first-seen meaningful.)
Else -> unattributable.

> Note the deliberate asymmetry vs. the DLL-unload engine: reconciliation NEVER acts, so being
> more permissive here (attributing a validly-signed known-publisher module) is safe - the worst
> case is we don't raise an observe signal for a module that is provably from a publisher already
> trusted on this host. Kill authority stays entirely in the existing behavioral engines.

### 4. Emit shape (R5) - copy `AppDnsExfilMonitor`'s observe pattern
```
new DetectionEvent {
  RuleName = "State Drift: Unexplained Module in Long-Lived Process",
  Evidence = $"Process '{proc}' (PID {pid}) has module '{modPath}' not present at baseline; " +
             $"signer={signer ?? "unsigned/untrusted"}; unexplained since {sinceUtc:O}.",
  Reasoning = "State-baseline reconciliation: a module appeared in a normally low-churn system/" +
              "shell process that could not be attributed to OS servicing, a trusted load " +
              "position, or a publisher already seen on this host. Observe-only: this is surfaced " +
              "for review and as correlation fuel, never auto-killed. A validly-signed module " +
              "(including one signed with a stolen certificate) that never behaves terminally " +
              "cannot be deterministically stopped here - see THREAT_MODEL.",
  Confidence = 0.55,
  Tier = DetectionTier.Tier2Indicator,
  AuthorizedResponse = ResponseAction.LogOnly,
  Family = null,
  ProcessName = proc, ProcessId = pid,
  SignalType = SignalType.SuspiciousProcess,
  Metadata = { ["WeakObserveSeed"]="true", ["StateDrift"]="true", ["ModulePath"]=modPath,
               ["Signer"]=signer ?? "", ["UnexplainedSinceUtc"]=sinceUtc.ToString("O"),
               ["HostImagePath"]=procImagePath }
}
```

## DI + lifecycle
- `services.AddSingleton<ModuleBaselineStore>();`
- `services.AddSingleton<StateReconciliationMonitor>();`
- Add `StateReconciliationMonitor` to the **SystemIntegrity** MonitorGroup's monitor list in
  `Program.cs` (NOT a flat `AddHostedService`; matches the group convention). Slow-cadence,
  limited-restart is fine.

## Constants (tunable, `static readonly`)
- `SettleDelay = 30s`, `Cadence = 5 min`, `ReEmitCadence = 30 min`.
- Long-lived process name set: `explorer, winlogon, services, lsass, csrss, dwm, sihost,
  taskhostw, runtimebroker` (start conservative; expand later).

## What this reuses (no reinvention)
- Enumeration: `NativeProcessMemory.EnumModules` + `CanInspect`.
- Attribution: `ModuleIdentity.Evaluate` (whole trust ladder), `SignerTrustService.GetSignerName`,
  lifted `ServicingWindow.IsActive`.
- Persistence: `kev_cache.json`-style System.Text.Json + restricted-ACL dir.
- Emit: `DetectionEngine.EmitAsync`, Tier2/LogOnly contract.
- Correlation: existing 60s PID window; we re-emit to participate.

## Test strategy (see tasks / R-mapping)
Pure-logic tests target `TryAttribute` and the reconcile diff via injected fakes (no live process
enumeration): feed a baseline + a synthetic snapshot, assert which deltas surface. Plus contract
tests: emitted event is Tier2Indicator + LogOnly + Family null; observe-only holds under
`ActiveResponse=true` (route a reconciliation event through `AdvancedResponseEngine`, assert no
destructive action). The "headache-DLL" analogue: an unsigned/new-publisher module injected into
`explorer.exe` surfaces; a signed known-publisher module and a servicing-window module are
suppressed.

## Honesty (NFR-4) - goes in THREAT_MODEL
State reconciliation is a cost-raiser, not a guarantee. It surfaces unexplained persistence in
low-churn hosts regardless of payload behavior, closing the "silent user-directed harm" gap
partially. It cannot catch a payload that blends into a high-churn host's legitimate plugin churn,
and it deliberately does not kill validly-signed modules - those are surfaced for review.
