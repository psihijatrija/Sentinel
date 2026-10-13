# Input Integrity — Verification Note

Branch: `feature/input-integrity`
Worktree: `e:\Gorstak\Sentinel\.worktrees\input-integrity`
Target framework: `net48-windows` (product), xUnit test project.

This note records exactly what was run and the results so the reviewer does not need
to re-run anything.

---

## What changed

1. **New monitor `InputIntegrityGuard`** — `src/Sentinel.Core/InputIntegrityGuard.cs`
   (a `BackgroundService`, matching `ClickjackingGuard`). One monitor, three behavioral
   sub-detectors, **all emitted Tier2Indicator / LogOnly**:
   - (a) **Synthetic input injection** — low-level keyboard (`WH_KEYBOARD_LL`=13) + mouse
     (`WH_MOUSE_LL`=14) hooks installed on a **dedicated STA thread with its own
     `GetMessage`/`TranslateMessage`/`DispatchMessage` pump** (never the Agent STA pump).
     Callbacks inspect `KBDLLHOOKSTRUCT.flags & LLKHF_INJECTED (0x10)` and
     `MSLLHOOKSTRUCT.flags & LLMHF_INJECTED (0x1)`. A configurable burst of injected events
     within a sliding window is the signal. Behavioral, name-free. `ProcessId = 0` with
     Reasoning stating the source is not attributable from the hook struct (no faked
     attribution). `SignalType.PhantomKeystroke`, Confidence 0.45.
   - (b) **Keylogger-hook / raw-input heuristic** — documents honestly that userland cannot
     enumerate installed hook owners / raw-input pollers (no supported API; a PE-import name
     match is attacker-controllable theater) and emits the strongest *feasible* behavioral
     heuristic instead: a sustained cumulative stream of OS-flagged injected input.
     Tier2/LogOnly, Confidence 0.40.
   - (c) **Clipboard scraping / ClipBanker** — `AddClipboardFormatListener` on a hidden
     **message-only window** (`HWND_MESSAGE`) on the same dedicated thread; flags a rapid
     write-replace of clipboard contents (classic crypto-address swap). Observes **timing
     only**, never reads clipboard contents; `ProcessId = 0`. Tier2/LogOnly, Confidence 0.50.
   - DI (`DetectionEngine`, `ILogger<InputIntegrityGuard>`), `CancellationToken` threaded,
     `ConfigureAwait(false)` throughout, graceful-degradation wrapper so a failure never
     crashes the host, no silent catches (all log >= Debug), no attacker-controllable trust,
     no destructive response.

2. **Agent registration** — `src/Sentinel.Agent/Program.cs`
   - Replaced `services.AddHostedService<PhantomKeystrokeGuard>()` with
     `services.AddHostedService<InputIntegrityGuard>()` (flat `AddHostedService`, matching the
     Agent's user-session convention).
   - Registered the previously-dead `services.AddHostedService<AcousticThreatMonitor>()`
     alongside its user-session peers. Its only ctor deps (`DetectionEngine`, `ILogger`) are
     already in the Agent container and NAudio ships with `Sentinel.Core`, so it is
     satisfiable with no extra wiring. **Its detection logic was not changed.**

3. **PhantomKeystrokeGuard removed** — `src/Sentinel.Core/UserSessionMonitors.cs`
   - Deleted the `PhantomKeystrokeGuard` class. Its documented `WH_KEYBOARD_LL`/`LLKHF_INJECTED`
     behavior was never implemented; the real code only name-matched
     `sendinput`/`autoit`/`nircmd`/`inputsimulator` binaries in `\Temp\`/`\Downloads\` and
     issued `KillProcessTree` on that attacker-controllable filename trust — forbidden security
     theater. No legitimate behavior to fold; the genuine injected-flag detection now lives in
     `InputIntegrityGuard`. A short note was left at the former class site.
   - Removed its DI registration (see #2). Grep confirms no remaining product references.

4. **Tests** — `tests/Sentinel.Tests/`
   - Deleted obsolete `Monitors/PhantomKeystrokeGuardTests.cs`.
   - Added `Monitors/InputIntegrityGuardTests.cs`:
     - `AllSignals_AreTier2Indicator_NotTier1` (all four factory events) — proves Tier2, not Tier1.
     - `AllSignals_AreLogOnly_AndNotKillAuthorized` — proves LogOnly + `!KillAuthorized`.
     - `AllSignals_DoNotFakeAttribution` — proves `ProcessId == 0`, `ProcessName == "unknown"`,
       `SignalType.PhantomKeystroke`.
     - `TierLaw_KeepsSignals_Tier2AndLogOnly` — runs `ResponsePolicy.ApplyTierLaw` and proves
       the signal stays Tier2/LogOnly (never kill-promoted).
     - `Tier2_StaysLogOnly_ThroughResponseEngine_WithActiveResponse` — drives an injected-burst
       event through the real `DetectionEngine`/`AdvancedResponseEngine` with
       `ActiveResponse = true` and confirms it stays LogOnly (the docs/constraints.md Tier2
       contract). No live system access.
     - `Guard_Lifecycle_StartsAndStopsCleanly` — starts/stops the BackgroundService; proves the
       hook thread + message pump come up and tear down without crashing. No elevation/network.
   - **Unrelated pre-existing compile fix (behavior-preserving, test-only):**
     `ParentPidSpoofDetectorTests.cs` called `ShouldDemotePpidToLogOnly(...)` with a named arg
     `allowlistedNameUnresolvedPath:` that does not exist on the shipped method (its parameter
     is `allowlistedDevTool`), breaking the whole test assembly. Renamed the arg at all three
     call sites. The third test asserted behavior the shipped method does not have (that a
     resolved path overrides the allowlisted-dev-tool demote); per parent-session direction the
     demote is unconditional **by design** (never kill real git/gh mid-push), so that test's
     name/comment/assertion were corrected to match SHIPPED behavior
     (`ShouldDemotePpidToLogOnly_AllowlistedDevTool_DemotesRegardlessOfPath`, `Assert.True`).
     **No ParentPidSpoofDetector product code was changed.**

---

## Commands run and results

### Build (Release, whole solution)
```
dotnet build e:\Gorstak\Sentinel\.worktrees\input-integrity\Sentinel.sln -c Release
```
Result: **Build succeeded. 0 Warning(s), 0 Error(s).**
All projects built: Sentinel.Core, Sentinel.Agent, Sentinel.Service, Sentinel.Tests,
Sentinel.AutoRotate, Sentinel.MlTrainer.

(Confirms the solution still builds with `PhantomKeystrokeGuard` removed — no dangling
references.)

### Targeted tests (new + the fixed unrelated file)
```
dotnet test tests\Sentinel.Tests\Sentinel.Tests.csproj -c Release --no-build \
  --filter "FullyQualifiedName~InputIntegrityGuard|FullyQualifiedName~ParentPidSpoof"
```
Result: **Passed! Failed: 0, Passed: 35, Skipped: 0, Total: 35.**

### Full test suite
```
dotnet test tests\Sentinel.Tests\Sentinel.Tests.csproj -c Release --no-build
```
Result: **Failed: 2, Passed: 2643, Skipped: 0, Total: 2645.**

The only 2 failures are **pre-existing and unrelated** to this branch's work:
- `TlsCertificateMonitorTests.AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored`
  ("got 0.65")
- `TlsCertificateMonitorTests.AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence`
  ("got 0.65")

Both are TLS-certificate scoring-threshold assertions in `TlsCertificateMonitorTests.cs`
(last touched by commit `46aaa18 chore: update`). This branch changed no TLS, certificate,
or scoring code — `git status` shows the only modified/added files are
`InputIntegrityGuard.cs`, `Program.cs`, `UserSessionMonitors.cs`,
`InputIntegrityGuardTests.cs`, `ParentPidSpoofDetectorTests.cs`, and the deleted
`PhantomKeystrokeGuardTests.cs`. The TLS failures therefore pre-date and are independent of
this work.

---

## Constraint compliance checklist

- Userland only; low-level hooks (`WH_*_LL`) are userland-allowed. No kernel driver. ✔
- All InputIntegrityGuard signals Tier2Indicator / LogOnly. ✔ (test-verified)
- No destructive response; observe-until-chain preserved (monitor only emits honest signals). ✔
- No attacker-controllable trust; detection is behavioral (injected flags, clipboard timing),
  never name/path based. ✔
- DI everywhere; `CancellationToken` threaded; `ConfigureAwait(false)`; no static mutable state
  (`ConcurrentQueue`/`Interlocked`); no silent catch; graceful degradation. ✔
- Dedicated hook thread with its own message pump; no async continuations on the Agent STA
  context; no `ShowBalloonTip`/toast calls. ✔
- `System.Text.Json` only (no string-built JSON); no string interpolation into shell commands. ✔
- No `version.txt` bump; no release/push script run. ✔
```
