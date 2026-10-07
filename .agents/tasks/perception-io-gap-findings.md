# Perception / Read-Write-to-User I/O Gap — Findings Report

READ-ONLY investigation. No source code was changed. All paths are relative to `e:\Gorstak\Sentinel`.

---

## 1. Summary answer (read first)

The user's literal fear (remote mind-reading / mind-writing via fMRI-style brain decoding) is not physically realizable remotely, so there is no monitor to build for it and none should be faked (that would be "security theater", explicitly banned by `docs/constraints.md`). The defensible mapping is the **credential-capture ("read the user") and perceptual-manipulation ("write to the user") I/O channel**, and Sentinel already covers most of it. The honest coverage picture:

**Already covered (real detectors that run):**
- Credential "read": `CredentialCanaryMonitor` (Credential Manager honeypots), `LsassDumpCanaryMonitor` (LSASS handle access via event log), browser cred/cookie theft (`CookieIntegrityMonitor`), credential-prompt spoofing (`ClickjackingGuard` fake-UAC + `ScarewareWindowMonitor`).
- Perceptual "write": overlay/clickjacking windows (`ClickjackingGuard`, `NeuroBehaviorVisualMonitor`), synthetic cursor control (`ClickjackingGuard` cursor-teleport, `CursorTakeoverMonitor`), screen capture (`ScreenCaptureMonitor` DXGI), webcam/mic activation (`WebcamMicMonitor`, `MicSessionMonitor`, `WebcamHijackMonitor`, `AudioHijackMonitor`), and acoustic output manipulation (`AcousticThreatMonitor` — but see the gap note: it is not registered anywhere).

**Genuinely uncovered or weakly covered gaps (the real opportunity for a focused new monitor):**
1. **Synthetic keystroke/mouse INJECTION is not actually detected by the injected-flag channel.** `PhantomKeystrokeGuard`'s class comment claims a `WH_KEYBOARD_LL` hook that reads the `LLKHF_INJECTED` flag, but the implementation does **no such thing** — it polls `GetLastInputInfo` and then alerts only when a process **named** `sendinput`/`autoit`/`nircmd`/`inputsimulator` runs from `\Temp\` or `\Downloads\`. That is attacker-controllable filename trust, forbidden by the adversarial-mindset constraint. There is NO detection of `SendInput`/`keybd_event`/`mouse_event` injection from an arbitrarily-named process, and NO use of the `LLKHF_INJECTED` / `LLMHF_INJECTED` flags.
2. **Journal / global hook keyloggers are not detected.** No code anywhere checks for `SetWindowsHookEx` with `WH_KEYBOARD`/`WH_KEYBOARD_LL`/`WH_MOUSE`/`WH_JOURNALRECORD`, `GetAsyncKeyState`/`GetRawInputData` polling, or `SetWinEventHook`. (These API strings appear only in a different project, `e:\Gorstak\C\Antivirus\Antivirus.cs`, and in `FileReputationEngine.cs` as a static PE-import keyword — not as a live runtime behavioral monitor.)
3. **Clipboard scraping / ClipBanker is not detected at runtime.** No `AddClipboardFormatListener` / `SetClipboardViewer` / clipboard-poll detector exists. "Clipboard" appears only as a keyword in `CoercionAbusePolicy`, as hardening that disables cloud-clipboard, and as job-object UI restrictions in `PseudoSandbox` — never as a sensor that notices a process reading or overwriting the clipboard.
4. **`AcousticThreatMonitor` is dead code.** It is a fully-implemented `BackgroundService` that emits detections, but it is registered in **neither** `Sentinel.Agent\Program.cs` nor `Sentinel.Service\Program.cs`, so it never runs.
5. **Toast / notification spoofing** has no monitor (and `docs/constraints.md` forbids Sentinel itself calling notification APIs, so a detector would have to be observational).

A single new user-session monitor — a true input-injection + keylogger-hook + clipboard-access guard — would close gaps 1–3, which are the core of the "read/write to the user" channel.

---

## 2. Per-monitor current-coverage summary (with symbols + ATT&CK)

Note on ATT&CK: monitors do **not** carry an explicit ATT&CK ID field. `DetectionEvent` has no `AttackTechnique` property; mapping is applied centrally by `AttackTechniqueMap.Enrich(detectionEvent)` (called from `DetectionEngine.EmitCompositeAsync`) and is inferred from `RuleName`/`SignalType`. The techniques below are the natural mapping from each rule, not a stored field.

### 2.1 `src\Sentinel.Core\CredentialCanaryMonitor.cs` — class `CredentialCanaryMonitor : IDisposable`
- **Detects:** deletion/tampering of 3–5 randomized honeypot credentials planted in Windows Credential Manager.
- **Hooks in:** constructor plants canaries via P/Invoke `CredWrite`; a `System.Threading.Timer` (`CheckInterval = 15s`) calls `CheckCanaries`, which uses `CredRead`. Missing canary ⇒ emit.
- **Scores:** `RuleName = "Credential Theft: Canary Credential Deleted"`, `Confidence = 0.88`, `Tier = Tier1Behavioral`, `AuthorizedResponse = LogOnly`, `ProcessName = "SYSTEM"`, `ProcessId = 0`.
- **ATT&CK:** T1555 (Credentials from Password Stores) / T1003 (OS Credential Dumping).
- **Note:** no PID attribution (the Credential Manager API does not reveal which process deleted the entry), so it is an alarm, not an actor identifier.

### 2.2 `src\Sentinel.Core\ClickjackingGuard.cs` — class `ClickjackingGuard : BackgroundService`
- **Detects three things**, polled every 5s in `ExecuteAsync`:
  - *Cursor teleport anomaly* (`CheckCursorTeleportation`): `GetCursorPos`, flags >800px jumps repeated ≥3×. `Confidence = 0.85`, `Tier1`, `LogOnly`, `SignalType = PhantomKeystroke`, `ProcessId = 0`.
  - *Suspicious overlay window* (`CheckOverlayWindowsAsync`): `EnumWindows` + `GetWindowLong(GWL_EXSTYLE)` for `WS_EX_LAYERED(0x80000)` + `WS_EX_TOPMOST(0x8)` + (`WS_EX_TRANSPARENT(0x20)` or `WS_EX_NOACTIVATE`), window >400×400, alpha check via `GetLayeredWindowAttributes`. Civilian filter `IsVerifiedOverlayCivilian` (DWM/explorer by signed path, known comms, games, IDEs, GPU overlays). `Confidence = 0.78`, `Tier1`, `AuthorizedResponse = KillProcessTree`, `SignalType = PhantomKeystroke`.
  - *Fake UAC / credential prompt* (`CheckFakeUacAsync`): `EnumWindows` + `GetWindowText`/`GetClassName` for UAC-like titles ("User Account Control", "Windows Security", `#32770` "Sign in") from processes NOT signed by a trusted publisher (`SignerTrustService.IsSignedFile`). `Confidence = 0.90`, `Tier1`, `KillProcessTree`, `SignalType = PhantomKeystroke`.
- **ATT&CK:** T1056.002 (GUI Input Capture), T1185 (Browser/UI redress), T1548 (Abuse Elevation — fake UAC).

### 2.3 `src\Sentinel.Core\AcousticThreatMonitor.cs` — class `AcousticThreatMonitor : BackgroundService`
- **Detects:** harmful frequency content in system audio **output** via WASAPI loopback (`WasapiLoopbackCapture`, NAudio): infrasound (1–20 Hz), 18–19 Hz "fear" band, 6.5–8 Hz "nausea" band, 17–22 kHz ultrasonic beacons, sustained narrow-band tones. Goertzel analysis. Whitelists Solfeggio / Schumann frequencies. On threat it mutes the offending audio session (`SimpleAudioVolume.Mute`).
- **Scores:** `RuleName = "Acoustic Threat: {type}"`, `Confidence 0.70–0.90`, `Tier1`, `LogOnly` (muting done directly), `ProcessId = 0`.
- **ATT&CK:** T1565 (Data Manipulation) / Impact — loose fit; this is a perceptual-manipulation defense more than a classic ATT&CK technique.
- **GAP:** **not registered in any composition root** → never instantiated → never runs. See §5.

### 2.4 `src\Sentinel.Core\WebcamHijackMonitor.cs` — class `WebcamHijackMonitor : BackgroundService`
- **Detects:** growth in the count of registered video-capture devices under `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{e5323777-f97a-4f0b-92a4-0e3062b86553}` (webcam device-interface GUID), polled every 10s. A new device ⇒ possible hardware emulation / stream hijack.
- **Scores:** `RuleName = "Webcam Hijack: New Video Capture Device Detected"`, `Confidence = 0.60`, `Tier = Tier2Indicator`, `LogOnly`, `ProcessId = 0`.
- **ATT&CK:** T1125 (Video Capture).
- **Note:** detects *device registration*, not *which process is streaming* — complementary to `WebcamMicMonitor`.

### 2.5 `src\Sentinel.Core\LsassDumpCanaryMonitor.cs` — class `LsassDumpCanaryMonitor : IDisposable`
- **Detects:** LSASS credential dumping via Windows event logs (deliberately NOT by self-enumerating handles, to avoid looking like Mimikatz). Timer every 30s:
  - Sysmon EID 10 (ProcessAccess) targeting `lsass.exe` with `GrantedAccess & PROCESS_VM_READ (0x10)` from a non-trusted path (`CheckSysmonProcessAccess`).
  - Fallback Security EID 4656 (`CheckSecurityAuditEvents`).
  - Defender ASR EID 1121 for GUID `9e6c4e1f...` (`CheckDefenderAsrEvents`).
- **Trust gate:** `IsTrustedPath` canonicalizes the path (handles `\\?\`, 8.3, trailing dot), directory-boundary match against System32/SysWOW64/Defender, THEN requires a valid signature (`SignerTrustService.IsSignedFile` / `SecurityValidation.VerifyAuthenticodeSignature`) — fails closed.
- **Scores:** `Confidence 0.85–0.95`, `Tier1`, `AuthorizedResponse = KillProcessTree`, `SignalType = LsassAccess`, **`Family = TerminalFamily.CredentialDump`** (typed terminal family — this is a kill-grade terminal).
- **ATT&CK:** T1003.001 (LSASS Memory).

### 2.6 `src\Sentinel.Core\MemoryBehaviorAnalyzer.cs` — class `MemoryBehaviorAnalyzer : IDisposable`
- **Detects:** foreign mapped PE modules across all PIDs. Timer every 5s; on the first (baseline) pass enumerates all processes and calls `DllUnloadEngine.CheckAndUnloadAsync(pid, name)`; skips game/anti-cheat and un-inspectable PIDs (`SecurityValidation.IsGameOrAntiCheatProcess`, `NativeProcessMemory.CanInspect`). Does NOT emit `DetectionEvent`s itself (constructor-injected `DetectionEngine`/`SignerTrustService`/`TelemetryFusionEngine` are assigned to `_` and unused); remediation + detection emission happen inside `DllUnloadEngine`.
- **ATT&CK:** T1055 (Process Injection) / T1574.002 (DLL side-loading). Not part of the perception I/O channel; included for completeness.

---

## 3. The exact `IMonitor` contract + DI/registration steps a new monitor needs

### 3.1 Interface options (both are valid; pick by lifecycle need)
`src\Sentinel.Core\IMonitor.cs`:
```csharp
public interface IMonitor
{
    string Name { get; }
    Task StartAsync(CancellationToken ct);
    Task StopAsync();
}
```
In practice almost no perception monitor implements `IMonitor` directly. The established patterns are:
- **`BackgroundService`** (from `Microsoft.Extensions.Hosting`) — used by `ClickjackingGuard`, `ScreenCaptureMonitor`, `WebcamHijackMonitor`, `AcousticThreatMonitor`, `NeuroBehaviorVisualMonitor`, etc. Override `protected override async Task ExecuteAsync(CancellationToken ct)` with a `while (!ct.IsCancellationRequested)` loop. **This is the recommended base for a new user-session monitor.**
- **`IHostedService, IDisposable` with an internal `System.Threading.Timer`** — used by `PhantomKeystrokeGuard`, `CredentialCanaryMonitor`, `LsassDumpCanaryMonitor`.

Constructor-injected dependencies (DI is mandatory): at minimum `DetectionEngine` and `ILogger<T>`; optionally `SignerTrustService` (publisher trust), `SentinelConfig`, `ContextBus`.

### 3.2 Where it registers — depends on session
A perception/UI monitor needs the interactive desktop and the per-user registry hive, so it belongs in the **Agent** (user session), not the Service (SYSTEM):

- **Agent (user-session monitors) — `src\Sentinel.Agent\Program.cs` (~lines 356–371):** registered flat via `services.AddHostedService<T>()`. Existing peers there: `ScreenCaptureMonitor`, `WebcamMicMonitor`, `AudioHijackMonitor`, `MicSessionMonitor`, `NeuroBehaviorVisualMonitor`, `BrowserExtensionMonitor`, `PhantomKeystrokeGuard`, `ClickjackingGuard`, `WebcamHijackMonitor`, `ScarewareWindowMonitor`, `CursorTakeoverMonitor`, `CookieIntegrityMonitor`. A new user-session monitor is added the same way:
  ```csharp
  services.AddHostedService<MyNewInputInjectionGuard>();
  ```
- **Service (SYSTEM monitors) — `src\Sentinel.Service\Program.cs`:** these are NOT flat; they are grouped into `MonitorGroup` instances (Critical, CoreDetection, CredentialProtection, NetworkIntegrity, SystemIntegrity, Peripheral). The group pattern is: `services.AddSingleton<MyMonitor>();` for the concrete type, then it is listed inside a `SafeMonitorResolver.Build(sp, (...))` tuple inside a `MonitorGroup` factory with a `MonitorGroupConfig` (Name, `Category` = `MonitorCategory.UserProtection` for this class of monitor, StartDelay, StaggerDelay, restart policy). Example group: "Peripheral" at `Program.cs` ~lines 828–878.

> Constraint tension to flag (`docs/constraints.md`): "**Monitors registered in groups** — All background monitors must be registered via `MonitorGroup` … no flat `AddHostedService` for monitors." The **Service** honors this; the **Agent** does not (it uses flat `AddHostedService` for all user-session monitors). A new user-session monitor should follow the existing Agent convention (flat `AddHostedService`) to match its neighbors, but be aware the constraint text was written for the Service's grouped model. This is an existing inconsistency, not something the new monitor introduces.

### 3.3 Supervision / registry
`MonitorRegistry` (`src\Sentinel.Core\MonitorRegistry.cs`) provides heartbeat/watchdog/auto-restart and a `MonitorCategory` enum that already contains `UserProtection // Clickjacking, ScreenCapture, Webcam, Audio` — the correct category for a perception monitor. In the Service, `MonitorGroup` auto-registers members and piggybacks heartbeats. In the Agent (flat registration) monitors are not wired to `MonitorRegistry`; a new Agent monitor would follow that same (unsupervised) pattern unless deliberately changed.

---

## 4. Signal-emission + correlation API shape (with a concrete example)

### 4.1 Emission entry point
`DetectionEngine.EmitAsync(DetectionEvent)` in `src\Sentinel.Core\DetectionEngine.cs`:
```csharp
public async Task EmitAsync(DetectionEvent detectionEvent)
{
    _metrics.RecordDetection(0);
    await HandleDetectionEventAsync(detectionEvent);  // -> tier law -> AdvancedResponseEngine.HandleAsync
}
```
Monitors call `_detectionEngine.EmitAsync(new DetectionEvent { ... })` (fire-and-forget `_ =` for timer callbacks, `await` inside async loops). This bypasses the rule sweep but still flows through `HandleDetectionEventAsync` → `AdvancedResponseEngine.HandleAsync`, where **all tier law applies**: `ApplyTierLaw` under `ObserveUntilChain`, the Tier2-never-acts gate, allowlist/IDE/game protection, and the mandatory pre-action audit log.

### 4.2 `DetectionEvent` shape (`src\Sentinel.Core\Models.cs`)
```csharp
public class DetectionEvent
{
    public string RuleName { get; set; } = string.Empty;
    public string? RuleId { get; set; }                 // optional "SENT-00X" style
    public string Evidence { get; set; } = string.Empty;
    public string Reasoning { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public DetectionTier Tier { get; set; }             // Tier1Behavioral | Tier2Indicator
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public SignalType SignalType { get; set; } = SignalType.Generic;
    public TerminalFamily? Family { get; set; }         // typed kill-grade family; null = legacy substring classify
    public Dictionary<string, string> Metadata { get; set; } = new();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public ResponseAction AuthorizedResponse { get; set; } = ResponseAction.LogOnly;
    public bool KillAuthorized => AuthorizedResponse >= ResponseAction.KillProcess;  // computed, not settable
}
```
Relevant enums: `DetectionTier { Tier1Behavioral, Tier2Indicator }`; `ResponseAction { LogOnly, NetworkIsolate, RemoveCert, VpnShieldUp, KillProcess, KillProcessTree, Quarantine, QuarantineAndKill, ... }` (note `KillAuthorized` becomes true at/after `KillProcess`); `SignalType { Generic, LsassAccess, ..., PhantomKeystroke }` — **`PhantomKeystroke` is the existing signal type for the input-injection/UI channel.** For a true input-injection detector the natural choices are `SignalType.PhantomKeystroke` plus, if it is kill-grade, `Family = TerminalFamily.CredentialTheft`/`Injection` as appropriate (see `TerminalFamily.cs`).

### 4.3 Correlation / enrichment bus
Two distinct channels:
- **Detections** → `DetectionEngine.EmitAsync` (above). The `BehavioralCorrelationEngine` and `WeightedCorrelationEngine` are wired in the `DetectionEngine` constructor via `_correlationEngine.Initialize(this.EmitCompositeAsync)` — composites re-enter through `EmitCompositeAsync`, which runs `AttackTechniqueMap.Enrich` then `HandleDetectionEventAsync`. A monitor does not call the correlation engine directly; it just emits, and correlation observes the emitted stream.
- **Enrichment (non-detection) context** → `ContextBus` (`src\Sentinel.Core\ContextBus.cs`): `Publish(EnrichmentSignal)` / `Subscribe<TSignal>(handler, name)` / `Query<TSignal>(pid)`. This is the pub/sub "nervous system" for cross-monitor hints (bounded channel, DropOldest, per-PID cache, 5-min TTL). Use it only if the new monitor should *enrich* other monitors rather than raise a detection.

### 4.4 Concrete example (copied pattern from `ClickjackingGuard.CheckOverlayWindowsAsync`)
```csharp
await _detectionEngine.EmitAsync(new DetectionEvent
{
    RuleName = "Clickjacking: Suspicious Overlay Window",
    Evidence = $"Process '{procName}' (PID {pid}) has a large overlay window ({width}x{height}, alpha={alpha}). " +
               "Layered+Topmost+Transparent/NoActivate pattern.",
    Reasoning = "A non-foreground transparent topmost window was detected covering a significant screen area. ...",
    Confidence = 0.78,
    Tier = DetectionTier.Tier1Behavioral,
    AuthorizedResponse = ResponseAction.KillProcessTree,
    ProcessName = procName,
    ProcessId = pid,
    SignalType = SignalType.PhantomKeystroke,
    Metadata = new Dictionary<string, string>
    {
        { "WindowSize", $"{width}x{height}" },
        { "Alpha", alpha.ToString() },
        { "ExStyle", "Layered+Topmost+Transparent" }
    }
});
```

---

## 5. Read/write-to-user threats — covered vs uncovered

| Threat (channel) | Status | Where / why |
|---|---|---|
| LSASS memory scraping (read) | **Covered** | `LsassDumpCanaryMonitor` (Sysmon EID10 / Security 4656 / Defender ASR 1121), `Family=CredentialDump`, kill-grade. |
| Credential Manager harvesting (read) | **Covered** | `CredentialCanaryMonitor` honeypots. |
| Browser credential/cookie/session theft (read) | **Covered** | `CookieIntegrityMonitor` (PsPorted), browser cred rules in `Sentinel.Core`. |
| Fake UAC / fake credential prompt (read via deception) | **Covered** | `ClickjackingGuard.CheckFakeUacAsync`, `ScarewareWindowMonitor`. |
| Clickjacking / transparent overlay (write/redress) | **Covered** | `ClickjackingGuard` overlay check + `NeuroBehaviorVisualMonitor` fullscreen-overlay check. |
| Screen capture (read of what user sees) | **Covered (Tier2)** | `ScreenCaptureMonitor` detects DXGI+D3D11 desktop duplication; path/name allowlist. GDI `BitBlt`-only capture is NOT detected (only the DXGI module pair is). |
| Webcam activation (read) | **Covered** | `WebcamMicMonitor` (ConsentStore), `WebcamHijackMonitor` (device-class growth). |
| Microphone activation (read) | **Covered** | `MicSessionMonitor`, `WebcamMicMonitor`, `AudioHijackMonitor` (new endpoints). |
| Harmful audio output (write/perceptual) | **Implemented but DEAD** | `AcousticThreatMonitor` is complete but registered **nowhere** → never runs. |
| Programmatic cursor control (write) | **Covered** | `ClickjackingGuard` cursor-teleport, `CursorTakeoverMonitor` (velocity-variance). |
| **Synthetic keystroke/mouse injection via `SendInput`/`keybd_event`/`mouse_event`** (write) | **GAP** | `PhantomKeystrokeGuard` claims a `WH_KEYBOARD_LL`+`LLKHF_INJECTED` hook in its doc comment but actually only name-matches `sendinput`/`autoit`/`nircmd`/`inputsimulator` in `\Temp\`/`\Downloads\`. No injected-flag detection; attacker renames the binary and evades. |
| **Keylogger hooks: `SetWindowsHookEx(WH_KEYBOARD/_LL/WH_MOUSE)`, `WH_JOURNALRECORD`, `GetAsyncKeyState`/`GetRawInputData` polling, `SetWinEventHook`** (read) | **GAP** | Not detected anywhere in `Sentinel.Core`. These strings exist only in a different project (`e:\Gorstak\C\Antivirus\Antivirus.cs`) and as a static PE-import keyword in `FileReputationEngine.cs`. No live behavioral hook-enumeration monitor. |
| **Clipboard scraping / ClipBanker (`AddClipboardFormatListener`/`SetClipboardViewer`/poll)** (read/write) | **GAP** | No runtime clipboard-access detector. "Clipboard" only appears in hardening (disable cloud clipboard), `PseudoSandbox` UI restrictions, and keyword lists. |
| Toast / notification spoofing (write) | **GAP (constrained)** | No monitor. Note `docs/constraints.md` forbids Sentinel *calling* notification APIs; a detector must be observational only. |

**Net:** the cleanest, highest-value new monitor is a **user-session Input Integrity Guard** that closes the three true gaps: (1) real synthetic-input-injection detection (low-level hook reading `LLKHF_INJECTED`/`LLMHF_INJECTED`, behavioral not name-based), (2) keylogger-hook enumeration (`SetWindowsHookEx`/`SetWinEventHook`/raw-input polling), and (3) clipboard-access monitoring (`AddClipboardFormatListener`). A separate quick win (no new monitor) is to **register the existing `AcousticThreatMonitor`**.

---

## 6. Hard constraints a new monitor MUST satisfy

Authoritative sources read: `.kiro\steering\constraints.md` (inclusion: always) and the full canonical set it references, `docs\constraints.md` (v2.5.6). (Note: `.agents\rules\constraints.md` referenced by `AGENTS.md` does **not exist** on disk; `.kiro\steering\constraints.md` + `docs\constraints.md` are the live constraint files.)

Rules that bind a new perception/input monitor:
1. **Userland only** — no kernel driver, no direct syscalls, no self-hiding, must stay visible in process list/Task Manager/event logs. A low-level hook (`SetWindowsHookEx(WH_*_LL)`) is userland and allowed; a kernel keyboard filter is not.
2. **Tier2 = LogOnly, unconditionally** — enforced in `AdvancedResponseEngine.HandleAsync`. If the monitor emits `Tier2Indicator`, it can never trigger an action regardless of config.
3. **Observe-until-chain / Tier1 = kill-grade only** — a destructive `AuthorizedResponse` (`KillProcess`/`KillProcessTree`/`Quarantine`) must be reserved for high-confidence (≥ `MinTier1Confidence`, default 0.85) proven-terminal behavior or a multi-signal chain. Note current `SentinelConfig.ObserveUntilChain` is hard-wired `false` (repeat-target host) so a lone strong Tier1 can act — all the more reason weak input heuristics must be emitted as Tier2/LogOnly.
4. **Behavioral signals only for kill authority; no attacker-controllable trust** — do NOT repeat `PhantomKeystrokeGuard`'s mistake. A process name/path/folder alone must never authorize or (for an allow path) exonerate. Trust an "allow" only via a non-attacker-controllable anchor: trusted-root load location that is not user-writable, valid Authenticode signature (`SignerTrustService.IsSignedFile`), or a proven legitimate host. Fail closed when the path can't be resolved.
5. **DI required** — all deps constructor-injected (`DetectionEngine`, `ILogger<T>`, optional `SignerTrustService`/`SentinelConfig`). No service locator, no `new` for injected services.
6. **CancellationToken threaded through every async method**; no `Thread.Sleep` without cancellation (use `await Task.Delay(..., ct)`).
7. **No static mutable state** — use `ConcurrentDictionary`/`Channel<T>`/`SemaphoreSlim` (existing monitors use `ConcurrentDictionary` for dedup).
8. **No silent exception swallowing** — every `catch` logs at least `LogDebug`. **Graceful degradation** — a failing monitor must not crash the host (wrap `ExecuteAsync` body; log and continue).
9. **No string-built JSON** (`System.Text.Json` only), **no string interpolation into shell commands**.
10. **Agent STA / notification rules** (if it touches UI): the Agent's WinForms STA pump must not get async continuations posted to its SynchronizationContext (`ConfigureAwait(false)` / dedicated threads), and **`ShowBalloonTip`/toast APIs must not be called** (they deadlock the STA pump; `WpnService` is removed by hardening).
11. **All file reads use `FileShare.ReadWrite | FileShare.Delete`** (never block user file deletion).
12. **Testing** — every Tier1 rule needs a test that it fires and returns `Tier1Behavioral`; every Tier2 rule a test it returns `Tier2Indicator`; the Tier2-stays-LogOnly contract must be test-verified with a mock engine; tests must not require elevation/network/specific FS state. See existing `tests\Sentinel.Tests\Monitors\PsPortedMonitorsTests.cs` for the pattern.
13. **No security theater** — if a detector can't actually work against an attacker who reads the source, it must be removed or honestly documented as limited. (Directly applicable: the new monitor must not re-create a name-based "injection" check.)

---

## 7. Recommendations (nothing implemented)

1. **Build one user-session `InputIntegrityGuard` (`BackgroundService`), registered in `Sentinel.Agent\Program.cs` alongside its peers**, covering:
   - **Synthetic input injection:** install a low-level keyboard+mouse hook (`SetWindowsHookEx(WH_KEYBOARD_LL/WH_MOUSE_LL)`) and inspect the hook struct's injected flags (`KBDLLHOOKSTRUCT.flags & LLKHF_INJECTED (0x10)`, `MSLLHOOKSTRUCT.flags & LLMHF_INJECTED (0x1)`), rate-limited, attribute to source where possible. Behavioral, not name-based. Emit `SignalType.PhantomKeystroke`.
   - **Keylogger hooks:** enumerate processes importing/using `SetWindowsHookEx`/`GetRawInputData`/`SetWinEventHook` as Tier2 observe fuel; only chain-confirm to Tier1.
   - **Clipboard access:** `AddClipboardFormatListener` to observe clipboard writes/reads, flag rapid read-after-focus or write-replace patterns (ClipBanker) as Tier2 → chain.
   - Keep everything Tier2/LogOnly unless a genuine kill-grade chain forms; obey constraint #4.
2. **Fix `PhantomKeystrokeGuard`:** either make it do what its comment claims (real `LLKHF_INJECTED` check) or fold it into the new monitor and delete the name-based path. The current filename/path trust violates the adversarial-mindset constraint and is "security theater."
3. **Register `AcousticThreatMonitor`** in `Sentinel.Agent\Program.cs` (it needs the user audio session) — a complete feature is currently dead code.
4. **Do not build** any "neural read/write" detector. Document (in user-facing materials) that remote brain reading/writing is not a real attack surface and that Sentinel instead defends the actual credential-capture and perceptual-manipulation I/O channel. This matches the honest-marketing / no-theater constraints.

---

### Appendix — files read for this report
`.kiro\steering\constraints.md`, `docs\constraints.md`, `src\Sentinel.Core\IMonitor.cs`, `MonitorRegistry.cs`, `MonitorGroup.cs`, `ContextBus.cs`, `Models.cs`, `DetectionEngine.cs`, `AdvancedResponseEngine.cs` (partial), `CredentialCanaryMonitor.cs`, `ClickjackingGuard.cs`, `AcousticThreatMonitor.cs`, `WebcamHijackMonitor.cs`, `LsassDumpCanaryMonitor.cs`, `MemoryBehaviorAnalyzer.cs`, `UserSessionMonitors.cs`, `Monitors\PsPortedMonitors.cs` (partial), `Sentinel.Agent\Program.cs` (registration block), `Sentinel.Service\Program.cs` (DI + MonitorGroup blocks); plus grep sweeps for `SendInput`/`SetWindowsHookEx`/`WH_JOURNAL`/`GetAsyncKeyState`/`GetRawInputData`/`SetWinEventHook`/`WS_EX_LAYERED`/`AddClipboardFormatListener`/`SetClipboardViewer`/`BitBlt`/DXGI duplication/`Clipboard`.

Note: `AGENTS.md` references `.agents\rules\constraints.md`, which does not exist on disk; the live constraint files are `.kiro\steering\constraints.md` and `docs\constraints.md`.
