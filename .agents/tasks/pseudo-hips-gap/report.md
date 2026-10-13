# Sentinel Pseudo-HIPS Gap Analysis & Phased Plan

**Mode:** READ-ONLY investigation. No code was modified. All paths absolute; citations are `file:symbol` or `file` with the construct named.
**Scope:** Turn Sentinel's userland EDR into a "pseudo-HIPS" (host intrusion *prevention*) without violating the hard constraints in `e:\Gorstak\Sentinel\docs\constraints.md`. No kernel driver, no direct syscalls — so true inline kernel gating (minifilter / WFP callout driver) is permanently off the table.

---

## 1. Summary answer (read this first)

Sentinel today is a **detect-then-react** EDR with a **large preventive-hardening surface already bolted on at startup**. It is *closer to a HIPS than the brief assumed*: it already ships Defender ASR Block rules, DEP/NX AlwaysOn, exploit-mitigation registry policy (SEHOP, Spectre/Meltdown, AlwaysInstallElevated=0, COM auto-approval off), IPSec port blocking, RPC-ephemeral firewall block, LGPO baseline, and credential hardening — all re-armed continuously by guards. What it is **missing** to be a credible pseudo-HIPS, all achievable in userland:

| Gap | Achievable in userland? | Highest-value |
|-----|------------------------|---------------|
| **WDAC / AppLocker policy generation + deployment** | ✅ Yes (policy files + registry/CI deploy) | ⭐ Phase 2 |
| **Process mitigation policy** (ACG / CFG / BlockNonMicrosoftBinaries) via `SetProcessMitigationPolicy` and/or **IFEO `MitigationOptions`** registry | ✅ Yes (IFEO persist is pure registry; API is per-process) | ⭐ Phase 1 (IFEO subset) + Phase 3 |
| **Expand ASR Block coverage** (currently 13 rules) | ✅ Yes (same registry mechanism already in place) | ⭐ Phase 1 |
| **User-mode WFP filter ADDITION for outbound block** (not just detection) | ✅ Yes (FWPUAPI user-mode `FwpmFilterAdd0`, no callout driver) | Phase 2/3 |
| **Declarative operation-level allow/deny policy engine** layered on existing monitors | ✅ Yes (post-hoc enforcement only; cannot be synchronous pre-op deny) | Phase 2 |
| **Synchronous pre-execution/pre-operation DENY of arbitrary file/registry/syscall** | ❌ No — requires the forbidden kernel path | Never (Section 6) |

The single most impactful *latency* improvement — shrinking detect→kill — is already partly present via `ResponsePolicy.IsAttackClassTerminal` (solo-confirm at ≥0.85), but **all detections share one channel consumer** (`DetectionEngine.ProcessTelemetryQueueAsync`), so a terminal-class kill can queue behind slower work. The cheapest prevention win is **not** faster kills; it is **leaning harder on Windows-native preventive policy** (ASR expansion, IFEO mitigations, WDAC) that blocks *before* Sentinel's loop ever runs.

**Honest ceiling:** pseudo-HIPS can *pre-block by policy* (Defender/WDAC/AppLocker/IFEO decide at the kernel on Windows' behalf) and *react fast*, but it can **never** itself synchronously intercept-and-deny an arbitrary file write, registry write, or syscall the way a minifilter/callout HIPS does. That boundary is dictated by `constraints.md` ("No kernel drivers", "No direct syscalls").

---

## 2. Current preventive-control inventory (verified in code)

### 2.1 Startup hardening — applied unconditionally, always-on

`e:\Gorstak\Sentinel\src\Sentinel.Service\Program.cs` calls `HardeningModule.ApplyOrFail()` then `HardeningModule.SecureInstallationDirectory()` at service entry (Program.cs:119,122). `RestrictivePortHardeningEnabled` is a hard `get => true` no-op setter (`HardeningModule.cs`), matching the **"HARDENING IS ALWAYS-ON (v2.5.5)"** constraint.

`ApplyOrFail()` → `ApplyUserSetupScriptsHardening()` runs this preventive chain (`HardeningModule.cs`, `ApplyUserSetupScriptsHardening`):

| Preventive control | Symbol / location | Mechanism | Prevention vs detection |
|--------------------|-------------------|-----------|--------------------------|
| **Defender ASR Block rules (13)** | `HardeningModule.AsrRules` + `ApplyAsrRules()` | Writes `...\Windows Defender Exploit Guard\ASR\Rules` GUID=`1` (Block) in the Policy hive | **PREVENTIVE** — Defender blocks the action at execution |
| ASR exclusions (self-protect installer) | `ApplyAsrOnlyExclusions()` | `ASROnlyExclusions` multi-sz | Supports constraint "Never ASR-block our own installer" |
| **IPSec port lockdown** (attack + restrictive sets) | `ReapplyIPSecPolicy()`, `AttackOnlyPortDefinitions`, `RestrictiveExtraPortDefinitions` | `netsh ipsec static` BLOCK filter action on in/out | **PREVENTIVE** — traffic dropped |
| **RPC ephemeral inbound block** | `BlockRemoteRpcEphemeralPorts()` | Firewall COM `HNetCfg.FwPolicy2`, block 49664-49675 from LocalSubnet | **PREVENTIVE** |
| **DEP / NX AlwaysOn** | `EnforceDepAlwaysOn()` | `bcdedit /set nx AlwaysOn` | **PREVENTIVE** (boot-level exploit mitigation) |
| **Registry exploit mitigations** | `ApplyRegistryHardening()` | SEHOP (`DisableExceptionChainValidation=0`), Spectre/Meltdown `FeatureSettingsOverride`, `AlwaysInstallElevated=0`, UAC `COMAutoApprovalList` off, TLS 1.3/no-downgrade, firewall EnableFirewall=1 all profiles, QUIC off, WCN off, crash dumps off, cloud clipboard off | **PREVENTIVE** (policy) |
| **LGPO security baseline** | `ApplyLgpoSecurityPolicy()` (embedded `GSecurity.inf`) | LGPO.exe | **PREVENTIVE** |
| **Credential hardening** | `ApplyCredentialHardening()` | LSASS PPL (`RunAsPPL`), WDigest off, `NoLMHash`, `restrictanonymous` | **PREVENTIVE** |
| **Browser hardening** | `ApplyBrowserHardening()` | policy registry | **PREVENTIVE** |
| **Install-dir ACL lockdown** | `SecureInstallationDirectory()` | Deny-write for Builtin Users | **PREVENTIVE** |
| **Service disablement** | `DisableRemoteAccessServices()` | Telnet/RemoteRegistry always; RDP/WinRM/sshd/etc under restrictive | **PREVENTIVE** |
| Safe Mode persistence of the service | `RegisterForSafeMode()` | SafeBoot Minimal+Network reg | self-protection |

Continuous re-arm guards (so prevention survives tamper): `AsrPolicyGuard` (verifies `IsAsrPolicyIntact()`, re-applies on drift — `HardeningModule.ReapplyAsrRules`), `IPSecIntegrityGuard` (`IsIPSecPolicyActive()` / `ReapplyIPSecPolicy()`), `FirewallIntegrityMonitor`. All registered as Critical/SystemIntegrity monitors in `Program.cs` (`AsrPolicyGuard`, `IPSecIntegrityGuard` at Program.cs:498).

### 2.2 Preventive-adjacent runtime controls

- **`VerdictGateRule`** (`e:\Gorstak\Sentinel\src\Sentinel.Core\Rules.VerdictGate.cs`): on process-start telemetry, hashes the image, reads a *signed* ADS verdict; `HashVerdict.Unsafe` → Tier1 `KillProcessTree` conf 0.99. The code comment says "Execution prevented," but mechanically this is **detect-then-kill after the process has started**, not a pre-execution deny. It only fires on binaries previously signed `Unsafe` (reputation consensus), so coverage is narrow. Still, it is the closest thing to an application-control gate today.
- **File-reputation on-execute** (`DetectionEngine.ProcessTelemetryQueueAsync`, the `ProcessTelemetry pt` branch): `Malicious` → KillProcessTree 0.95; `HighRisk` → KillProcess 0.80 (demoted to observe for installer-like unknowns). Again post-launch kill, not pre-exec block.
- **`ThreatIntelFeedBlocker`** (`e:\Gorstak\Sentinel\src\Sentinel.Core\ThreatIntelFeedBlocker.cs`): CAN proactively add COM firewall block rules for feed IPs — but design says **observe-only by default**, proactive firewall only when `ThreatIntelProactiveFirewall`. This is the one existing component that *adds* network blocks preventively.
- **`HostsFileGuard` + `RuntimeBlocklistService`**: enforce domain blocks (hosts line + wildcard NRPT) and IP blocks (in/out firewall) for a configured/runtime block set — preventive, posture-gated (design.md).
- **`DllUnloadEngine`**: FreeLibrary-unloads foreign modules and quarantines hijack-name disk plants on drop. This is *remediation after load*, the closest userland analogue to blocking a load.

### 2.3 WFP today = DETECTION only (confirmed)

`e:\Gorstak\Sentinel\src\Sentinel.Core\Monitors\WfpIntegrityMonitor.cs`:
- Exports filters via `netsh wfp show filters`, regex-parses for BLOCK filters targeting Sentinel/EDR binaries (`AnalyzeWfpFiltersAsync`). Emits Tier1 detections (EDRSilencer / bulk-block / multi-tool-block).
- `AttemptFilterRemovalAsync` explicitly **does not add or remove filters by GUID** — it only re-enables netevents auditing and *logs an operator recommendation* to restart BFE. The code comment states a blanket purge / BFE restart "would tear down the host firewall, an unacceptable blast radius for a userland EDR." So **no WFP filter ADD exists anywhere** in `src`.

### 2.4 What is confirmed ABSENT (grep across `src/**/*.cs`)

- **No `SetProcessMitigationPolicy`**, no `UpdateProcThreadAttribute`-based mitigation, no process mitigation application of any kind.
- **No IFEO `MitigationOptions`** registry writes (IFEO only referenced as a *persistence detection* surface in `BehavioralCorrelationEngine.cs:523` and `DashboardHtml.cs`).
- **No WDAC** (`SiPolicy`/`CIPolicy`/`ConfigCI`/`CodeIntegrity`) and **no AppLocker** policy generation or deployment.
- **No ACG / CFG / BlockNonMicrosoftBinaries** anywhere.
- **No declarative operation-level allow/deny policy language** — enforcement decisions are hard-coded in `ResponsePolicy` / rules, not expressed as a user-authored allow/deny grammar. (`DynamicRulesEvaluator` loads HMAC-signed *detection* rules with an allowlisted field set; it is a detection extension, not an operation-gating policy engine.)

*(Note: `.worktrees\*` copies exist, including one named `autorotate` tied to an unrelated password-rotation thread. They were ignored; all citations are from the canonical `e:\Gorstak\Sentinel\src` tree.)*

---

## 3. Detect→respond latency path

### 3.1 The pipeline (verified)

```
ETW/WMI/FSW monitors
  → TelemetryFusionEngine (passive)
  → DetectionEngine._telemetryChannel  (Channel.CreateBounded 10k, DropOldest)
  → ProcessTelemetryQueueAsync  [SINGLE consumer loop]           DetectionEngine.cs
       • per ProcessTelemetry: Task.Run(reputation lookup)  (async, off-loop)
       • foreach rule in _rules: rule.Evaluate(context) → ProcessDetectionAsync
  → ProcessDetectionAsync                                         DetectionEngine.cs
       • 10s (Tier1) / 30s (Tier2) dedup
       • ScoringEngine.Score + ATT&CK enrich
       • ResponsePolicy.ApplyTierLaw   (demote non-terminal to Tier2/LogOnly)
       • HandleDetectionEventAsync
       • THEN correlationEngine.RegisterSignalAsync (composites emit later)
  → HandleDetectionEventAsync → SentinelOrchestrator.ProcessDetectionAsync
  → AdvancedResponseEngine.HandleAsync                           AdvancedResponseEngine.cs
       • self-exclusion, IDE/game protection, allowlist
       • ObserveUntilChain gate: ResponsePolicy.MayPerformDestructiveResponse
       • MANDATORY pre-action audit (LogAuditBeforeActionAsync) BEFORE any kill
       • branch → HardeningModule.SafeKillProcessTree / QuarantineAndKill / NetworkIsolate / ...
```

### 3.2 Where a kill is authorized fast

- **Solo terminal confirm:** `ResponsePolicy.RegisterAndEvaluateChain` → if `IsAttackClassTerminal(detection)` and `Confidence ≥ MinTier1Confidence` (default 0.85), it tags chain-confirmed **immediately on the first signal** (`ResponsePolicy.cs:776`). `IsAttackClassTerminal` (`ResponsePolicy.cs:690`) covers mesh/webhook C2, potato LPE, kernel-EoP loader, ClickFix, Hell's Gate, unmapped-thread, CS pipes, classic RAT ports, tunneling tools, impostor AMSI, ALLOCVM_REMOTE, `ThreatIntelInjectionRule`. For these, there is **no second-signal wait** — this is the existing synchronous fast path the brief referenced.
- **Chain-confirmed kills bypass the rate limiter:** `AdvancedResponseEngine.TryConsumeKillBudget(chainConfirmed:true)` returns true unconditionally — confirmed attacks are never throttled.
- **Pre-action audit is on the hot path by design** (constraint: "All actions ... logged before execution"). `LogAuditBeforeActionAsync` is awaited before the destructive branch. This is a required, small, serialized cost.

### 3.3 Where the window could be shortened (userland-safe)

1. **Single-consumer head-of-line blocking.** `ProcessTelemetryQueueAsync` is one loop; every rule's `Evaluate` runs inline per context (reputation is already offloaded to `Task.Run`, good). A burst of slow rules delays a terminal-class detection sitting behind them in the channel. **Fix (low risk):** a dedicated high-priority fast lane for `IsAttackClassTerminal`-shaped `ProcessTelemetry` / direct `EmitAsync` events that routes straight to `AdvancedResponseEngine.HandleAsync`, bypassing the full rule sweep when the triggering event already carries a terminal-class rule name. Keep the normal loop for everything else.
2. **Correlation runs *after* response** in `ProcessDetectionAsync` (response first, then `RegisterSignalAsync`). Good for latency on the triggering signal; it means composites that would confirm a chain only fire on the *next* signal. No change needed unless composite-confirmation latency is a target.
3. **Process-start → kill is bounded by ETW delivery + the queue.** The genuine prevention improvement is to **not rely on the kill at all** for known-bad shapes: let ASR/WDAC/IFEO mitigations block at the OS layer before the process is useful (Section 5, Phase 1-2). Shaving queue latency helps the *reactive* half; policy prevention removes the race entirely for covered classes.

**Honest latency ceiling:** even a perfect fast lane kills *after* the process has executed instructions. For true "action doesn't matter" prevention you need either (a) OS policy that blocks the launch (ASR/WDAC/AppLocker/IFEO) or (b) kernel inline gating (forbidden).

---

## 4. Ranked pseudo-HIPS gaps vs a real HIPS

Legend: **(a)** achievable in userland within constraints · **(b)** requires forbidden kernel path.

| # | Gap | Class | Extends which component | Bounding constraints (quoted) |
|---|-----|-------|-------------------------|-------------------------------|
| 1 | **Expand ASR Block coverage** (add high-value Block rules beyond the current 13; keep installer carve-outs) | **(a)** | `HardeningModule.AsrRules` + `AsrPolicyGuard` | "HARDENING IS ALWAYS-ON"; "Never ASR-block our own installer (v1.9.6)" — must keep `c1db55ab` out of Block and preserve `ASROnlyExclusions`. |
| 2 | **IFEO `MitigationOptions` process mitigations** for named high-risk hosts (e.g. CFG, DEP-permanent, image-load from remote off, child-process on Office) — pure HKLM registry, persists per image name | **(a)** | new `HardeningModule` block + a re-arm guard like `AsrPolicyGuard` | "No persistence mechanisms" applies to *Sentinel self-survival*, not to Windows security policy it configures; still "No self-hiding", "All actions ... logged". Must not weaken host (parallel to "Kiosk LGPO must not weaken the host"). |
| 3 | **`SetProcessMitigationPolicy` ACG/CFG/BlockNonMicrosoftBinaries** on Sentinel's **own** processes (self-hardening), and optionally on children it launches | **(a)** | `HardeningModule.ApplyOrFail` self-protect section (sits beside existing `SetDefaultDllDirectories`) | "No kernel drivers / No direct syscalls" — `SetProcessMitigationPolicy` is a documented Win32 API, compliant. Self-only is safest (no FP surface). |
| 4 | **Terminal-class fast lane** to shrink detect→kill (Section 3.3 #1) | **(a)** | `DetectionEngine.ProcessTelemetryQueueAsync` + `AdvancedResponseEngine` | "No static mutable state" (use `Channel<T>`); "Tier2 can never trigger action"; "Observe-until-chain" — fast lane may only short-circuit for `IsAttackClassTerminal` at ≥`MinTier1Confidence`, never for Tier2. |
| 5 | **User-mode WFP outbound BLOCK filter addition** (replace the "operator must restart BFE" gap with surgical `FwpmFilterAdd0` by GUID; also remove hostile EDRSilencer filters by GUID) | **(a)** | `WfpIntegrityMonitor` (add enforcement) or new `WfpEnforcementEngine`; register as a `ResponseAction` | "No kernel drivers" — FWPUAPI user-mode add is **not** a callout driver, compliant. "Response path: prefer native APIs." Blast-radius caution already documented in `AttemptFilterRemovalAsync`. |
| 6 | **WDAC / AppLocker allowlist policy generation + deployment** | **(a)** | new `AppControlPolicyModule` in `Sentinel.Core`; deploy via CI policy file / AppLocker registry + re-arm guard | "No kernel drivers" (WDAC *is* enforced by the OS kernel, but Sentinel only *authors/deploys* policy — compliant, like ASR). "Must function as a standard user (reduced capability)" — deploy only when elevated. HUGE lockout risk → audit-mode first. |
| 7 | **Declarative operation-level allow/deny policy engine** layered on monitors (user writes "deny process X writing to Y"; Sentinel enforces post-hoc kill/quarantine/block) | **(a) partial** | new policy model consumed by `ResponsePolicy` / `AdvancedResponseEngine`; signed like `DynamicRulesEvaluator` | "No string-built JSON" (use `System.Text.Json`); "Compiled config only" / "Disk JSON is not loaded" — any on-disk policy MUST be HMAC-signed with install entropy and fail-closed, exactly like `DynamicRulesEvaluator`. **Enforcement is reactive, not synchronous pre-op.** |
| 8 | **Synchronous pre-execution/pre-operation DENY** of arbitrary file/registry/syscall/image-load | **(b)** | — | "No kernel drivers"; "No direct syscalls". Impossible in userland. See Section 6. |

---

## 5. Phased plan

Each phase lists components touched, applicable constraints, and user-facing risk (false-positive / lockout). Lockout-capable items ship in **audit mode first** with an allowlist.

### Phase 1 — highest-value, lowest-risk, already reachable (policy + fast lane)

**1A. Expand ASR Block rules (gap #1).**
- Component: `HardeningModule.AsrRules` (add vetted GUIDs), re-armed by existing `AsrPolicyGuard`.
- Candidates to evaluate (all Defender-native, Block=`1`): "Block Adobe Reader from creating child processes", "Block Webshell creation for Servers", "Block use of copied/impersonated system tools", "Block rebooting into Safe Mode" (caution: Sentinel registers for Safe Mode), plus any current Audit-only rules promoted to Block after telemetry review.
- Constraints: keep `c1db55ab` **out** of Block ("Never ASR-block our own installer"); keep `ASROnlyExclusions` for the install dir.
- Risk: **Medium.** ASR Block rules can break legit workflows (macro-heavy Office, LOLBin-using installers). **Mitigation:** stage each new rule in Audit first; only promote rules with zero legit hits in the field. Flag that "Block process creations from PSExec and WMI" (already active) can break admin tooling.

**1B. Self-process mitigation hardening via `SetProcessMitigationPolicy` (gap #3, self-only).**
- Component: `HardeningModule.ApplyOrFail` self-protect section (next to `SetDllDirectory`/`SetDefaultDllDirectories`).
- Apply to Sentinel's own Service/Agent: CFG, DEP permanent, `BlockNonMicrosoftBinaries` / `MicrosoftSignedOnly` image-load (if it doesn't break Sentinel's unsigned dev builds — gate on signed release builds only), strict handle checks, extension-point disable.
- Constraints: Win32 API — compliant with "No kernel drivers / No direct syscalls". "Must function as a standard user" — wrap in try/catch, fail-soft (matches `ApplyOrFail` best-effort pattern).
- Risk: **Low.** Self-only, no third-party FP surface. Verify unsigned dev builds still start (BlockNonMicrosoftBinaries would kill them) — gate that specific policy behind a signed-build check.

**1C. IFEO `MitigationOptions` for a *small* curated set of high-risk host images (gap #2).**
- Component: new `HardeningModule.ApplyProcessMitigationIfeo()` + a re-arm guard modeled on `AsrPolicyGuard` (registered in the same group in `Program.cs`).
- Scope Phase 1 narrowly: enable CFG / DEP-permanent on classic LOLBin / Office-child surfaces only where it won't break function. **Do not** apply `BlockNonMicrosoftBinaries` broadly here (that is Phase 3 opt-in).
- Constraints: HKLM `Image File Execution Options\<exe>\MitigationOptions` is OS-sanctioned policy, not Sentinel self-persistence; "All actions ... logged before execution"; parallel to "Kiosk LGPO must not weaken the host" — never set options that reduce security.
- Risk: **Medium.** A bad `MitigationOptions` value can prevent an app from starting. **Mitigation:** curated per-image list, documented, with a one-switch rollback (delete the IFEO values); ship disabled-by-default with a per-image allowlist.

**1D. Terminal-class fast lane (gap #4).**
- Component: `DetectionEngine` (second high-priority `Channel<T>` or priority check in `ProcessTelemetryQueueAsync`), routing `IsAttackClassTerminal` events straight to `AdvancedResponseEngine.HandleAsync`.
- Constraints: "No static mutable state" (bounded `Channel<T>`); "Tier2 can never trigger action" — the fast lane must re-check tier and `IsAttackClassTerminal` + `MinTier1Confidence`, never short-circuit Tier2; "Observe-until-chain" preserved (fast lane only applies to the classes that already solo-confirm).
- Risk: **Low.** No change to *what* is killed, only *how fast*. Must keep the mandatory pre-action audit on the fast path.

### Phase 2 — more invasive userland policy (opt-in, audit-first)

**2A. User-mode WFP outbound BLOCK enforcement (gap #5).**
- Component: new `WfpEnforcementEngine` (FWPUAPI P/Invoke: `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0`) + a new `ResponseAction.WfpBlockOutbound`; wire into `AdvancedResponseEngine.HandleAsync` branch table; let `WfpIntegrityMonitor` *remove hostile EDRSilencer filters by GUID* instead of only logging a BFE-restart recommendation.
- Use for: chain-confirmed C2 egress block as a surgical alternative/supplement to `NetworkIsolate`'s firewall rule; targeted removal of filters that block Sentinel.
- Constraints: "No kernel drivers" (user-mode WFP API, compliant); "prefer native APIs"; blast-radius discipline already noted in `WfpIntegrityMonitor.AttemptFilterRemovalAsync` — add filters tagged with a Sentinel sublayer/provider so they're cleanly removable and never touch the host firewall sublayer.
- Risk: **Medium.** Mis-scoped filters can break legit egress. **Mitigation:** gate behind chain-confirm (same bar as kill), own-sublayer only, rate-limited like `NetworkIsolate`, auto-expire.

**2B. Declarative operation-level allow/deny policy engine (gap #7).**
- Component: new signed policy model (`System.Text.Json`, HMAC-signed with install entropy, fail-closed) consumed by `ResponsePolicy` + `AdvancedResponseEngine`; reuse the `DynamicRulesEvaluator` signing/allowlist pattern.
- Semantics: policies express "when monitor observes <operation> by <non-attacker-controllable identity> → <reactive action>". Enforcement is **post-hoc** (kill/quarantine/WFP-block/registry-remove), *not* synchronous pre-op deny.
- Constraints: "No string-built JSON"; "Compiled config only / Disk JSON is not loaded" → policy file MUST be signed + fail-closed; "Adversarial mindset: no attacker-controllable trust" — allow rules may never rest on a filename/path the attacker controls; "Tier2 can never trigger action".
- Risk: **Medium-High.** A user-authored deny rule can kill legit software. **Mitigation:** audit mode default; dry-run report before enforce; allowlist; signed-only.

### Phase 3 — strongest userland control, highest lockout risk (strictly opt-in)

**3A. WDAC / AppLocker application-allowlisting (gap #6).**
- Component: new `AppControlPolicyModule` (generate a WDAC CI policy from a learned baseline, or AppLocker rules via the AppLocker policy registry/CSP); deploy only when elevated; re-arm/verify guard like `AsrPolicyGuard`; `BehavioralBaselineService` can seed the allowlist.
- Constraints: "No kernel drivers" (Sentinel authors policy; the OS enforces — same model as ASR, compliant); "Must function as a standard user (reduced capability, no crash)" → generation/deploy elevated-only, degrade gracefully otherwise; "no attacker-controllable trust" → allow by publisher/hash/trusted-path only, never bare filename.
- Risk: **HIGH / lockout-capable.** A wrong WDAC policy can brick the machine (block boot-critical or user-critical binaries). **Mitigation (mandatory):** ship **Audit mode only** by default; require explicit operator opt-in to Enforce; always keep a signed rollback policy and a documented recovery (safe-mode removal — note Sentinel's existing SafeBoot registration helps recovery); never auto-promote Audit→Enforce.

**3B. Broad `BlockNonMicrosoftBinaries` / strict ACG via IFEO or `SetProcessMitigationPolicy` for third-party hosts.**
- Component: extend 1C with the aggressive mitigations, opt-in per image.
- Risk: **HIGH.** Breaks apps with JIT (Electron/.NET/browsers — note `ChainTracer.IsLegitimateIdeHost` already exists to protect IDEs) and unsigned plugins. **Mitigation:** explicit per-image opt-in, audit-first, never default.

### Cross-cutting rollout rules
- Everything lockout-capable (ASR Block additions, IFEO, WFP add, WDAC, broad mitigations) ships **audit/observe first**, promotes only after a clean field window, and has a one-action rollback.
- Preserve the installer/self carve-outs ("Never ASR-block our own installer"; `SelfPathGuard`; `ASROnlyExclusions`).
- All new enforcement actions keep the **mandatory pre-action audit** (`LogAuditBeforeActionAsync`) and are rate-limited like the existing kill/isolate budgets.

---

## 6. What pseudo-HIPS will NEVER do (honest expectations)

A true HIPS inserts itself **inline in the kernel** (filesystem minifilter, registry callback, WFP callout driver, process/thread/image-load notify callbacks) and returns a **DENY before the operation completes**. Because `constraints.md` forbids **"No kernel drivers"** and **"No direct syscalls"**, Sentinel's pseudo-HIPS can **never**:

1. **Synchronously block an arbitrary file write/read/delete** before it happens. (Userland FSW/ETW are *notifications after the fact*; `FileActivityMonitor` observes, it cannot veto. Constraint also mandates `FileShare.Delete` — "Sentinel never blocks user file deletion.")
2. **Synchronously block an arbitrary registry write** before it commits. (`RegistryMonitor` is WMI/ETW observe; it removes malicious keys *after* via `RemoveRegistryEntry`.)
3. **Intercept/deny a syscall or an arbitrary API call** inline. (No direct syscalls; no inline hooking engine.)
4. **Block an arbitrary process launch pre-execution** by its own logic. Launch-blocking only happens for classes Windows itself gates (**ASR / WDAC / AppLocker / IFEO / Defender**); for everything else Sentinel can only **kill after start** (`SafeKillProcessTree`), which is a race, not a veto.
5. **Block a DLL load pre-load.** `DllUnloadEngine` FreeLibrary-unloads *after* the module is mapped; a kernel HIPS denies the load image notification before mapping.
6. **Guarantee "the action never mattered."** The fast lane (Phase 1D) shrinks the window but cannot eliminate it. Only OS-policy prevention (ASR/WDAC/IFEO) removes the race for *covered* classes.

**Bottom line:** pseudo-HIPS = (OS-native preventive policy that blocks at launch/action time) + (fast, chain-confirmed userland kill/quarantine/WFP-block for everything policy didn't catch). It is a strong, honest posture — but it is *policy prevention + fast reaction*, not *arbitrary inline interception*. Any marketing or docs must say so plainly, consistent with "No security theater features" in `constraints.md`.

---

## 7. Recommendations (implement nothing now — scoping only)

1. **Start with Phase 1A + 1B + 1D.** They reuse mechanisms that already exist (`AsrRules`/`AsrPolicyGuard`, `ApplyOrFail` self-protect, the detection channel) and carry the lowest FP/lockout risk for the biggest preventive gain.
2. **Treat ASR expansion and IFEO as the cheapest "prevention" lever** — they block at the OS before Sentinel's loop runs, which is strictly better than any kill-latency work for covered classes.
3. **Phase 2/3 (WFP add, policy engine, WDAC) are genuine prevention but lockout-capable** — gate every one behind audit-mode-first + explicit opt-in + signed/fail-closed config + one-action rollback, honoring "Compiled config only", "no attacker-controllable trust", and "Must function as a standard user".
4. **Keep expectations honest per Section 6** in any user-facing text ("No security theater features").
