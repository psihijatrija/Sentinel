# State Baseline & Reconciliation (Drift Detection) - Requirements

**Roadmap link:** `docs/ROADMAP.md` -> visibility / real-world-threat themes. Adds a **state-driven**
detection axis to complement Sentinel's existing **event-driven** monitors.

**Threat model link:** `docs/THREAT_MODEL.md` -> new section "Silent / user-directed harm with no
system-level malicious behavior". Honest ceiling stated below.

Reference docs (authoritative): `#[[file:../../../docs/requirements.md]]`,
`#[[file:../../../docs/constraints.md]]`, `#[[file:../../../docs/design.md]]`.

---

## Problem statement

Every existing Sentinel terminal family (credential theft, C2, ransomware, injection-then-exfil)
is defined around harm to the **system or its secrets**, and every kill decision is gated on
*behavior over time* (`ObserveUntilChain`). This leaves a real blind spot:

> A payload that harms the **user** rather than the system - e.g. a DLL that merely emits an
> audio/hypnotic stream, flickers the screen, or otherwise degrades the human (headache, sleep
> disruption) - has **no** network leg, **no** credential access, **no** file destruction, and
> **no** escalation. It produces zero terminal telemetry. It may be signed with a stolen but
> validly-chaining certificate. Because there is no chain and no escalation, `ObserveUntilChain`
> can *never* confirm it: the steady state *is* the attack, and waiting is losing.

Neither axis alone catches this: behavior gives nothing, and signature can be forged. But the
payload cannot avoid one thing - **it must persist somewhere** (a module mapped into some process,
a file on disk, an autostart entry). A **state-driven** approach - periodically snapshot what the
system *is*, diff against a stored baseline, and surface unexplained new state - attacks exactly
this blind spot, because it is agnostic to what harm the payload delivers.

## The failure mode to avoid (why this is not "just diff everything")

A naive whole-system diff produces thousands of benign deltas per day (Windows Update, browser
updates, every app shadow-copying DLLs into temp - literally the Roslyn analyzer FP). If those
deltas drove any action, this becomes the ultimate false-positive machine - the opposite of what
the project needs. **The diff is cheap; attribution is the entire product.** A delta is only worth
surfacing if it cannot be attributed to a trusted cause.

## Goals

- Add a state-baseline surface (surface #1: **loaded-module inventory of a fixed set of long-lived,
  low-churn processes**), persisted reboot-durably, diffed on a cadence.
- Emit a signal **only** for deltas that survive every attribution rule (trusted signer/servicing/
  toolchain/known-prior-publisher-on-this-machine).
- Keep every surviving delta **observe-only** (Tier2 / `LogOnly`), never auto-kill - so the diff
  can never become a destructive FP engine.
- Hold the "unexplained since X" state durably and re-emit it on cadence so the correlation layer
  can chain it if the module later *does* something terminal.
- Document the residual blind spot honestly rather than overclaim coverage.

## Non-goals (explicit)

- **No auto-quarantine / no kill** from reconciliation. Ever. It is an observation surface.
- **No whole-filesystem or all-process diffing** in this iteration - pure churn, would drown signal.
- **No kernel/PPL, no stealth** (unchanged project invariant).
- **No claim of deterministic coverage** for user-directed harm. See NFR-4.
- Surfaces beyond loaded-module inventory (autostart, services, scheduled tasks, WMI) are a
  **later** iteration, deliberately deferred so attribution is designed, not accreted.

---

## Requirements

### R1 - Baseline the loaded-module inventory of long-lived processes

**User story:** As a victim, I want Sentinel to remember which modules a stable system/shell process
normally loads, so a new unexplained module in that process is noticeable.

Acceptance criteria (EARS):

- WHEN the reconciler runs, it SHALL enumerate loaded modules only for processes in a fixed
  **long-lived / low-churn** set (e.g. `explorer.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`,
  `csrss.exe`, `dwm.exe`, `sihost.exe`, `taskhostw.exe`, `RuntimeBroker.exe`), keyed by process
  **name** (not PID, which changes across reboots).
- WHERE a process is not inspectable (`NativeProcessMemory.CanInspect` returns false - PPL,
  anti-cheat, unresolved path), the reconciler SHALL skip it and SHALL NOT record an empty baseline
  for it.
- The baseline SHALL record, per process name, the set of module identities (normalized full path
  + module file name).
- The reconciler SHALL NOT clobber `MappedModuleCache` for a process it cannot inspect (respect the
  `EnumModules` side-effect contract).

### R2 - Persist the baseline reboot-durably

**User story:** As a victim, I want the baseline to survive reboots, so a module that was present at
baseline is not re-flagged as "new" every boot.

Acceptance criteria (EARS):

- The baseline SHALL be persisted under `%ProgramData%\Sentinel` using the reboot-durable
  `System.Text.Json` file pattern (like `kev_cache.json`), NOT the boot-bound `SecureCacheStore`.
- The baseline directory/file SHALL be created with SYSTEM+Admins-only ACL (mirror
  `EnsureRestrictedProgramDataDir`).
- IF the baseline file is missing or unreadable, the reconciler SHALL treat the current snapshot as
  the initial baseline (learn mode) and emit nothing on that pass.
- Baseline writes SHALL use `System.Text.Json` (no string-built JSON; constraint).

### R3 - Reconcile: surface only unattributable deltas

**User story:** As a victim, I want to see only the genuinely unexplained new modules, not every
benign update.

Acceptance criteria (EARS):

- WHEN a module is present in the current snapshot but absent from the baseline for that process,
  the reconciler SHALL run it through the attribution rules (R4) before surfacing.
- IF a delta is attributable to any trusted cause, the reconciler SHALL suppress it and fold it into
  the baseline silently.
- IF a delta survives all attribution rules, the reconciler SHALL emit exactly one Tier2 observe
  signal and record the module as "unexplained since `<UTC timestamp>`" in a durable side-ledger.
- The reconciler SHALL NOT re-emit a fresh full alert for an already-recorded unexplained module on
  every pass beyond a documented re-emit cadence (avoid log spam), but SHALL keep the durable
  "unexplained since X" record so it can feed correlation (R6).

### R4 - Attribution rules (the heart of the feature)

**User story:** As a maintainer, I want attribution to be provenance/behavior-based, not a growing
path whitelist, so it generalizes.

Acceptance criteria (EARS):

- A delta SHALL be attributed (suppressed) WHEN any of the following holds:
  1. **Trusted load position** - `ModuleIdentity.Evaluate(hostImagePath, modulePath, isMsSigned)`
     returns `Allowed` (reuses the existing trust ladder: os-servicing, keep-tree, signed
     Program Files, Roslyn shadow-copy, GPU ICD, app-directory, etc.).
  2. **Active servicing window** - a Windows servicing actor is/was recently active (lift the
     existing `IsServicingProcessActive` check into a shared helper; optionally a short
     "recently active" grace window).
  3. **Known-prior publisher on THIS machine** - the module's Authenticode signer CN has been seen
     in a prior accepted baseline on this host (a per-machine first-seen-publisher ledger). This is
     the one signal a *stolen* cert cannot fully launder: even a valid cert is "new to this host"
     the first time.
- WHERE none of the above holds, the delta is **unattributable** and is surfaced per R3.
- Attribution SHALL be computed with the cached signer/verify services (`SignerTrustService`,
  `SecurityValidation.VerifyAuthenticodeSignature`) to bound cost (NFR-1).

### R5 - Observe-only output contract

**User story:** As a victim, I want reconciliation to never destroy anything on its own.

Acceptance criteria (EARS):

- Every emitted reconciliation signal SHALL have `Tier = Tier2Indicator`, `AuthorizedResponse =
  LogOnly`, and `Family = null` (so `KillAuthorized` is false and `ClassifyTerminalOutcome` never
  treats it as kill-grade).
- WHEN `ActiveResponse = true`, a reconciliation signal SHALL still be `LogOnly` (the Tier2 log-only
  contract, enforced in `AdvancedResponseEngine.HandleAsync`).
- The signal metadata SHALL include the host process, the module path, the signer (if any), the
  attribution outcome, and "unexplained since" timestamp, for explainability and dashboard review.

### R6 - Durable observation feeds correlation without self-confirming

**User story:** As a victim, if the unexplained module ever *does* something terminal, I want the
prior suspicion to count.

Acceptance criteria (EARS):

- The reconciler SHALL re-emit the durable "unexplained since X" observation on its cadence so it
  can land within the correlation window if a correlating leg appears.
- A reconciliation observation SHALL NOT, alone, satisfy a kill-grade composite (it is one weak
  observe leg; consistent with observe-until-chain and the evidence-independence work).

---

## Non-functional requirements

### NFR-1 - Bounded cost
- The reconciler SHALL run on a slow cadence (default >= 5 min), over a **small fixed** process set,
  and SHALL reuse cached signer/verify results. Module enumeration of ~10 processes on a slow
  cadence is the cost ceiling; it SHALL NOT enumerate all processes.

### NFR-2 - Graceful degradation
- A failure to inspect any single process, verify any signature, or read/write the baseline SHALL
  NOT crash the monitor or the host; errors are logged (`LogDebug`), and the pass continues.

### NFR-3 - Constraint compliance
- DI-injected; `CancellationToken` threaded through every async path; no `Thread.Sleep` without
  cancellation; no static mutable state (baseline held in the instance / on disk); `System.Text.Json`
  only; no string-interpolated shell.

### NFR-4 - Honest ceiling (documented, not overclaimed)
- The THREAT_MODEL SHALL state plainly: reconciliation raises the attacker's cost and shrinks the
  blind spot (an unexplained module injected into a low-churn host is surfaced regardless of what it
  does), but it does **not** deterministically stop user-directed harm - a payload loaded into a
  high-churn host (browser/game) that legitimately loads many third-party modules can blend in, and
  a validly-signed module that never behaves badly is surfaced for **review**, not killed.

### NFR-5 - No new destructive surface
- This feature introduces no new response action and no host mutation. It is observation + a durable
  review ledger only.
