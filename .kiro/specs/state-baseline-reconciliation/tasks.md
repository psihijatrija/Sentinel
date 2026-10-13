# State Baseline & Reconciliation (Drift Detection) - Tasks

Implementation plan for `./design.md`. Each task is scoped, references the code it touches, and maps
back to requirements. Do them in order; the post-task test hook runs the suite.

**Execution:** run all tasks to completion autonomously (see `.kiro/steering/workflow.md`). When
every task is done and verified (0W/0E build + green tests), finish with the release task, which
bumps one patch per the strict versioning policy and builds/commits/pushes/publishes.

- [ ] 1. `ServicingWindow` shared helper
  - Lift `FileActivityMonitor.IsServicingProcessActive()` into an internal shared
    `ServicingWindow.IsActive()` in `Sentinel.Core` (keep the original delegating to it to avoid
    behavior change). Optional: record a last-active UTC for a short "recently active" grace.
  - _Requirements: R4_

- [ ] 2. `ModuleBaselineSnapshot` + `ModuleBaselineStore`
  - Add the snapshot model and the reboot-durable System.Text.Json store under
    `%ProgramData%\Sentinel\baseline`, SYSTEM+Admins ACL, load-failure -> empty (learn mode).
  - _Requirements: R2_

- [ ] 3. `StateReconciliationMonitor : BackgroundService` skeleton
  - Ctor DI (DetectionEngine, SignerTrustService, ModuleBaselineStore, ILogger). ExecuteAsync with
    settle delay + cancellation-safe cadence loop. No work yet beyond load/save round-trip.
  - _Requirements: R1, NFR-2, NFR-3_

- [ ] 4. Snapshot the long-lived process set
  - Resolve the fixed name set to live PIDs; `CanInspect` gate (skip PPL/anti-cheat, no baseline
    clobber); `EnumModules` per inspectable PID. Build current module-set-by-process.
  - _Requirements: R1, NFR-1_

- [ ] 5. `TryAttribute` + reconcile diff
  - Implement attribution order (ModuleIdentity.Evaluate -> ServicingWindow -> known-publisher).
    Diff current vs baseline; suppress attributed deltas (fold into baseline + grow KnownPublishers
    from accepted signers only); mark unattributable deltas UnexplainedSince.
  - _Requirements: R3, R4_

- [ ] 6. Observe-only emit + durable re-emit
  - Emit the Tier2/LogOnly/Family-null "State Drift" event for new unattributable deltas; re-emit
    durable unexplained observations on ReEmitCadence for correlation.
  - _Requirements: R3, R5, R6_

- [ ] 7. DI wiring
  - Register `ModuleBaselineStore` + `StateReconciliationMonitor` singletons; add the monitor to the
    SystemIntegrity MonitorGroup in `Sentinel.Service/Program.cs`.
  - _Requirements: R1_

- [ ] 8. Tests
  - Pure-logic: attribution suppresses (identity-allowed, servicing-window, known-publisher); an
    unsigned/new-publisher module injected into `explorer.exe` surfaces; signed-known-publisher and
    servicing suppressed. Contract: emitted event Tier2Indicator + LogOnly + Family null; observe
    holds under ActiveResponse=true through AdvancedResponseEngine. Store: reboot-durable round-trip;
    missing file -> learn mode (no emit).
  - _Requirements: R1-R6, R5 (contract)_

- [ ] 9. Docs
  - THREAT_MODEL: new "silent / user-directed harm" section with the honest ceiling (NFR-4).
    requirements/design updates if behavior surface changed. CHANGELOG entry headed with the
    released version.
  - _Requirements: NFR-4_

- [ ] 10. Release
  - `installer/release.ps1` (bump one patch, build, stamp, installer), then
    `D:\Gorstak\push.ps1 -ProjectFilter sentinel`. Build 0W/0E + full suite green first.
