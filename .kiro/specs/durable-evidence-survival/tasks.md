# Durable Evidence Survival (B1) - Tasks

Implementation plan for `./design.md`. Each task is scoped, references the code it touches, and
maps back to requirements. Do them in order; the post-task test hook runs the suite after each.

**Execution:** run all tasks to completion autonomously without pausing between them (see
`.kiro/steering/workflow.md`). When every task is done and verified (0W/0E build + green tests),
finish with the release task below, which bumps the version by one patch per the strict versioning
policy and builds/commits/pushes/publishes.

> **STATUS (reconciled 2026-09-21): SHIPPED in v2.5.8.** Tasks 1-10 are implemented, tested, and
> documented in the current codebase - the checkboxes below were never updated after the work
> landed. Verified against the tree:
> - `ShutdownContext` (`src/Sentinel.Core/ShutdownContext.cs`); `MarkExpected` wired into
>   `SentinelService.StopAsync`, `Program.cs` OS-shutdown (`ApplicationStopping`), and the watchdog
>   stop path.
> - `AntiTamperGuard.WriteLastGasp` classifies expected vs suspicious and emits the
>   `SERVICE_STOP_SUSPECTED` audit record + Tier1 `AntiTamper` LogOnly detection.
> - `JsonlEventLogger.LogServiceStopSuspected` / `LogServiceStopExpected` audit shapes.
> - `AutoIncidentReportingConfig.MirrorEvidenceOffHost` (default **false**), `EvidenceSummary`,
>   `ThreatReportService.ReportEvidenceAsync`, and `AutoIncidentReporter.MirrorEvidenceOffHostAsync`.
> - Tests: `DurableEvidenceStopClassificationTests.cs`, `DurableEvidenceMirrorTests.cs` (green).
> - Docs: `THREAT_MODEL.md` B1 (durable-evidence additions) + B13 (`/report/evidence` Worker route).
>
> Only the Worker deployment (task 10's out-of-band route) lives outside this repo, as designed.
> No further code work is required; this spec is retained as the record of the shipped design.

- [x] 1. Add `ShutdownContext` lifecycle signal
  - Create a small thread-safe `ShutdownContext` (internal, `Sentinel.Core`) holding a
    `volatile` expected-stop reason + timestamp, with `MarkExpected(reason)` and `TryGetExpected(...)`.
  - Document the deliberate process-lifetime exception to the "no static mutable state" rule.
  - _Requirements: R1_

- [x] 2. Mark expected stops from legitimate shutdown paths
  - Call `ShutdownContext.MarkExpected(...)` in `SentinelService` stop `finally` and
    `SentinelGuardService.OnStop`, and on `SERVICE_CONTROL_SHUTDOWN` / `SessionEnding`.
  - Ensure upgrade/uninstall paths (installer-triggered stop) set the appropriate reason.
  - _Requirements: R1_

- [x] 3. Classify stop in the exit hook + durable record
  - Extend `AntiTamperGuard.WriteLastGasp` to branch on `ShutdownContext`:
    expected -> lifecycle record; unexpected -> `SERVICE_STOP_SUSPECTED` append-only audit entry
    via `JsonlEventLogger` + a Tier1 `AntiTamper` `LogOnly` detection if the engine is reachable.
  - Keep it best-effort, non-blocking, never-throw; no network here.
  - _Requirements: R1, R3_

- [x] 4. Add `SERVICE_STOP_SUSPECTED` audit shape to `JsonlEventLogger`
  - Add an audit method (or reuse `LogAuditBeforeActionAsync` with a new `AuditType`) for the
    suspected-stop record; confirm append-only + SYSTEM+Admins ACL + 90-day prune still apply.
  - _Requirements: R1, R3_

- [x] 5. Extend config for off-host mirroring
  - Add `MirrorEvidenceOffHost` (default **false**) to `ThreatReportingConfig` (or incident config);
    reuse `ProxyEndpoint` + `ProxySharedSecret`. Compiled defaults only.
  - _Requirements: R5_

- [x] 6. Add `EvidenceSummary` + `ThreatReportService.ReportEvidenceAsync`
  - Define `EvidenceSummary` (reportId, version, host, sealedUtc, detection summary, indicators,
    manifestSha256, manifestHmacSha256). Serialize with `System.Text.Json`.
  - Implement `ReportEvidenceAsync` reusing `CanReport()` (fail-closed) +
    `ProxyAuthHelper.CreateAuthenticatedPost("/report/evidence", ...)`; never throw.
  - _Requirements: R2, R4, R5_

- [x] 7. Wire the mirror step into `AutoIncidentReporter.HandleDetectionAsync`
  - After `WriteEvidencePackAsync` + `SealPackIntegrityAsync`, if `MirrorEvidenceOffHost` and
    `CanReport()`, build an `EvidenceSummary` (reuse `ExtractIndicators` + sealed manifest hashes)
    and call `ReportEvidenceAsync`. Keep the local pack write independent of mirror success.
  - _Requirements: R2, R4_

- [x] 8. Tests - stop classification
  - Expected reason -> lifecycle only (no tamper detection). No reason -> `SERVICE_STOP_SUSPECTED`
    audit record + Tier1 `AntiTamper` LogOnly. Exit-hook never throws when logger disposed.
  - _Requirements: R1, R3; NFR-2, NFR-5_

- [x] 9. Tests - off-host mirror contract
  - Missing/short secret -> no request, local pack still written (fail-closed).
  - Valid secret -> request has `X-Sentinel-Timestamp`/`-Nonce`/`-Signature`, no secret header.
  - Tier2 detection -> mirror never fires. `EvidenceSummary` carries no file contents/secrets.
  - `MirrorEvidenceOffHost` defaults to false.
  - _Requirements: R2, R4, R5; FR-11_

- [x] 10. Docs - honest ceiling + Worker contract
  - Update `docs/THREAT_MODEL.md` B1 with the new durable-record + off-host-mirror mitigation and
    keep residual risk HIGH (local admin can still delete local files / disable mirror).
  - Document the `/report/evidence` Worker route contract (verifies client HMAC, stores summary,
    optional signed receipt) - Worker itself is deployed out-of-band, not in this repo.
  - Add a CHANGELOG entry.
  - _Requirements: R3 (honesty), R4_

- [ ] 11. Release
  - After tasks 1-10 are done and verified (0W/0E build + green suite), run the end-of-work
    release: bump the version by exactly one patch per the strict policy, build the installer,
    commit, push to origin, and publish the GitHub release.
  - Run `installer/release.ps1` (use `-DryRun` first to confirm the computed next version).
  - _Policy: `.kiro/steering/workflow.md`_
```
