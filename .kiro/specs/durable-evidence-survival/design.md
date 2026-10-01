# Durable Evidence Survival (B1) - Design

Implements the requirements in `./requirements.md`. This design **reuses existing abstractions**
(evidence packs, the HMAC-signed proxy, the append-only audit log, the last-gasp exit hook) rather
than introducing new subsystems. It fits the Sentinel pipeline and constraints
(`#[[file:../../../docs/design.md]]`, `#[[file:../../../docs/constraints.md]]`).

---

## Existing code this builds on

| Component | File | Role in this feature |
|-----------|------|----------------------|
| `AutoIncidentReporter` | `src/Sentinel.Core/AutoIncidentReporter.cs` | Writes + seals packs; `HandleDetectionAsync` is where the off-host mirror step is added (after `WriteEvidencePackAsync` / `SealPackIntegrityAsync`). |
| `ResponsePolicy.ShouldAutoReportIncident` | `src/Sentinel.Core/ResponsePolicy.cs` | Existing silent-observe / chain-confirmed gate. The mirror reuses it - no new gating logic. |
| `ProxyAuthHelper` | `src/Sentinel.Core/ProxyAuthHelper.cs` | `CreateAuthenticatedPost` + `CreatePinnedHttpClient`; the only sanctioned outbound-auth path (FR-11). |
| `ThreatReportService` | `src/Sentinel.Core/ThreatReportService.cs` | Template + home for a new signed `ReportEvidenceAsync` route; `CanReport()` fail-closed pattern reused verbatim. |
| `AntiTamperGuard` | `src/Sentinel.Core/AntiTamperGuard.cs` | `CheckServiceRegistration`, `RegisterExitHandler`, `WriteLastGasp` - extended for stop classification (R1). |
| `SentinelService` / `SentinelGuardService` | `src/Sentinel.Service/SentinelService.cs`, `Program.cs` | Service stop path (`finally`, `OnStop`) - signals expected-stop vs unexpected. |
| `JsonlEventLogger` | `src/Sentinel.Core/JsonlEventLogger.cs` | Append-only `audit-*.jsonl` (SYSTEM+Admins ACL) - the durable local sink for R1/R3. |
| `ThreatReportingConfig` | `src/Sentinel.Core/Models.cs` (config types) | Extended with off-host mirror flag (R5). |

---

## R1 - Hostile-stop classification (alert-before-suppression)

**Approach:** distinguish an *expected* stop from an *unexpected* one, then record accordingly.
The Service already knows when it is stopping cooperatively; the missing signal is intent.

1. **Expected-stop token.** Add a process-lifetime flag set by the *legitimate* shutdown paths:
   - `SentinelService` stop `finally` block and `SentinelGuardService.OnStop` set
     `ShutdownContext.MarkExpected(reason)` before teardown, where reason 
     {`ServiceControllerStop`, `SystemShutdown`, `Upgrade`, `Uninstall`}.
   - OS shutdown is detected via `SessionEnding` / `SERVICE_CONTROL_SHUTDOWN` already delivered to
     the service host.
   - `ShutdownContext` is a small internal, thread-safe holder (a single `volatile` reason field +
     timestamp). No static *mutable domain state* beyond this deliberate process-lifetime signal;
     documented and justified against the "no static mutable state" rule as lifecycle metadata.

2. **Classification in the exit hook.** Extend `AntiTamperGuard.WriteLastGasp(reason)`:
   - If `ShutdownContext` shows an expected reason -> write a normal lifecycle record (no tamper
     detection).
   - If the process is exiting with **no** expected reason recorded -> classify as
     **suspicious stop** and:
     - Append a `PRE_ACTION`-style record to the append-only `audit-*.jsonl` via
       `JsonlEventLogger` (reuse `LogAuditBeforeActionAsync` shape, new `AuditType = "SERVICE_STOP_SUSPECTED"`).
     - Emit a Tier1 `SignalType.AntiTamper`, `ResponseAction.LogOnly` `DetectionEvent`
       ("Anti-Tamper: Service Stopped Unexpectedly") *if the detection engine is still reachable*
       during shutdown; otherwise the audit-log write is the durable fallback.

3. **Best-effort / non-blocking.** All of this runs inside the existing synchronous exit hook,
   stays wrapped in try/catch, and must complete fast (no network on the shutdown thread - see R2
   note). It never throws and never delays OS shutdown (NFR-2).

**Why not react at SCM level with a driver/PPL?** Forbidden by constraints. The honest move is to
make the stop *observable and durable*, not to prevent it.

## R2 - Off-host evidence mirror

**Where:** a new step at the end of `AutoIncidentReporter.HandleDetectionAsync`, after the local
pack is written and sealed, gated by `_config` (off-host enabled) AND the existing
`ResponsePolicy.ShouldAutoReportIncident` result that already let us get this far.

**Transport:** add `ThreatReportService.ReportEvidenceAsync(EvidenceSummary summary)`:
- Reuses `CanReport()` (fail-closed: `Enabled` + `ProxyEndpoint` + `HasSharedSecret`).
- Builds the payload with `System.Text.Json` (no string-built JSON).
- Signs + sends via `ProxyAuthHelper.CreateAuthenticatedPost(endpoint, "/report/evidence", json, config)`.
- Catches all exceptions, logs at Debug, never throws (mirrors `SendReportAsync`).

**Payload (`EvidenceSummary`)** - minimal, no file contents, no secrets:
- `reportId`, `sentinelVersion`, `host` (machine name), `sealedUtc`
- detection summary: `rule`, `signalType`, `tier`, `confidence`, `processName`, `processId`
- `indicators` (hashes/ips/urls) from the existing `ExtractIndicators`
- `manifestSha256` + `manifestHmacSha256` (origin proof, R4) from the sealed manifest
- optionally a compressed `incident_report.txt` **only if** a future config explicitly opts in;
  default is summary-only to keep the honest, minimal-exfil posture.

**Shutdown-path caveat:** R1 runs on a dying process, so it must NOT attempt a network upload there
(no time, may block). Off-host mirroring is therefore tied to R2's normal detection path (which runs
while healthy). The B1 story is covered because chain-confirmed detections that *precede* a
suppression already mirror off-host in real time; the suspicious-stop record itself is captured
locally (R1) and, if a detection is emitted before exit, mirrored by the normal R2 path.

## R3 - Local append-only durability

Reuse the existing `audit-*.jsonl` mechanism (already `FileMode.Append`, `FileShare.Read|Delete`,
SYSTEM+Admins ACL, 90-day prune). Add the `SERVICE_STOP_SUSPECTED` audit type. No new store.
Document honestly that local admin can still delete these (R3 AC + THREAT_MODEL B1 stays HIGH).

## R4 - Portable origin proof

Ship the existing machine-bound `manifestHmacSha256` as origin proof only. For portable
verification, the Worker (deployed out-of-band, not in this repo) can return and store a
**server-side signed receipt** (server key, never a host secret leaving the box). This design
documents the Worker contract (`/report/evidence` accepts the summary, verifies the client HMAC,
stores it, optionally returns a receipt id) but does not implement the Worker here.

## R5 - Config & transparency

Extend `ThreatReportingConfig` (or the incident-reporting config) with:
- `MirrorEvidenceOffHost` (bool, **default false**)
- reuse `ProxyEndpoint` + `ProxySharedSecret` (no new secret surface)

Compiled defaults only; disk JSON is not loaded (constraints). All steps logged around execution.

---

## Data / control flow (added path shown with )

```
Detection  AutoIncidentReporter.HandleDetectionAsync
                ShouldAutoReportIncident (existing gate)
                WriteEvidencePackAsync + SealPackIntegrityAsync (existing)
                 if MirrorEvidenceOffHost && CanReport:
                      ThreatReportService.ReportEvidenceAsync(EvidenceSummary)
                         ProxyAuthHelper.CreateAuthenticatedPost (HMAC, fail-closed)

Service stop   ShutdownContext.MarkExpected(reason)  [legitimate paths only]
AntiTamperGuard exit hook   WriteLastGasp classifies:
    expected  -> lifecycle record
    unexpected -> SERVICE_STOP_SUSPECTED (append-only audit) + Tier1 LogOnly AntiTamper (if reachable)
```

---

## Testing strategy (feeds tasks + constraints)

Per `constraints.md` testing rules and NFR-5:

- **Stop classification:** unit test that an expected reason -> lifecycle (no tamper detection), and
  absence of a reason -> `SERVICE_STOP_SUSPECTED` audit record + Tier1 `AntiTamper` LogOnly.
- **Fail-closed mirror:** `ReportEvidenceAsync` with missing/short secret -> no request sent
  (assert `CanReport()` false path), local pack still written.
- **Signed mirror:** with a valid secret, assert the request carries `X-Sentinel-Timestamp`,
  `X-Sentinel-Nonce`, `X-Sentinel-Signature` and NO secret header (reuse `ProxyAuthHelper` tests).
- **Tier2 gate:** a Tier2 detection never triggers the mirror (ShouldAutoReportIncident false).
- **Payload minimality:** assert no file contents / secrets in the serialized `EvidenceSummary`.
- **Graceful degradation:** exit-hook classification never throws even if the logger is disposed.
- **No new proactive host mutation** is introduced, so no `ProductPosture` default-deny test is
  required - but a test SHALL assert `MirrorEvidenceOffHost` defaults to false.
