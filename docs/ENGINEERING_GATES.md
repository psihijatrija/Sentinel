# Engineering improvement gates

These are acceptance criteria for improving Sentinel, not new ratings or a promise of universal protection. Ratings must name a tested commit, supported Windows configuration, workload and known limits. Historical numerical scores in QUALITY_REVIEW.md are not a current benchmark.

## 3.3.3 evidence

Incident housekeeping now preserves actionable evidence without a receipt and atomically preserves newer PID owners when older incidents close. Nine added regression cases cover Open/Active missing receipts, reopened incidents, observation expiry, newer-owner receipt routing and four incomplete outcomes. All 23 incident tests pass in a temporary net10.0 host compiling production IncidentManager and JsonlEventLogger source against the built Core dependencies; the same tests report four failures when the original expiry/mapping behavior is restored in an external copy. The shipping solution still targets Windows Framework. The portable host does not validate Windows ACLs, native process identity or service lifecycle.

Full Release cross-compilation passes with zero warnings/errors; 22 dashboard and 8 independent Worker tests pass. Native Windows tests and installer execution were not run in this Linux workspace. Metadata was prepared with `installer/release.ps1 -PrepareOnly`; preparation does not publish an installer.

## Evidence required for higher ratings

| Area | Acceptance evidence still needed |
| --- | --- |
| Architecture and incident continuity | Durable versioned incident snapshots; crash/corruption/disk-full tests; no stale PID bindings or replayed response authorization on restart; bounded retention of unresolved evidence |
| Telemetry and host reconciliation | Per-provider availability, event-loss and backlog measurements; disable/re-enable and inventory-gap recovery tests on supported Windows variants |
| Correlation and response safety | Process-generation-aware incident grouping; concurrent receipt/closure and PID-reuse tests; repeatable benign/adversarial corpus with measured false positives and misses |
| Memory, modules and credentials | Native Windows/PPL/anti-cheat compatibility, actual read/injection scenarios and controls; claims limited to observed supported telemetry |
| Certificates, network and repair | Enterprise/private PKI, VPN/DHCP/IPv6, domain-policy conflicts, UAC, journal ACLs, interrupted mutations and reboot tests with independently verified restoration |
| IPC and service boundaries | Adversarial client-token/ACL tests on the supported custom Windows image; malformed/stalled/replayed requests; no user-controlled expansion of privilege |
| Evidence and privacy | Corruption/truncation checks, independently retained checkpoints, explicit privacy/export review; no claim that a local administrator cannot rewrite all local evidence |
| Offline ML | Published model/data provenance, held-out metrics, calibration and drift evaluation; missing/stale model coverage visible to operators |
| Diagnostics and usability | Interactive dashboard/UAC/accessibility testing; every success label backed by a verified receipt and incomplete coverage visible |
| Regression and performance | Full Windows suite on the release commit; reproducible event-rate, CPU/memory/disk, loss and response-latency budgets with raw results |
| Packaging and update integrity | Signed artifacts and verification, interrupted install/update recovery, rollback authorization and actual installer lifecycle tests |

The legacy Worker is an independent component, not a required endpoint capability. Offline product policy excludes live cloud reputation/reporting; adding those to improve an old score would require an explicit product-policy decision. No kernel enforcement, administrator-compromise resistance, perfect detection or router-clean guarantee is implied by completing these gates.
