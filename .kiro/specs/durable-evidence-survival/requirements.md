# Durable Evidence Survival (B1) - Requirements

**Roadmap link:** `docs/ROADMAP.md` -> Theme 1 (Local admin can stop the service, residual HIGH)
and Theme 4 (Evidence durability & trust).

**Threat model link:** `docs/THREAT_MODEL.md` -> Bypass Scenario **B1** ("Attacker has local
admin"). Honest ceiling: userland cannot beat local admin. The goal is **not** to prevent
suppression - it is to make the *evidence of the attack (and of the suppression itself)* survive
and be noticed, so the attacker cannot both win and erase the trail quietly.

Reference docs (authoritative): `#[[file:../../../docs/requirements.md]]`
and `#[[file:../../../docs/constraints.md]]`.

---

## Problem statement

Today, when a local admin (or malware running as SYSTEM/admin) attacks the host:

- `AutoIncidentReporter` writes a sealed evidence pack to `%ProgramData%\Sentinel\IncidentReports`.
- `AntiTamperGuard.CheckServiceRegistration` detects **deletion/disable** of the service and
  re-registers it.

But two gaps remain that let an admin win *quietly*:

1. **Clean SCM stop is not treated as hostile.** `sc stop Sentinel` / SCM stop of a still-registered
   service triggers only the graceful shutdown path (`SentinelService` stop, `WriteLastGasp`). No
   detection is emitted and no evidence is flushed before the process dies.
2. **Evidence is local-only.** All packs, JSONL, and audit logs live under `%ProgramData%\Sentinel`,
   which a local admin can read, tamper with, or delete after suppression. Nothing is mirrored
   off-host, so removing the folder erases the trail.

## Goals

- Detect and record when the Service is stopped in a way consistent with tampering, and preserve
  that observation durably.
- Optionally mirror sealed evidence packs off-host so suppression cannot erase them.
- Do all of this while honoring Sentinel's constraints: userland-only, transparent, fail-closed
  outbound, HMAC-signed, compiled-config, no covert exfil, no overclaiming.

## Non-goals (explicit)

- Preventing a local admin from stopping the service (impossible in userland - do not attempt
  kernel/PPL tricks; see NFR-7).
- Any covert/stealth exfiltration. Off-host mirroring is opt-in, signed, and documented.
- Filing with law enforcement (unchanged; packs remain victim-filed).

---

## Requirements

### R1 - Detect hostile-looking Service stop (alert-before-suppression)

**User story:** As a victim, when an attacker stops Sentinel to go quiet, I want a durable record
that the service was stopped under suspicious circumstances, so the gap in coverage is evidence,
not silence.

Acceptance criteria (EARS):

- WHEN the Service enters its stop path, the system SHALL classify the stop as either **expected**
  (OS shutdown, upgrade/uninstall, service-manager restart) or **unexpected/suspicious**.
- WHEN a stop is classified as unexpected/suspicious, the system SHALL write a final durable record
  (extending the existing `WriteLastGasp` / audit-log path) that includes timestamp, uptime, last
  heartbeat, recent detection context if available, and the classification reason.
- WHEN a stop is classified as expected, the system SHALL record it as a normal lifecycle event and
  SHALL NOT emit a tamper detection.
- The stop-classification and final write SHALL be best-effort and SHALL NOT block or delay OS
  shutdown, and SHALL NOT throw out of the shutdown path (NFR-2, graceful degradation).
- The final record SHALL be written to the append-only audit trail (SYSTEM+Admins ACL, the existing
  `audit-*.jsonl` pattern) so it is not silently overwritten.

### R2 - Off-host evidence mirror (opt-in, signed, fail-closed)

**User story:** As a high-profile target, I want confirmed-attack evidence copied off my machine so
a local admin who suppresses Sentinel cannot also delete the proof.

Acceptance criteria (EARS):

- WHEN an evidence pack is written for a chain-confirmed/reportable detection AND off-host mirroring
  is enabled in compiled config, the system SHALL upload a signed evidence summary off-host via the
  existing `ProxyAuthHelper` HMAC-signed path (new Worker route, e.g. `/report/evidence`).
- WHEN off-host mirroring is not enabled OR the shared secret is missing/short (< 16 chars), the
  system SHALL skip the upload silently (fail closed, per FR-11) and continue writing the local pack.
- The upload SHALL be HMAC-signed with headers `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`,
  `X-Sentinel-Signature` only, and SHALL NEVER transmit the shared secret (FR-11).
- The upload SHALL NOT transmit user file contents or secrets - only the detection summary,
  indicators, integrity hashes, and the machine-bound seal as an **origin proof** (see R4).
- The upload SHALL never crash the reporting path on failure (best-effort, Debug-logged), mirroring
  `ThreatReportService` behavior.
- Off-host mirroring SHALL be gated by the same silent-observe / chain-confirmed gate that already
  fronts `AutoIncidentReporter` (`ResponsePolicy.ShouldAutoReportIncident`). Tier2 never triggers it.

### R3 - Local append-only durability hardening

**User story:** As a user, I want the incident trail to be resistant to casual deletion so evidence
persists as long as userland ACLs allow.

Acceptance criteria (EARS):

- The incident/audit trail SHALL continue to use append-only files with SYSTEM+Admins ACLs (existing
  pattern) and SHALL record a durable "suppression suspected" marker from R1.
- The system SHALL NOT claim tamper-proof local storage; documentation SHALL state that a local admin
  can still delete local files (honesty requirement).

### R4 - Portable origin proof for off-host evidence

**User story:** As someone verifying evidence later, I want to confirm an off-host copy genuinely
came from the victim machine.

Acceptance criteria (EARS):

- The off-host summary SHALL include the existing machine-bound manifest HMAC (`MANIFEST.hmac` /
  `evidence_manifest.json`) as an **origin proof**, with documentation that it verifies only on the
  original host (the current `VERIFY.txt` limitation).
- WHERE a portable (non-machine-bound) verification is desired, the design SHALL evaluate adding a
  server-side seal at the Worker (signed receipt) rather than shipping any host secret off-box.

### R5 - Configuration & transparency

Acceptance criteria (EARS):

- New behavior SHALL be controlled by compiled defaults (constraints: compiled config only; disk
  JSON is not loaded), reusing/extending `ThreatReportingConfig` and the incident-reporting config.
- Off-host mirroring SHALL default to **disabled** on clean installs (opt-in, matches the honest,
  no-covert-exfil posture).
- All actions (stop classification, mirror attempt, mirror result) SHALL be logged before/around
  execution, consistent with the transparency requirement.

---

## Constraints this feature must obey (from constraints.md / requirements.md)

- **FR-11 fail-closed HMAC** on every outbound byte; never send the secret.
- **Compiled config only**; uninstall is the off switch.
- **Userland only / transparent**: no kernel, no persistence tricks, no self-hiding; the stop
  reaction stays a normal userland observer.
- **Tier2 never acts**; off-host mirror rides the chain-confirmed silent-observe gate.
- **Graceful degradation**: shutdown-path work is best-effort and never throws.
- **Honest ceiling**: docs and any user-facing text must state local admin can still win; this is
  durability + alerting, not invincibility.
