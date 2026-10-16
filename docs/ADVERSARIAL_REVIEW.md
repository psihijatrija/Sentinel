# Adversarial source review — 3.1.8 work

Review scope: response selection/coordinator, incident recovery, offline replay,
restore journals, named-pipe requests, evidence exports, Worker authentication and
checkpoint storage. This is a source review with regression cases prepared for the
final Windows validation gate. It is not a live penetration test, malware benchmark,
or a claim that the whole product has no vulnerabilities.

## Findings addressed

| Finding | Severity | Change |
| --- | --- | --- |
| Public client compatibility credential could authorize evidence writes and external threat submissions | High | All `/report/*` routes require a separate deployment-only credential, distinct from the public lookup credential. Client reporting also refuses the public credential. Lookup behavior is retained. |
| Requested actions were recorded as executed even when the engine chose LogOnly; those records could suppress a later real response | High | Coordinator consumes the response engine's actual disposition. Observed, attempted, failed and confirmed outcomes are distinct. Only confirmed outcomes enter successful-response history or mark an incident Responded. |
| Removing an apparently idle PID semaphore could race with an arriving waiter and create two locks for one PID | Medium | Fixed bounded lock stripes are retained for the coordinator lifetime; pruning never replaces an in-use serialization boundary. |
| Unbounded pipe request and idle client could hold the sequential IPC host | Medium | 64 Ki-character request limit and five-second connection deadline covering reads and writes. |
| Recovery journal could redirect read-back toward network/device paths or describe unsupported state | Medium | Bounded journal, schema/state/hash/path validation, local absolute destinations, rejection of links, DOS devices and alternate streams. No automatic replay of restore or response actions. |
| Old evidence could reach process response after a PID was reused | High, partially mitigated | Refuse process actions if the current generation started after the evidence, or identity cannot be queried. This does not eliminate the check/use race in existing termination helpers; see residuals. |
| Incident history vanished on restart; naive restoration could rebind stale PID authority | Medium | Atomic bounded snapshots, collision-resistant IDs, detached history, retained unreadable state, explicit pending evaluations, and recovered records excluded from live PID/hash grouping. |
| Private names and URLs were transmitted before the Worker discarded them | Medium | Source-side allowlist sends only hashed report identity, content hashes and checkpoint coordinates. Private exports can also remove absolute dates. |
| Collection errors could look like an empty healthy inventory | Medium | Root-store and WFP collectors expose failures through sensor progress. WFP collection requires successful command exit and bounded valid XML. |

## Residual risks and verification limits

- Process termination/tree traversal still uses existing helpers that can reopen PIDs.
  A timestamp check narrows reuse exposure but is not a handle-bound identity guarantee.
  Some inline monitor remediations bypass the central coordinator; this review does
  not certify them all. These remain priority response-safety work.
- Response logs from legacy helpers often establish an attempt rather than a verified
  host result. The coordinator now reports that limitation instead of claiming success.
- Root removal remains the owner's deterministic live-store policy. OS root-program
  stamps are safety anchors; private/enterprise CA compatibility still needs actual
  Windows evaluation. No new certificate trust exception was introduced.
- An administrator or kernel attacker can rewrite local files and stop a userland
  service. Independently retained off-host checkpoints can reveal inconsistent history;
  they cannot prevent host compromise or independently prove the originating machine.
- Worker nonce history is per isolate. A replay reaching another isolate within the
  timestamp window is not globally prevented. Content-addressed anchors are idempotent;
  global report replay prevention needs durable coordination.
- A deployment reporting credential authenticates a deployment, not individual devices.
  Compromise of that credential permits forged submissions within that deployment.
- Local incident checkpoint writes are synchronous. Snapshot size and retained timeline
  detail are bounded, but sustained event-rate/resource measurements remain necessary.
- Unknown sensor coverage stays Unknown. The remaining uninstrumented monitors, optional
  Windows components, VPN changes, enterprise PKI, and debloated installations need
  deployment validation. Source inspection cannot supply those measurements.

## Deployment requirements

Worker mutations now need `SENTINEL_REPORT_SHARED_SECRET` (at least 32 characters),
distinct from `SENTINEL_SHARED_SECRET`. Store the matching client value as
`ReportingProxySharedSecret` through the existing administrator-protected encrypted
configuration mechanism, then restart the service. Do not commit the credential.
`EVIDENCE_STORE` KV is additionally required for evidence anchoring. Without these,
reports fail closed; local detection and local evidence continue. The dashboard
shows NotConfigured, Pending, Failed or Confirmed anchoring status.

The Worker also retains the existing `RATE_LIMITER` binding and upstream API secrets
for the corresponding services. Copying JavaScript alone cannot provision bindings
or deployment secrets. No production Cloudflare deployment was performed here.

Additional source findings addressed during the same pass:

- The enrichment bus's DropOldest channel did not count actual evictions; overload
  could therefore disappear from its health statistics. Eviction now increments the
  existing drop counter directly.
- ML initialization could publish its completion flag before models were ready,
  and one model failure disabled all model types. Initialization now publishes
  completion last and isolates failures by model.
- Loose model files were loaded without a release-bound byte identity. Runtime
  loading now snapshots bounded bytes, checks compiled release-reviewed hashes and
  loads the verified snapshot, avoiding a file-swap between hashing and loading.
- The trainer printed held-out metrics and then shipped a different model refitted
  on the full dataset. It now saves the evaluated train-only model and writes a
  provenance/evaluation report. Existing shipped models were not retrained and their
  unavailable original provenance is not invented.

## Follow-up, 2026-10-16 (unreleased)

The chain tracer now records termination only after a handle-bound creation-time,
image and critical-status check, successful TerminateProcess and same-handle wait.
The central plain-kill fallback uses that path too. This removes reopening the PID
between those checks and termination in these paths. It does not establish generation
identity for an ancestor whose creation time was never captured in the original graph.
Other legacy/inline action helpers remain outside this guarantee. No native Windows
validation has been executed for this change.

Process reputation is bounded (two workers, 256 pending), with exact oldest-item
loss accounting and original observation timestamps. The legacy prefix-based self
exemption was removed; known self binaries still use the existing identity guard.

Installer recovery no longer deletes `.old` material before checking the installer.
It refuses missing/mismatched/unsigned installers before service disruption and keeps
a verified archive plus a recovery state record. It requires a trusted digest supplied
by the operator; it does not manufacture publisher trust, provision a signing identity,
or claim that a healthy service state proves endpoint functionality.

The detection deduplication claim previously used side effects inside
ConcurrentDictionary.AddOrUpdate factories. Those factories may run speculatively
and repeatedly, so multiple callers could believe they owned the same slot. Claims
now use TryAdd/TryUpdate compare-and-exchange loops. Concurrent pruning removes only
the exact expired key/value pair, never a freshly updated slot. Regression cases
cover 10,000 simultaneous claims for both new and expired slots.

### Continued follow-up: process generations and isolation actions

The exact-creation-time limitation for cached ancestry noted above is addressed for
chain termination: cache snapshots capture creation time, refresh invalidates replaced
PIDs, and chain-node termination compares that captured time on the held native handle.
Unknown identity and chronologically impossible parent links refuse chain traversal.
Snapshot writes now serialize refresh with event insertions. Windows regressions cover
concurrent insertion and simulated replacement generations; they are not yet executed.

Central certificate-adder, injector and ISO fallback termination also uses the native
verified path. Legacy inline monitor remediations and file-path check/use races remain
outside this guarantee. ISO source deletion still needs a handle-bound file transaction;
these process fixes do not make filesystem mutation reversible or race-free.

Isolation actions now reject a missing event time for ISO/VM process termination.
An ISO path must match the live mounted origin; dismount failure prevents deletion.
Shared VM management services cannot pass the dedicated-worker image restriction.
Docker references cannot become command options, reusable names resolve to immutable
full IDs before mutation, and full image hashes are required. Nonzero command exits
fail the operation rather than supplying success-like output. Commands have concurrent
bounded pipe reads and deadlines. Image removal no longer uses force against shared
images. Partial operations remain explicitly unconfirmed; no live Docker/VM/ISO
validation or reversible container/image deletion is claimed.

### Write-ahead firewall rules and bounded offline rule replay

Central isolation previously reported an isolation action even when the void COM helper
failed. It now creates two uniquely named rules through a journalled transaction and
requires read-back matches for Verified. Existing rules cannot be overwritten through
this API. Interrupted or failed application retains the journal and any partial rules.
Explicit rollback only considers canonical definitions under the configured protected
recovery root, refuses altered/duplicate names, and verifies absence after removal.
The CLI requires elevation and a recorded pre-action audit before rollback. Separate
per-invocation audit directories avoid sharing a live service audit writer. This does
not authenticate local journals against an administrator or make Windows COM's
compare/remove sequence atomic. Unrecorded/new firewall properties and simultaneous
privileged changes remain outside the guarantee. Older legacy rules have no rollback
state and are left alone.

Telemetry replay runs an explicit eight-rule profile from typed records, without response
or live collector dependencies. Rule timestamps and dedup windows use historical time;
context features reuse production code. Every output action is forced to LogOnly and
requested actions are explanatory metadata. Rule-category lookup no longer constructs
unrelated rules. Input limits and profile/fingerprint comparison checks prevent silently
accepting partial or mismatched replays. This is not live protection or detection-rate
validation, and raw replay output is not a privacy-redacted export.

### 3.1.8 CI fixture repair without weakening process identity

The reported release failures showed nonexistent-PID fixtures being refused before
the deeper budget/audit/containment code they intended to exercise. Process operations
and isolation routing now have injected trusted application boundaries for tests;
production service registrations use the native implementations. This adds no user
configuration or IPC bypass. Tests no longer depend on attempted host termination or
Docker/VM availability, check actual fixture call counts and audit ordering, and retain
a default-production-path regression for refusing an unknown generation.

Restore validates raw device/alternate-stream syntax before Framework path canonicalization,
so unsupported stream paths cannot escape the deliberate InvalidDataException policy
refusal merely because Windows raises NotSupportedException earlier.

### Unreleased certificate safety follow-up

Central certificate response now preflights live contexts across its four target stores, refuses stamped or unknown trust evidence, rechecks before removal, and verifies absence before reporting removal. Certificate property reads distinguish documented absence from native/API failure. Dedicated distrust refuses incomplete store scans and rechecks live stamps before removing a context. Nine pure policy cases cover present/absent/unknown combinations.

This is not a certificate recovery transaction. Native Windows store behavior, concurrent store changes, private-PKI compatibility, and partial removal/blocking recovery remain unvalidated; CurrentUser refers to the executing service account. No automatic trust restoration is added.
