# Sentinel engineering assessment and improvement record

Assessment date: 2026-10-15. These are provisional engineering judgments of this
checkout, not malware-detection percentages, certification, or competitor rankings.
The owner's deployment target is custom/debloated Windows. The coding workspace
is Linux; Windows product targets remain `net48-windows`.

Scores consider implementation completeness, response boundaries, meaningful tests,
operational visibility, and demonstrated deployment behavior. A 10 requires all five,
including repeatable Windows tests and realistic benign/adversarial workloads. Source
inspection and successful cross-compilation cannot establish those outcomes.

| Segment | Before /10 | After /10 | Main remaining evidence or implementation needed |
| --- | ---: | ---: | --- |
| Architecture and modularity | 7 | 7 | Reduce static/shared policy state; validate lifecycle/concurrency under load |
| Telemetry and sensor health | 5 | 6 | Instrument remaining sensors, provider loss, queue age and ETW buffer loss |
| Behavioral correlation | 6 | 7 | Full-pipeline replay, process-generation identity, broader adversarial corpus |
| Response authorization and safety | 5 | 6 | Verify every inline action, PID reuse, partial failures and Windows response outcomes |
| Memory, module and injection monitoring | 6 | 6 | Windows/PPL/anti-cheat compatibility and realistic injection evaluation |
| Certificate trust integrity | 5 | 6 | Enterprise/private PKI compatibility and independently verified remediation safety |
| Network integrity | 5 | 6 | Real VPN/Wi-Fi/DHCP transitions and corporate-network compatibility |
| Host-state reconciliation | 5 | 6 | Broader inventories, collection completeness and post-gap Windows validation |
| Incident lifecycle and restart continuity | 4 | 4 | Persist complete incident identity and pending response state; current IncidentManager remains in memory |
| Evidence integrity and independent verification | 4 | 6 | Deploy/test remote storage, periodic checkpoints and independently protected signatures |
| Privacy and investigation exports | 4 | 6 | Privacy review of all existing reports, timestamp disclosure and end-to-end export UX |
| Threat-intelligence proxy | 5 | 6 | Live authenticated Cloudflare/KV validation and upstream integration tests |
| Offline ML | 4 | 4 | Published model provenance, held-out data, calibration and drift measurements |
| IPC and service/agent boundaries | 6 | 6 | Windows ACL/identity adversarial tests on the intended custom OS |
| Diagnostics and user explanations | 5 | 6 | Windows dashboard validation, complete response reasoning and accessibility |
| Regression testing and evaluation | 5 | 6 | Execute full Windows suite and realistic attack/benign workload benchmarks |
| Performance and resource budgets | 4 | 4 | Event-rate, CPU, memory, disk, latency and drop-rate measurements |
| Packaging and update integrity | 5 | 5 | Signed update/rollback authorization, interrupted-update tests and installer validation |

No segment is rated 10. Assigning that score before obtaining the missing evidence
would conceal work the product still needs.

## Implemented improvements

- Separate actual sensor collection progress from supervisor task liveness. Existing
  uninstrumented sensors report Unknown. ETW, module reconciliation and the new integrity
  inventory publish progress. Native ETW queries report provider enable status and lost
  events/buffers. A quiet but queryable session with a live consumer is not restarted
  merely because it produced no events.
- Count real channel evictions in both telemetry lanes and expose queue depth, oldest
  queued age and sampled queue-wait P95. Visibility-gap notifications cause subsequent
  inventory passes to re-sample state and label missing attribution explicitly.
- Detect background monitor faults and restart without disposing the instance first.
  Clean completion is treated as unavailable coverage, allowing optional sensors on
  debloated Windows to stop without an endless restart loop.
- Make weighted correlation explanations reflect score, category and terminal-evidence
  gates. High score alone cannot substitute for terminal evidence. Plugin results without
  independently corroborating evidence remain Tier2/LogOnly. Weighted composites need
  at least two categories even if configuration requests fewer.
- Add deterministic historical-time replay of weighted correlation using production
  logic. Replay has no response engine, plugins or live graph; all output actions are
  LogOnly. Prior weighted outputs are excluded to prevent feedback.
- Add a hash-chained companion audit journal, independent verification, trusted-prefix
  checkpoints, explicit integrity-degradation reporting and optional checkpoint fields
  in evidence summaries. Keep original audit records compatible.
- Implement the previously missing Worker `/report/evidence` endpoint. It requires
  existing HMAC/nonce authentication, stores only minimal content-addressed anchors,
  and returns 503 when durable storage is absent or fails. Tests exercise storage using
  an injected KV implementation; no production deployment is implied.
- Journal explicit quarantine restores as Prepared/Applied/Verified, write to a staging
  file, refuse existing destinations, verify restored bytes and retain the encrypted
  original. Recovery inspection is read-only and never replays malware restoration.
- Add observational network-context and root-certificate histories. Compare snapshots
  across restarts; hash network identifiers/configuration; record additions/removals
  with uncertainty about actor and exact change time. A context change never grants
  trust or changes existing hardening policy.
- Expose sensor progress, audit degradation, correlation decisions and response reasons
  in the existing dashboard data paths and UI.
- Add a standalone diagnostic CLI, redacted export preview and a derived offline ZIP
  with a checksum manifest. Raw names, PIDs, evidence, arguments and metadata are omitted.
- Add regression cases to the existing Windows Framework test project and Worker tests
  to Windows CI/release checks. Diagnostics also targets `net48-windows`. No Linux CI
  job or product runtime is introduced.

## Scope of the requested suggestions

| Suggestion | Delivered scope | Still required |
| --- | --- | --- |
| Useful sensor health | ETW queries/provider status/loss, exact queue drops/age/wait, three instrumented sources, fault recovery, dashboard counts | Instrument remaining individual monitors; validate native counters on Windows |
| Incident replay | Historical weighted-correlation replay and existing benign/malicious policy corpus | Telemetry-to-rule/full-policy replay and measured evaluation lab |
| Independently verifiable evidence | Audit hash chain, manifest checker, checkpoint comparison, Worker anchor receiver | Live off-host validation, periodic anchoring, protected signing key |
| Recoverable response | Quarantine restore transaction and read-only recovery inspection | Firewall, registry and certificate transactions; kill cannot be reversed |
| Why suspicious activity was observed | Correlation gate metadata and displayed response reasons | Complete per-action authorization explanation and drill-down |
| Post-outage reconciliation | ETW visibility-gap coordination, inventory re-sampling and explicitly unknown attribution | Cannot reconstruct events never collected; validate Windows recovery timing |
| Network context awareness | Context-tagged observational history without trust changes | Approved profiles and real network-transition compatibility tests |
| Private investigation export | Preview, allowlisted redaction, offline ZIP | Review/share UI and privacy audit of older export paths |
| Certificate provenance | Persistent observations and change history, actor explicitly unknown | Correlation with trusted installation records and chain-validation history |

## Platform and release limits

Windows service behavior, ETW/provider availability, DPAPI, root-store remediation,
WinForms/WebView2 fallback, firewall changes, and installer behavior must be checked on
Windows. The existing CI workflow retains that job. Its execution is not proven by
editing the workflow. Also test on the owner's debloated image, where optional services
may be unavailable even when stock Windows CI succeeds.

Cloudflare account connection in a client does not by itself inject authentication
into the cloud shell. The checked shell had no Cloudflare binding names and Wrangler
reported unauthenticated. No account secret values were inspected. Connect the required
runtime access or use the Cloudflare tooling available in the user's environment;
configure `EVIDENCE_STORE` before remote evidence-storage validation.

The user requested commit/push and a GitHub Actions installer after implementation is
complete. The release workflow now runs the Windows Framework suite and Worker tests
before building/publishing. The sanctioned release script supports `-PrepareOnly` to
compute the single allowed version increment and stamp metadata while deferring the
Windows installer to Actions. A passing local cross-build is not release publication.
Release assets include the installer, a directly copyable Worker JavaScript file,
a Windows Framework diagnostics ZIP and SHA-256 checksums. An actual successful Actions run must be observed before claiming
an installer release exists.


## Validation recorded before commit

- Release cross-build: seven projects, zero warnings/errors; Windows product/diagnostic
  targets retained. Repeated after the final release version stamp.
- External temporary algorithm host: 82 executed, 82 passed, zero skipped. It reuses
  production code and existing policy/correlation corpora and is not committed or shipped.
- Worker: eight executed, eight passed. Actual local Worker runtime + KV write/read-back,
  private-field stripping and nonce-replay rejection also passed.
- Release/build PowerShell files parsed; canonical release DryRun selected 3.1.7 from 3.1.6.
- Full Windows Framework suite, native ETW/DPAPI behavior, installer creation and publication
  are delegated to the Windows GitHub Actions release gate. Do not infer success from
  local checks; consult the actual workflow/release result.

## Follow-up implementation and audit

The numeric table above records the initial 3.1.7 assessment; it is not a measured
before/after protection benchmark. Do not compare it with independent reviewers'
numbers as if all reviews used the same rubric. The work below addresses additional
implementation gaps. Ratings are not raised simply because more code was added.

- **Restart continuity:** durable bounded incident timelines, total/omitted event
  counts, pending response evaluations and stable IDs. Recovered history never
  restores stale PID mappings, suppression or action authority. Corrupt state is
  preserved and failures reach system health.
- **Response safety and explanations:** actual engine dispositions reach the
  coordinator; LogOnly no longer masquerades as an executed response. Attempts do
  not become confirmed outcomes. Fixed lock stripes remove a concurrency race.
  Temporal process-generation checks refuse stale evidence, with the remaining
  handle/use race explicitly recorded in the adversarial review.
- **Replay:** optional behavioral correlation plus weighted correlation, historical
  clocks, tier-law evaluation, output comparison and a repeatable runtime benchmark.
  Collector/rule input, live identity, graph/plugins and host effects remain outside
  this offline replay's scope.
- **Evidence continuity:** optional five-minute remote checkpoint publication now
  runs independently of incident-pack creation. Private deployment authentication,
  receipt validation and visible configuration/failure states replace implied
  protection from the public compatibility credential.
- **Privacy:** evidence payloads are minimized on the client before transmission.
  Private exports remove absolute dates while retaining intervals.
- **Sensor progress:** root-store evaluation and WFP collection expose incomplete
  reads, unavailable commands, timeouts and malformed inventories. Uninstrumented
  monitors remain Unknown. Corrupt host observation baselines are retained.
- **Recovery safety:** restore inspection validates schema, state, content hash and
  canonical local paths; it refuses network/device/link/alternate-stream targets.
  Neither recovery history nor a journal authorizes automatic action replay.

The adversarial findings, fixes and remaining risks are in
[ADVERSARIAL_REVIEW.md](ADVERSARIAL_REVIEW.md). Windows deployment, enterprise PKI,
false-positive and sustained performance evidence are still separate requirements.
At the owner's request, intermediate test runs stopped; final verification follows
completion of the code changes, not each edit.

### Current provisional assessment

Same conservative engineering rubric as the original table. These are source-based
judgments, not measured protection percentages. Final release validation is recorded
by the linked GitHub Actions run; that cannot substitute for deployment/attack data.

| Segment | 3.1.7 | Current code | Evidence behind the change or limit |
| --- | ---: | ---: | --- |
| Architecture and modularity | 7 | 7 | New state-store boundary; shared/static policy remains |
| Telemetry and sensor health | 6 | 7 | More explicit collectors; corrected enrichment-drop accounting; remaining coverage Unknown |
| Behavioral correlation | 7 | 8 | Historical behavioral replay, isolated clock/identity dependencies and output comparison |
| Response authorization and safety | 6 | 7 | Actual dispositions, bounded serialization, temporal PID check; handle-bound execution still needed |
| Memory, module and injection monitoring | 6 | 6 | No new Windows injection/anti-cheat evaluation |
| Certificate trust integrity | 6 | 6 | Collection degradation exposed; private-PKI remediation compatibility unresolved |
| Network integrity | 6 | 6 | No VPN/DHCP/Wi-Fi workload evidence added |
| Host-state reconciliation | 6 | 7 | Unreadable baselines retained rather than silently replaced |
| Incident lifecycle and restart continuity | 4 | 7 | Durable history, stable IDs, pending evaluations, no stale authority recovery |
| Evidence integrity and independent verification | 6 | 7 | Independent periodic anchoring with private write credentials and confirmed receipts |
| Privacy and investigation exports | 6 | 7 | Source-side minimization and removal of absolute dates in private exports |
| Threat-intelligence proxy | 6 | 7 | Public compatibility credential no longer authorizes report mutations |
| Offline ML | 4 | 5 | Pinned artifacts and initialization fixes; future metrics bind to saved model; original provenance/calibration absent |
| IPC and service/agent boundaries | 6 | 7 | Bounded request and connection lifetime; final Windows boundary validation required |
| Diagnostics and user explanations | 6 | 7 | Attempts distinguished from confirmed outcomes and explicit anchoring states |
| Regression testing and evaluation | 6 | 6 | Additional cases prepared; no new independent attack/benign benchmark |
| Performance and resource budgets | 4 | 5 | Bounded locks/state writes, corrected drops and repeatable offline benchmark; live sustained budgets unmeasured |
| Packaging and update integrity | 5 | 5 | Installer pipeline retained; signing and interrupted-update/rollback assurance absent |

Unchanged scores identify work this pass did not establish. A claim that all segments
are 10/10 would still be unsupported, including for code paths with real fixes.

## Resumed implementation — 2026-10-16 (unreleased)

This resumes the interrupted follow-up; it does not close the full improvement request
or change the ratings above. No release or Windows execution is claimed.

- Process reputation uses two workers and a 256-item pending queue instead of one
  fire-and-forget task per process event. Oldest pending items are evicted under overload;
  `ReputationDropped` records these separately from telemetry losses and is displayed in
  Ops. Rule evaluation continues independently. Shutdown cancels and waits for workers.
- Reputation detections retain the process telemetry timestamp. Queue/network delays
  no longer turn old observations into apparently fresh evidence for a reused PID.
- Reputation self-exclusion now uses `SelfPathGuard` only; arbitrary `Sentinel.*` files
  in the install directory no longer gain the broader prefix exemption.
- Chain-tracer termination and the central plain-kill fallback open one least-privilege
  Windows process handle for creation-time, critical-process and image checks,
  termination and exit verification. Chain nodes also require the traced image to match.
  A failed/unverified termination no longer enters `KilledProcesses`. This verifies only
  the selected process, not a complete process tree. Cached ancestor identity still lacks
  captured creation-time evidence; inline remediations, quarantine, certificate-adder and
  isolation helpers require further conversion and Windows evaluation.
- Plain-kill fallback outcomes become Confirmed only after same-handle exit verification.
  Chain/mixed effects retain Attempted semantics; completion of tracing alone is not a
  verified successful response. Protected process names/paths compare without case sensitivity.
- Recovery takes explicit installer/version/hash inputs, validates digest and Authenticode
  before disruption, copies and hashes an archive including `.old` files, journals phases,
  handles installer failure/cancellation and checks installed version and service state.
  It never deletes the only recovery copy or silently restores/executes old code.
  It requires a signed installer and an independently trusted digest. Existing unsigned
  release artifacts cannot use this path; signing infrastructure is still outstanding.
  Service state/version checks are not a functional endpoint health test. Interrupted
  upgrade/rollback compatibility remains a required Windows exercise.

The full improvement backlog remains the “Still required” column above, particularly
full telemetry/rule replay, remaining sensor instrumentation, durable reversible host
mutations, deployment-bound evidence validation, original ML evaluation provenance and
real benign/adversarial/performance measurements. None can be replaced by assigning 10/10.

Validation for the resumed changes:

- .NET SDK 10.0.402 cross-build of all seven projects, Release, warnings as errors:
  zero warnings and zero errors. Shipping targets remain unchanged.
- Six queue/deduplication regression cases executed in an external Linux .NET 10
  host linked to production code and committed tests: six passed, zero skipped.
  Includes 1,000 concurrent submissions with two occupied workers, exact eviction
  counts, continued processing after a failed item, and cancellation on shutdown.
- PowerShell 7.6 parser accepted the recovery script; this is syntax validation only.
- Full Windows Framework tests, native termination, installer execution, service restart
  and signing/release validation are unrun in this Linux environment.
- Changes remain unreleased. No new version, push, installer or revised rating is claimed.

A further concurrency finding in the resumed pass: detection deduplication factories
could grant multiple callers apparent ownership. Slot claims now use atomic
compare-and-exchange operations, pruning conditionally removes the observed value,
and the pruning counter uses Interlocked. This matters more with concurrent reputation
workers; the fix applies to all detection submissions.

### Continued response and sensor work (2026-10-16, unreleased)

- Ancestry refresh and event insertions now serialize snapshot updates, avoiding lost
  sibling entries. Cache observations retain process creation times, invalidate old
  ancestry when a PID generation changes, and withdraw identity when it cannot be read.
  Chain tracing refuses missing generations and parents born after their children;
  native termination checks the exact creation time captured with that chain node.
- Certificate-adder, injector and ISO fallback kills in AdvancedResponseEngine now use
  the verified termination path too. Injector failures do not enter reinfection tracking.
  File quarantine and certificate removal remain separate mutations with their own limits;
  this does not establish identity-bound file operations across the whole product.
- ISO containment requires event time, a local path matched to the live mounted-image
  origin and confirmed process exit before dismount. Failed dismount prevents source
  deletion. Cancellation is checked before subsequent mutation. Source-file replacement
  races still need a file-handle-bound transaction; no complete rollback guarantee is made.
- VM containment no longer uses an unverified display name with Stop-VM. Same-handle
  process policy restricts termination to dedicated worker images; shared management
  services such as vmms are refused. VM files remain preserved. The image restriction
  narrows existing behavioral authority; it never authorizes a response on its own.
- Docker responses resolve names to full container IDs, validate full image hashes,
  stop on command failure, and avoid force-removing shared images. Command execution
  drains both pipes concurrently, bounds each output to 1 MiB and enforces a 15-second
  deadline. Partial results explicitly remain unconfirmed. Native/container integration
  is still unrun here; exit-status success is not an independent host-integrity proof.
- DNS polling implements the existing sensor-progress interface. A completed empty
  collection is Healthy; unavailable or failed event-log reads are Failed. The supervisor
  samples the source so stalled collection becomes Stale. This does not prove that the
  optional DNS log records every query or that its localized payload parsing is complete.

Portable validation now exercises 27 queue, deduplication, termination-policy and
isolation-identifier cases against production sources. They passed with zero skipped.
Two new ancestry regressions are included in the Windows test project (concurrent starts
and replacement generations), and the existing preservation test now uses the real
current-process image instead of inventing a conflicting image identity. Those Windows
cases and native DNS/process/isolation behavior remain unexecuted on this Linux host.

Final continued-pass cross-build: all seven projects compiled in Release with warnings
as errors, zero warnings and zero errors. One parallel MSBuild attempt lost worker
processes; the serial build with node reuse/shared compilation disabled completed.
This is cross-compilation evidence, not execution of the Windows Framework suite.

### Recorded-input replay and reversible firewall isolation (unreleased)

The diagnostics tool now supports typed telemetry-to-rule replay with eight production
rules, shared live context features, atomic historical-time deduplication, tier-law
annotations and behavioral/weighted correlation. Comparisons bind to the same normalized
telemetry fingerprint and identify the compiled module. Outputs remain LogOnly. This
extends the former detection-only replay without claiming complete pipeline coverage:
no live identity, reputation, scoring/allowlists, plugins/graph, dynamic/sliding-window
rules, self-PID filter or response execution is included. An explicit capture is required;
continuous telemetry recording is not silently enabled.

Rule-category lookup no longer instantiates arbitrary rules while scanning metadata.
A reviewed type list and explicit attribute alias preserve existing category names;
a Windows registration test checks all declared categories/aliases. This also removes
constructor side effects from offline classification.

New central firewall isolation is a write-ahead transaction with unique rule names,
prior-absence checks, intended state, authorization reference, partial-failure records,
and read-back verification. The response engine reports Confirmed only for verified
firewall rules; the DNS/ARP cache side effects remain outside the recovery scope.
Diagnostics provides read-only inspection and explicit elevated rollback. Rollback
validates paths/schema/intended definitions, refuses changed/duplicate rules, preserves
foreign rules, verifies removal and can resume explicitly after interruption. No startup
replay or automatic removal was introduced. Native Windows COM behavior and concurrent
administrator races remain validation/implementation limits; rule-field snapshots are
not a complete firewall policy backup. Existing protected ProgramData ACLs are required.

Repeated verified targets reuse their existing rules/journal after current read-back,
including across service restart. Retained transaction history is capped at 4096 rather
than growing without bound; completed history needs explicit archival/service restart
at the limit. Cache invalidation now sits behind an injected Windows boundary and only
runs after verified isolation, so rejected targets do not flush host caches and fake-store
response tests have no native cache side effects.

Validation for this continuation:

- Final Release cross-build: all seven projects, zero warnings/errors, shipping targets
  unchanged. Includes diagnostics commands, native adapters, service DI and new tests.
- External source-linked .NET 10 host: 44 passed, zero skipped (17 firewall transaction
  cases plus the 27 earlier queue/deduplication/process/identifier cases). Recovery cases
  exercise partial application, interrupted rollback, conflicts, edited journals,
  protected recovery-root validation, target reuse across restart and foreign-rule preservation.
- External .NET 10 host loading the compiled Core assembly: 11 passed, zero skipped
  (nine recorded-telemetry replay cases and two fake-firewall response integration cases).
  The response cases have no native firewall or DNS/ARP side effects.
- Full Windows Framework suite, registration/ancestry Windows cases, actual Firewall COM
  field normalization, elevated diagnostics rollback, production ACLs and native cache
  invalidation remain unexecuted. No publication, release or numerical rating increase
  is claimed. The implementation remains an unreleased local change set.

### Reported 3.1.8 release-test failures

The owner supplied the summary for Release run 38774407671 (commit b27f801):
2782 executed, 2775 passed, seven failed, none unexecuted. The public job page
identifies the failing Windows build/test gate; Node action deprecation messages
are warnings, not these test failures.

Six failures used nonexistent process IDs to reach kill-budget, kill-outcome,
pre-action-audit or Docker/VM-delegation assertions. The production generation guard
correctly refused those actions earlier. Tests now inject explicit process and
isolation fixtures rather than relying on unsuccessful native kills. Production DI
binds native process operations and real isolation containment; there is no runtime
configuration/IPC switch to bypass identity checks. Budget tests additionally verify
exactly three/two fixture terminations, and the audit fixture checks PRE_ACTION from
inside the termination callback. A new test verifies default production handling of
an unknown PID remains LogOnly, without a destructive pre-action audit.

The seventh failure was real Windows Framework path-validation ordering: GetFullPath
could throw NotSupportedException for an alternate data stream before the restore
policy rejected it. Raw local/device/stream validation now precedes normalization,
retaining the InvalidDataException refusal contract and preventing writes.

Validation: final seven-project Release cross-build passed with zero warnings/errors.
Twenty-six selected cases passed in the external .NET 10 host loading compiled Core,
including all seven reported cases, neighboring ISO/Tier2/audit/restore safety checks
and affected replay/firewall response cases. None were skipped. This does not establish
a successful Windows Framework rerun: the original Actions run remains failed until
updated code is published and the Windows gate executes again. Changes remain local
and unreleased, alongside the ongoing improvement work.

### Unreleased certificate safety follow-up

Central certificate response now preflights live contexts across its four target stores, refuses stamped or unknown trust evidence, rechecks before removal, and verifies absence before reporting removal. Certificate property reads distinguish documented absence from native/API failure. Dedicated distrust refuses incomplete store scans and rechecks live stamps before removing a context. Nine pure policy cases cover present/absent/unknown combinations.

This is not a certificate recovery transaction. Native Windows store behavior, concurrent store changes, private-PKI compatibility, and partial removal/blocking recovery remain unvalidated; CurrentUser refers to the executing service account. No automatic trust restoration is added.
