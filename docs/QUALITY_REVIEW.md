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
