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

- The main response pipeline carries structured effect receipts through coordination and
  incident state. Completion/deduplication requires verified requested effects; dashboard
  success indicators require that receipt. Native state read-back was added where supported;
  legacy asynchronous/isolated-environment executors remain explicitly unverified. Portable
  logic/renderer tests do not replace Windows validation of the native actions or Framework suite.

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


## CI runtime correction

Build & Test uses a concurrency group per branch or pull request with cancellation of superseded runs. Its single coverage-enabled Framework test invocation emits both the TRX result and Cobertura report; it does not run the suite a second time for coverage. Release validation remains independent.

The legacy-sidecar one-shot marker regression supplies a temporary scan root through an internal overload of the production cleanup path. The public production overload retains its fixed-drive scope. The regression verifies actual deletion counts and preserved files without scanning or deleting sidecars elsewhere on the runner. No tests are skipped or filtered out of the normal suite. Windows CI must confirm the resulting wall-clock improvement; Linux cross-builds do not measure it.


## Release trigger

Release is triggered by successful Build & Test workflow completion for push events on main/master, or by manual dispatch. Pull-request completions and unsuccessful builds cannot publish. The publishing job checks that the source repository matches this repository and pins both checkout and release target to the successful run's head SHA. An existing release is a no-op; version.txt remains authoritative. Independent Windows release checks still run before packaging.
