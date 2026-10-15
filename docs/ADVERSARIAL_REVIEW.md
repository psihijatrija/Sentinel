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
