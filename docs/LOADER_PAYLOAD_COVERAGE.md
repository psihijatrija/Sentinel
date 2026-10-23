# DLL-loader and injected-payload coverage — 3.4.0 follow-up

The reported fake-game chain is an adjacent DLL loader followed by an injected
stealer/RAT. The pasted discussion attributes it to RenLoader/HijackLoader, but
contains no sample, hash, or independently verifiable analysis. This update
addresses concrete inspection gaps; it does not claim campaign-specific blocking.

## Changes

`ThreatIntelInjectionRule` queues both the caller and target of a recognized remote
API event before suppressing a noisy browser-labelled observation. Suppression
still prevents that API observation from authorizing a response. These additional
candidates are PE-inspection-only; they do not newly authorize the legacy
compact-page/thread heuristics. Actual inspection remains off the ETW callback,
behind the existing `CanInspect` game/anti-cheat, unresolved-path and companion gates.

`EtwThreatIntelMonitor` no longer restricts PE inspection to named high-value hosts.
The read-only `UnbackedPeScanner` accepts committed private executable allocations,
including RX code whose PE header is in a separate read-only region at the same
allocation base. It checks DOS/PE structure, a complete section table, and overlap
with an executable section inside SizeOfImage. MZ bytes, JIT pages, ordinary
MEM_IMAGE modules, mapped files, non-executable data and guard pages do not suffice.
This is structural evidence, not execution tracing or proof of malicious intent.

The walk is limited to 10,000 regions, 128 header inspections, eight reported
allocations and a cooperative 250 ms budget per process. The candidate loop
rotates through at most 16 candidates with a cooperative one-second budget before
its eight-second delay. OS calls already in progress cannot be interrupted by
those deadlines. Each header read is at most 4 KiB. Only recent remote-API
candidates are scanned; there is no new full-system polling walk. The separate
eight-second payload cooldown permits fresh evidence while a candidate remains
eligible, without inheriting another process lifetime's cooldown.

The observation is **Tier2 LogOnly**, with no DLL-unload or file-quarantine action
from the PE observation itself. It can complete the dedicated credential-theft
chain only with an actual Kernel-File credential-store read within 15 seconds,
matching PID and creation time, and confirmation that this is still the live
process lifetime. Unresolved identity, stale/future evidence, consultant signals,
watcher notifications and evidence from a different process cannot complete it.

The resulting composite carries the pinned victim creation time into the response
executor. This route audits and attempts verified termination of that victim and
its descendants, subject to existing protections and budgets. It refuses a reused
PID, missing action authority or a composite older than 15 seconds. It bypasses broad ancestor tracing and does not quarantine the victim's
backing EXE, mutate its ISO/container/VM, or register its backing hash as malware
in the reinfection cache. An injected legitimate host does not establish which
DLL or ancestor supplied the payload. Independently proven loader detections
retain their own existing response paths.

Existing mapped-module identity and DLL remediation remain available independently.
Qt/runtime DLL names, unfamiliar folders and large module counts acquire no new
kill authority. NanoAV source, online behavior and aggressive response rules are
unchanged. No new desktop-content collection or outbound reporting is added.

## Validation

- `LoaderPayloadCoverageTests` exercises the production walk using fake memory
  queries and header reads, then sends its actual observation into correlation
  and dispatch policy. It covers readonly-header/RX layouts, malformed/truncated
  headers and section tables, caps, cancellation, normal mappings, browser caller
  suppression, target attribution, stale evidence and PID reuse.
- `InjectedVictimResponseTests` exercises the production response adapter with
  fake process handles. The victim and eligible descendants are terminated while
  its parent remains untouched; missing authority or a replacement lifetime is
  refused. Existing process-tree tests cover protected/failed descendants and
  verified exit accounting.
- `LoaderPayloadWindowsTests` adds a native Windows-only fixture that allocates
  inert private pages in the test process, makes the header readonly and a code
  page RX, and invokes the production memory walk. It never executes those bytes
  or injects another process. A separate Windows case checks clean adjacent Qt
  and runtime DLL names against the actual module identity policy.

Linux cross-builds and portable tests do not execute the Windows fixtures or
prove installed ETW availability, cross-process read permissions, or real attack
containment. Native Framework tests and the existing isolated process-termination
fixture remain required on Windows before deployment.

## Remaining limits

This does not identify the malicious adjacent DLL from its filename or compare
every mapped image against a known-good vendor copy. MEM_IMAGE patching, erased
headers, unsupported PE layouts/architectures, headers larger than the read
budget, late payload activity after candidate expiry, protected/inaccessible
processes and queues that exceed the scan/correlation windows can be missed.
Normal application-directory DLL policy is unchanged. A legitimate private PE
loader combined with a credential-store read can resemble the chain; the evidence
does not infer operator intent or prove successful theft.

There is no new persistence remover, universal loader detector, account/session
revocation, or guarantee that first execution/theft is prevented. The target's
caller/parent is not automatically blamed. Persistence cleanup still requires
separate attributed evidence and its existing action-specific authorization.
