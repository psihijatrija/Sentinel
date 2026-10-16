# Sentinel diagnostics

Windows/.NET Framework 4.8 command-line tool (`net48-windows`). Build with the same
SDK already used by the solution; running the built executable requires Framework 4.8,
not the modern .NET runtime. It does not change Sentinel's product platform.

From PowerShell at the repository root:

```powershell
dotnet build tools/Sentinel.Diagnostics/Sentinel.Diagnostics.csproj -c Release
$diag = './tools/Sentinel.Diagnostics/bin/Release/net48-windows/Sentinel.Diagnostics.exe'
& $diag verify-pack PATH_TO_PACK
& $diag verify-ledger PATH_TO_LEDGER
& $diag verify-ledger PATH_TO_LEDGER TRUSTED_CHECKPOINT.json
& $diag replay EVENTS.jsonl
& $diag replay EVENTS.jsonl WEIGHT_CONFIG.json
& $diag compare-replays ORIGINAL_REPLAY.json UPDATED_REPLAY.json
& $diag inspect-restore PATH_TO_RESTORE_JOURNAL
& $diag preview-export EVENTS.jsonl
& $diag export EVENTS.jsonl investigation.zip
```

Commands return 0 on success, 1 on validation/error, 130 on cancellation. They do not
execute response actions, deploy a Worker or upload evidence. Export refuses an existing
destination. Review `preview-export` and the resulting bundle before sharing.

Replay accepts one detection object per line or Sentinel `type=detection` JSONL envelopes.
Timestamps are required, UTC, and processed in chronological order. Enum values may be
numeric or named. Weighted score overrides are optional; configuration is included in
the result. It uses production weighted-correlation code with an injected clock. Graph
boost, plugins and the full response pipeline are outside replay scope. Reports record
the engine assembly version and normalized input fingerprint. Retain a baseline report
and use `compare-replays` after updating rules/configuration; mismatched input is rejected. Output actions
are always LogOnly; hypothetical findings are not response authorizations. Prior weighted
composites are excluded. A maximum of 100,000 detections and 64 MiB of input is accepted per run.

`verify-pack` checks files listed in `MANIFEST.sha256`, not origin, custody, or unlisted
files. It rejects empty manifests, duplicate names, traversal, linked files and altered
content. Use an immutable offline copy for adversarial verification; mutable directories
can race any path-based reader. The tool does not extract untrusted ZIPs.

`verify-ledger` outputs a checkpoint of the form `{"Sequence":2,"Hash":"..."}`.
Retain checkpoints separately/off-host. Without a trusted checkpoint, rewriting the whole
chain or deleting a valid suffix is not detectable. Checkpoints cover the named daily
ledger only; retention is 90 days and each daily chain is capped at 20 MB. Overflow or
write/verification failure degrades integrity reporting while the original audit path
remains available. This is not protection against an administrator who controls every
copy and key. The Worker can retain incident-summary checkpoints when configured.

Restore journals live in the vault's `RestoreJournal` subdirectory and contain destination paths. Production
vault ACLs protect them; protect custom test/export directories yourself. Inspection
does not trust journal data to authorize filesystem changes. Prepared/Applied records
and staged files require operator review after interruption; the original vault is
retained even after a verified restore. Restore never overwrites an existing target.

Redacted exports preserve timestamps and stable per-export process aliases, category,
confidence, tier, signal and requested action. They omit rule names and arbitrary raw
fields. Timing can still be sensitive. A normalized source-evidence fingerprint links the derived copy to the original detection
objects without copying raw fields. Their checksum manifest describes a derived copy
and does not preserve the original evidence seal or authenticate its origin.

Run the Windows regression suite and Worker tests:

```powershell
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
Push-Location worker
npm test
Pop-Location
```

The solution, shipping tests and GitHub Actions release remain Windows projects. A
throwaway host outside the checkout can exercise platform-neutral algorithms in a
non-Windows cloud workspace, but it is not shipped or added as a supported product target
and does not replace running the Framework tests on Windows.

## Recorded telemetry rule replay

`replay-telemetry` starts from telemetry rather than precomputed detections. Its
`RecordedInputRules-v1` profile runs eight production rules (credential commands,
ransomware, encoded PowerShell/reverse-shell patterns, privilege escalation,
ClickFix, npm supply-chain activity, and the two browser-flag rules). The report
lists their exact names and the compiled module ID. It shares live fusion's context
features and deduplication primitive, then runs historical behavioral/weighted
correlation. Every output action is LogOnly; requested and tier-law actions are
recorded separately as hypothetical metadata.

Input is JSONL with one typed envelope per line. For example:

```json
{"Kind":"Process","Data":{"Timestamp":"2020-01-01T00:00:00Z","ProcessId":12000,"ProcessName":"fixture.exe","ImagePath":"fixture.exe","ParentProcessName":"fixture-parent.exe","CommandLine":"fixture.exe --help"}}
```

Kinds are `Process`, `Network`, `File` and `ThreatIntel`; Data uses the corresponding
production telemetry DTO. `TelemetryReplayRecord.FromEvent` serializes supported
captured DTOs without losing their concrete type. This command consumes an explicit
capture; it does not add continuous disk recording or invent missing telemetry.
UTC timestamps are mandatory. Inputs are bounded to 64 MiB/100000 events by the CLI,
with 500 events per PID and at most 8000 active PID histories during replay. Ties
preserve input order. Historical time drives feature windows and deduplication.

```powershell
& $diag replay-telemetry CAPTURE.jsonl > BEFORE.json
& $diag replay-telemetry CAPTURE.jsonl UPDATED_WEIGHTS.json > AFTER.json
& $diag compare-telemetry BEFORE.json AFTER.json
```

Comparisons require the same normalized telemetry fingerprint and profile. A module
ID identifies a build; it is not a publisher signature. This is a selected-rule
replay, not the full live pipeline: reputation, host identity, scoring/allowlists,
live graph/plugins, dynamic/sliding-window rules, self-PID filtering, monitor input
loss and host effects are excluded. Reports can contain original command lines and
paths; they are investigation records, not the private/redacted export format.

## Firewall isolation recovery

New central isolation actions write per-transaction journals under
`%ProgramData%\Sentinel\Recovery\FirewallIsolation`. They create fresh inbound and
outbound block-rule names, require prior absence, and read back the recorded rule
state before reporting Verified. Existing firewall rules are not overwritten.
Partial applications remain Failed with their rules retained for operator review;
startup does not replay or automatically undo them.

```powershell
Get-ChildItem "$env:ProgramData\Sentinel\Recovery\FirewallIsolation\*.firewall.json"
& $diag inspect-firewall JOURNAL_PATH
# Explicitly remove only the unchanged rules belonging to this transaction:
& $diag rollback-firewall JOURNAL_PATH
```

Rollback requires an elevated administrator terminal. It validates the journal,
checks all transaction rule names for duplicates/changes before removing any, checks
again before each removal, and verifies absence afterward. Repeating rollback is
safe when the rules are already absent. Changed rules require manual review. A
separate operator audit directory records the explicit rollback request/outcome.
The configured recovery root and its inherited service ACLs must remain protected.

Recovery covers these new firewall rules only. It cannot restore killed processes
or cache contents, and it cannot undo older legacy rules without recorded state.
Windows Firewall COM does not provide an atomic compare-and-remove operation against
concurrent administrator changes; the checks reduce that risk, not eliminate it.
The journal records known firewall fields; it is not an independent signature or a
complete backup of Windows Firewall policy. Native COM behavior still requires Windows
validation before release.

Repeated isolation of an already verified target reuses its unchanged rules and journal,
including after service restart. The active journal index refuses corrupt history and
limits retained firewall transaction records to 4096. At the limit, new targets require
operator review and archival of completed history, followed by service restart; existing
verified isolation can still be reused. Active/partial transactions must not be discarded
merely to free space. History is never silently deleted by the service.
