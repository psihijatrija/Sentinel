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
copy and key. Sentinel 3.2.3 does not upload checkpoints to the legacy Worker; retain trusted copies independently through an operator-controlled process.

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
