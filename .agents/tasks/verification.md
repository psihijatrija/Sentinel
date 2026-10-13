# Verification — Fix False-Positive Process Kills (fix/false-positive-kills)

Branch: `fix/false-positive-kills` · Version: `2.9.7` → `2.9.8` (patch +1)

## What was changed

1. **PPID spoofing FP (git/git-remote-https/git-remote-http/gh/credential helpers).**
   `src/Sentinel.Core/AllowlistService.cs` — added `git-remote-http`, `gh`,
   `git-credential-manager`, `git-credential-manager-core` to the existing
   `DevelopmentProcesses` set (which already held `git`, `git-remote-https`).
   `ParentPidSpoofDetector` already consults `IsDevelopmentProcess(name)` AND requires a
   valid Authenticode/signer signature at the call site before skipping the KillProcess
   response, so names alone never self-authorize (fail-closed, no attacker-controllable
   trust). No ParentPidSpoofDetector / ChainTracer / ResponsePolicy edit was required —
   the mechanism was already parent/child-chain-aware via that signature-gated call site.

2. **PowerShell "Sentinel" self-reference FP.**
   `src/Sentinel.Core/ScriptExecutionMonitor.cs` — the `MaliciousPatterns` array listed the
   bare substring `"Sentinel"` (twice) plus a never-matching `"Stop-Service.*Sentinel"`
   (patterns are matched with `string.Contains`, so `.*` never matches). Any benign script
   referencing the product name matched and got `KillProcessTree`. Replaced those three
   entries with literal service-tamper substrings: `Stop-Service Sentinel`,
   `Stop-Service -Name Sentinel`, `sc stop Sentinel`, `sc.exe stop Sentinel`,
   `Set-Service Sentinel`, `Set-Service -Name Sentinel`. Genuine attack-tool signatures
   (Mimikatz, AMSI, download cradles, injection APIs, persistence, webhook exfil) are
   untouched. The `isCritical` "Sentinel" clause stays — every remaining "Sentinel" pattern
   is a service-stop command, so real shutdown attempts still escalate to Tier1.
   Added pure, I/O-free `internal static` helpers `MatchMaliciousPatterns` and
   `IsCriticalScriptMatch` (used by both the script-block and script-drop paths) so the
   signature set is unit-testable without the Windows event log. Production logic unchanged.

3. **Torrent/P2P clients vs C2/beaconing kills.**
   `src/Sentinel.Core/BeaconingDetector.cs` — `AnalyzeAllAsync` now consults the canonical
   `BulkTransferNoise.IsBulkTransferProcessName` allowlist (via new `internal static`
   predicate `ShouldDemoteBeaconToObserve`) before authorizing a response. A recognized
   bulk-transfer client's statistical-beacon detection is emitted with
   `Tier = Tier2Indicator`, `AuthorizedResponse = LogOnly`, and `Metadata["BulkTransfer"]="true"`,
   so the hard "Tier2 never acts" rule guarantees no kill AND no NetworkIsolate. The detection
   is still logged. The non-torrent flow (DetermineResponseAction, Tier1) is unchanged.
   `BulkTransferNoise` already covered all required names (qbittorrent, utorrent, bittorrent,
   transmission[-qt/-daemon], deluge[d/-gtk], tixati, vuze, azureus, frostwire, aria2c, …),
   so no list edit was needed there.

## Build

Command (run from worktree root): `dotnet build Sentinel.sln -c Release -warnaserror`

Result: **Build succeeded. 0 Warning(s), 0 Error(s).** (The non-zero process exit code was
the .NET SDK first-run welcome banner printed to stderr, not a build error; the MSBuild
summary reports 0W/0E and all six projects produced their outputs.)

## Tests

Command: `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug`

Full suite result: **Passed: 2619, Failed: 2, Skipped: 0, Total: 2621.**

The 2 failures are **pre-existing and unrelated** to this change:
- `Monitors.TlsCertificateMonitorTests.AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored`
- `Monitors.TlsCertificateMonitorTests.AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence`

Both are TLS-certificate scoring tests (self-signed root scored 0.65 vs expected < 0.60/remove
threshold). They were confirmed to fail on the clean baseline: stashing all six source/test
changes and re-running `--filter FullyQualifiedName~TlsCertificateMonitorTests` reproduced
`Failed: 2, Passed: 13` with identical messages. This task touches no TLS code
(AllowlistService, ScriptExecutionMonitor, BeaconingDetector only).

New / extended tests (all pass — `--filter` of the three classes: **Passed: 40, Failed: 0**):
- `AllowlistServiceTests.IsDevelopmentProcess_Recognizes_GitToolchain` — asserts `git`,
  `git-remote-https`, `git-remote-http`, `gh`, `git-credential-manager`,
  `git-credential-manager-core` (and case-insensitive `GH`) are recognized, and an attacker
  name `git-stealer` is NOT.
- `ScriptExecutionMonitorTests` (new class):
  - `BenignScript_ReferencingSentinelProgramData_DoesNotMatch`
  - `BenignScript_WithBareWordSentinel_DoesNotMatch`
  - `SentinelServiceStop_StillMatchesAndIsCritical`
  - `ScStopSentinel_StillMatchesAndIsCritical`
  - `Mimikatz_StillMatchesAndIsCritical`
  - `AmsiBypass_StillMatchesAndIsCritical`
  - `DownloadCradle_StillMatches`
- `BeaconingDetectorTests`:
  - `TorrentClient_IsDemotedToObserve_WithAndWithoutExe` (Theory, 14 client names ×
    bare/`.exe`/uppercase)
  - `NonTorrentProcess_IsNotDemoted` (`beacon`, `beacon.exe`, null, empty → false)

No `.trx` artifacts were produced (none found under the worktree after the runs).

## Constraints honored

- Userland only; no kernel/driver/syscall changes.
- Fail-closed + observe-until-chain: all three fixes suppress only the RESPONSE for
  known-good processes; detections are still emitted and logged. No attack-tool signature
  weakened, no detection rule disabled.
- Tier2-never-acts preserved (the torrent fix relies on it).
- DI (constructor injection) unchanged; no new service added — extended the existing
  `AllowlistService` and reused the existing `BulkTransferNoise` allowlist.
- No string-built JSON; no static mutable state introduced; no unrelated refactoring.
