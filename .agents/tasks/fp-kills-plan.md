# Implementation Plan — Fix False-Positive Process Kills (fix/false-positive-kills)

Worktree (ALL paths relative to this root): `e:\Gorstak\Sentinel\.worktrees\fix-fp-kills`
Branch: `fix/false-positive-kills` · Primary branch for final rebase: `main` · Current `version.txt`: `2.9.7` → bump to `2.9.8`.

## Context discovered during exploration (read before implementing)

- **Project**: Userland Windows EDR, C# / .NET Framework `net48-windows`. Solution: `Sentinel.sln`. All runtime detection code lives in `src/Sentinel.Core/`. Tests: `tests/Sentinel.Tests/` (xUnit 2.9.2 + Moq, `TargetFramework=net48-windows`).
- **Build command (canonical, 0W/0E gate)**: `dotnet build Sentinel.sln -c Release -warnaserror` (run from the worktree root). The installer build (`installer/build.ps1`) uses `dotnet publish ... -c Release -f net48-windows`; plain `dotnet` is the toolchain, not msbuild.
- **Test command**: `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug` (run from the worktree root). Tests must use temp dirs only, no elevation/network.
- **Response pipeline**: `Monitors → DetectionEngine → AdvancedResponseEngine`. Hard constraint: **Tier2 detections NEVER trigger a response** (enforced unconditionally in `AdvancedResponseEngine.HandleAsync`). Setting `Tier = DetectionTier.Tier2Indicator` is therefore the strongest no-kill guarantee available to a monitor; `AuthorizedResponse = ResponseAction.LogOnly` is the matching author action.
- **AllowlistService** (`src/Sentinel.Core/AllowlistService.cs`): constructor DI (`SecureCacheStore`, `ILogger`, optional `SignerTrustService`). `ShouldSuppress`/`GetConfidenceReduction` honor only the USER allowlist and never President's-Law rules. `IsDevelopmentProcess(name)` is a built-in static `DevelopmentProcesses` HashSet (already contains `git`, `git-remote-https`, `dotnet`, `powershell`, `pwsh`, etc.) consulted ONLY by `ParentPidSpoofDetector` **with signature verification at the call site**.
- **BulkTransferNoise** (`src/Sentinel.Core/BulkTransferNoise.cs`): the project's EXISTING built-in torrent/P2P/downloader name allowlist. `IsBulkTransferProcessName(name)` already matches all required torrent clients (qbittorrent, utorrent, bittorrent, transmission[-qt/-daemon], deluge[d/-gtk], tixati, vuze, azureus, frostwire, aria2c, …) case-insensitively, with/without `.exe`. Already consulted by `DataExfiltrationMonitor` and `AntiTaoMonitors` to demote network-volume FPs to Tier2 + LogOnly. **It is NOT yet consulted by `BeaconingDetector`.**

### Design decisions (chosen approach + rationale)

1. **PPID (git/gh)** — Extend `AllowlistService.DevelopmentProcesses` with the missing legitimate git transport/CLI helper names (`gh`, `git-remote-http`, `git-credential-manager`, `git-credential-manager-core`). `ParentPidSpoofDetector` already does `IsDevelopmentProcess(name)` + **mandatory Authenticode/signer verification** before `continue`-ing (skipping the KillProcess emit). Adding the names reuses that proven, path/signature-anchored call site exactly — no new mechanism, and name-alone never self-authorizes (binary must be validly signed). This is the narrowest fix the mechanism supports. (`ChainTracer` already preserves signed-installer and IDE ancestors and already special-cases PPID stock-host races; no ChainTracer edit is required, but it is covered by verification.)
2. **PowerShell "Sentinel" self-reference** — The FP is entirely inside `ScriptExecutionMonitor.MaliciousPatterns`, which lists the bare substring `"Sentinel"` (twice) and a never-matching literal `"Stop-Service.*Sentinel"` (patterns are matched with `string.Contains`, so the `.*` can never match real text). Any benign script mentioning the product name (e.g. `$env:ProgramData\Sentinel`) matches and is escalated to Tier1 `KillProcessTree`. Fix: remove the self-referential bare `"Sentinel"` literals and replace with narrow **behavioral** service-tamper literals that only match genuine Sentinel-evasion commands. Genuine attack-tool signatures (Mimikatz, AMSI, download cradles, injection APIs) are untouched. The other repo `"Sentinel"` occurrences are legitimate (service names, ProgramData paths, `AntiTamperGuard` self-protection) and are NOT script-block signatures — out of scope.
3. **Torrent clients vs network/beaconing kills** — Consult the existing `BulkTransferNoise.IsBulkTransferProcessName(history.ProcessName)` inside `BeaconingDetector.DetermineResponseAction`, mirroring the `DataExfiltrationMonitor` precedent: a recognized torrent/P2P client emits the detection (still LOGGED) but as `Tier2Indicator` + `ResponseAction.LogOnly` with `Metadata["BulkTransfer"]="true"`, so the hard "Tier2 never acts" rule guarantees no kill AND no NetworkIsolate. Chosen over duplicating a torrent list into `AllowlistService` because `BulkTransferNoise` is the project's canonical torrent allowlist already consulted by network detectors, keeping the fix minimal and consistent. (`BeaconingDetector` is the "beaconing / connection-rate / C2" detector that would terminate a torrent client; other `Network*`/`C2 Pairing` rules are already Tier2/observe or weak-chain-only per `ResponsePolicy` and do not kill on peer/connection volume.)

Preserve fail-closed + observe-until-chain throughout: these changes suppress the RESPONSE for known-good processes; detections may still be emitted and logged. No unrelated refactoring.

---

## Ordered implementation items

- [ ] 1. Extend the development-process allowlist with git transport/CLI helpers.
      Add `"gh"`, `"git-remote-http"`, `"git-credential-manager"`, `"git-credential-manager-core"` to the `DevelopmentProcesses` HashSet (the entry that already has `"git", "git-remote-https"`). Names only — the `ParentPidSpoofDetector` call site still requires a valid signature, so this does not grant name-only trust.
      Files: `src/Sentinel.Core/AllowlistService.cs`
      Verify: `dotnet build Sentinel.sln -c Release -warnaserror` succeeds (0W/0E). Covered by the unit test added in item 4.

- [ ] 2. Narrow the self-referential PowerShell "Sentinel" signatures.
      In `ScriptExecutionMonitor.MaliciousPatterns`, replace the `// Sentinel evasion` entries `"Sentinel", "Sentinel", "Stop-Service.*Sentinel"` with narrow behavioral literals that only match genuine service-tamper commands, e.g.: `"Stop-Service Sentinel"`, `"Stop-Service -Name Sentinel"`, `"sc stop Sentinel"`, `"sc.exe stop Sentinel"`, `"Set-Service Sentinel"`, `"Set-Service -Name Sentinel"` (all are literal substrings, since matching uses `string.Contains`). Do NOT touch Mimikatz/AMSI/credential/download-cradle/injection/persistence/webhook signatures. In the `isCritical` computation, the existing `p.Contains("Sentinel")` clause becomes safe automatically (every remaining "Sentinel" pattern is a service-stop command); leave it as-is so genuine Sentinel-shutdown attempts still escalate to Tier1.
      Files: `src/Sentinel.Core/ScriptExecutionMonitor.cs`
      Verify: `dotnet build Sentinel.sln -c Release -warnaserror` succeeds. Covered by the unit test added in item 5. (Note: the `MaliciousPatterns` array is `private`; the test exercises matching behavior through a pure helper — see item 5 — so expose matching via a small `internal static bool MatchesMaliciousPattern(string scriptBlock)` + `internal static bool IsCriticalScriptMatch(IReadOnlyList<string>)` helper, or `[assembly: InternalsVisibleTo("Sentinel.Tests")]` if not already present. Prefer adding the two `internal static` helpers that `CheckScriptBlockLogging` then calls, keeping production logic and test surface identical.)

- [ ] 3. Consult the torrent/bulk-transfer allowlist in the beaconing detector.
      In `BeaconingDetector`, before authorizing a kill for a confirmed statistical beacon, demote recognized bulk-transfer clients. Add an early check in `AnalyzeAllAsync` (right before building/emitting the `DetectionEvent`, after the CV/interval gates) OR at the top of `DetermineResponseAction`: if `BulkTransferNoise.IsBulkTransferProcessName(history.ProcessName)` is true, emit the detection with `Tier = DetectionTier.Tier2Indicator`, `AuthorizedResponse = ResponseAction.LogOnly`, and `Metadata["BulkTransfer"]="true"` (keep `SignalType = SignalType.NetworkC2` so it still correlates/logs), mirroring `DataExfiltrationMonitor`'s bulk-transfer branch. Keep the normal multi-factor `DetermineResponseAction` path for all other processes unchanged. Implement as a single guarded branch so the non-torrent flow is byte-for-byte unchanged.
      Files: `src/Sentinel.Core/BeaconingDetector.cs`
      Verify: `dotnet build Sentinel.sln -c Release -warnaserror` succeeds. Covered by the unit test added in item 6.

- [ ] 4. Add PPID-allowlist unit tests (git/git-remote-https/gh recognized).
      Append to the existing `AllowlistServiceTests` (mirror the existing `IsDevelopmentProcess_Recognizes_DevTools` fact): assert `IsDevelopmentProcess` returns true for `"git"`, `"git-remote-https"`, `"git-remote-http"`, `"gh"`, `"git-credential-manager"` and false for an attacker name like `"git-stealer"`. This proves the names the PPID rule consults are present (the kill-path skip also requires a valid signature, verified at the detector call site; the unit test targets the allowlist membership, which is the fix's surface).
      Files: `tests/Sentinel.Tests/AllowlistServiceTests.cs`
      Verify: `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug` — new facts pass, existing tests stay green.

- [ ] 5. Add PowerShell signature unit tests (benign "Sentinel" script does NOT match).
      Add a new test class `ScriptExecutionMonitorTests` (xUnit, mirror `AllowlistServiceTests` style) that calls the `internal static` matching helper(s) added in item 2. Cover:
      (a) a benign script containing `$env:ProgramData\Sentinel` (and one containing the bare word `Sentinel`) does NOT match any malicious pattern and is NOT critical;
      (b) a genuine evasion script containing `Stop-Service Sentinel` (and `sc.exe stop Sentinel`) DOES match and IS critical;
      (c) a genuine `Invoke-Mimikatz` / `AmsiScanBuffer` script still matches and is critical (proves attack signatures were not weakened).
      Files: `tests/Sentinel.Tests/ScriptExecutionMonitorTests.cs` (and the `internal static` helpers from item 2 in `src/Sentinel.Core/ScriptExecutionMonitor.cs`).
      Verify: `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug` — new tests pass.

- [ ] 6. Add beaconing torrent-allowlist unit test (torrent client not killed).
      Extend `BeaconingDetectorTests`. Because `DetermineResponseAction` is `private` and needs a heavy DI graph, verify through the stable public surface instead: assert `BulkTransferNoise.IsBulkTransferProcessName` returns true for each required torrent client name (`qbittorrent`, `utorrent`, `bittorrent`, `transmission`, `transmission-qt`, `transmission-daemon`, `deluge`, `deluged`, `deluge-gtk`, `tixati`, `vuze`, `azureus`, `frostwire`, `aria2c`) with and without `.exe`, and false for a non-torrent name (e.g. `"beacon"`). This proves the exact list the beaconing demotion consults. If feasible without an elevated/complex graph, also add an `internal static` demotion predicate in `BeaconingDetector` (e.g. `internal static bool ShouldDemoteBeaconToObserve(string processName)` wrapping the `BulkTransferNoise` check) and assert it returns true for a torrent client and false otherwise — this directly exercises the beaconing fix. Prefer the `internal static` predicate approach so the test exercises `BeaconingDetector`'s own code.
      Files: `tests/Sentinel.Tests/BeaconingDetectorTests.cs` (and, if using the predicate, `src/Sentinel.Core/BeaconingDetector.cs`).
      Verify: `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug` — new facts pass.

- [ ] 7. Bump the version by exactly one patch.
      Set `version.txt` contents to `2.9.8` (from `2.9.7`; no carry needed). Do NOT hand-edit any `*.csproj`/`setup.iss` version — `installer/build.ps1` stamps those from `version.txt`. Do NOT run `installer/release.ps1` or `push.ps1`.
      Files: `version.txt`
      Verify: file reads `2.9.8`.

- [ ] 8. Add the CHANGELOG entry for the release.
      Prepend a `## [2.9.8] - <today>` section above `## [2.9.7]` in `docs/CHANGELOG.md`, following the existing heading format (the release notes are extracted by exact `MAJOR.MINOR.PATCH` heading match). Under `### Fixed`, summarize the three false-positive fixes: (1) git/git-remote-https/git-remote-http/gh/git-credential-manager added to the PPID dev-process allowlist (still signature-gated); (2) PowerShell script-block rule no longer treats the bare product name "Sentinel" as a malicious signature — narrowed to genuine service-tamper commands; (3) torrent/P2P clients demoted to Tier2 LogOnly in `BeaconingDetector` via the existing `BulkTransferNoise` allowlist so C2/beaconing response never kills them (detections still logged). Add a "Version stamp 2.9.7 → 2.9.8" line under `### Changed`.
      Files: `docs/CHANGELOG.md`
      Verify: the new heading reads exactly `## [2.9.8] - <date>`; build/tests unaffected.

- [ ] 9. Full build + test gate (integration check for the seams between items).
      Run the full build and the full test project; fix any integration issues before finishing.
      Files: none (verification only).
      Verify: `dotnet build Sentinel.sln -c Release -warnaserror` reports 0 warnings / 0 errors AND `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug` reports all tests passing (new + existing). Clean up any temp artifacts (e.g. `*.trx`) produced by the test run.

- [ ] 10. Commit locally; stop at commit.
      Stage only the changed files by name (`src/Sentinel.Core/AllowlistService.cs`, `src/Sentinel.Core/ScriptExecutionMonitor.cs`, `src/Sentinel.Core/BeaconingDetector.cs`, the three test files, `version.txt`, `docs/CHANGELOG.md`) and commit on `fix/false-positive-kills` with a clear message (e.g. `fix: stop false-positive kills of git/gh, Sentinel-named scripts, and torrent clients (2.9.8)`). NEVER `git push` / `--force` / `--force-with-lease`; the release path (`push.ps1`) is run separately by the user. Work ends at the local commit (+ the final merge step's local rebase onto `main`).
      Files: none (git only).
      Verify: `git -C e:\Gorstak\Sentinel\.worktrees\fix-fp-kills status` shows a clean tree on `fix/false-positive-kills` with the new commit present (`git log -1 --oneline`).

## Notes / assumptions

- The build/test commands and `-warnaserror` 0W/0E gate were taken from this repo's own prior task docs (`docs/typed-family-migration.md`, `.agents/tasks/aggressive-dll-sweep/plan.md`); they are the project's established commands.
- Items 2, 5 and 6 add small `internal static` helpers purely to make the fix unit-testable without constructing heavy DI graphs or reading the Windows event log; they do not change production behavior (`CheckScriptBlockLogging` / `AnalyzeAllAsync` call the same helpers). If `InternalsVisibleTo("Sentinel.Tests")` is not already configured for `Sentinel.Core`, add it (check first — several existing tests already reach `internal`/`static` members like `ParentPidSpoofDetector.IsStockWindowsConsoleHost`, so it is almost certainly already enabled).
- The torrent demotion deliberately uses the behavioral/name allowlist only to suppress the RESPONSE on the network/beaconing path (Tier2 + LogOnly). President's-Law and non-network terminal rules are unaffected, preserving fail-closed and observe-until-chain.
