# Verification Note — PPID name-demote + stale TLS test fixes

Branch: `feature/ppid-tls-fixes`
Worktree: `e:\Gorstak\Sentinel\.worktrees\ppid-tls-fixes`

## Changes

### FIX 1 — PPID name-demote tightened to unresolved-path-only (kill-authority)
Product: `src/Sentinel.Core/ParentPidSpoofDetector.cs`, `ShouldDemotePpidToLogOnly`.
Replaced the unconditional name demote
`if (allowlistedDevTool) return true;`
with
`if (allowlistedDevTool && string.IsNullOrEmpty(imagePath)) return true;`
and rewrote the preceding comment to explain: an allowlisted dev/browser NAME demotes the kill
only in the genuine transient unresolved-path race window; if a path resolved, fall through to
the selfSigned / IsStockWindowsConsoleHost / IsOsCriticalPath checks so an impostor at a
resolved untrusted path (C:\Temp\gh.exe) is not exonerated by name. Mirrors the shipped
IsStockWindowsConsoleHost empty-path carve-out. Caller at ~line 161-162 unchanged (imagePath
already passed).

Tests: `tests/Sentinel.Tests/ParentPidSpoofDetectorTests.cs`
- Renamed `ShouldDemotePpidToLogOnly_AllowlistedDevTool_DemotesRegardlessOfPath` ->
  `ShouldDemotePpidToLogOnly_AllowlistedDevTool_ResolvedUntrustedPath_DoesNotDemote`; it now
  asserts FALSE for ("gh", C:\Temp\gh.exe, selfSigned:false, allowlistedDevTool:true), with a
  corrected comment.
- Added `ShouldDemotePpidToLogOnly_AllowlistedDevTool_ResolvedSignedPath_Demotes`: asserts TRUE
  for ("gh", C:\Program Files\GitHub CLI\gh.exe, selfSigned:true, allowlistedDevTool:true) via
  the selfSigned branch.
- `ShouldDemotePpidToLogOnly_ReturnsTrue_ForAllowlistedNameWithUnresolvedPath` still passes
  (unresolved-path window still demotes).
- `InstallerFalsePositiveTests.ShouldDemotePpidToLogOnly_WinReducerCase` (3-arg overload)
  unaffected and still passes.

### FIX 2 — stale TLS no-EKU test thresholds corrected (TEST-ONLY)
Tests: `tests/Sentinel.Tests/Monitors/TlsCertificateMonitorTests.cs`
- `AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence`: `Confidence < 0.60` ->
  `Confidence <= 0.65`, comment updated to note the +0.25 no-EKU/All-Purpose bonus.
- `AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored`: strict `< 0.65` -> `<= 0.65`,
  message updated. The companion `Assert.DoesNotContain(..., "No CRL/OCSP")` left unchanged.
- No product-code change. The +0.25 no-EKU/All-Purpose scoring (T1553.004 / T1587.002
  detection) is intentional and preserved.

## Commands run (from worktree root) and results

1. `dotnet build Sentinel.sln -c Release`
   => Build succeeded. 0 Warning(s), 0 Error(s).

2. `dotnet test --filter "ParentPidSpoof|TlsCertificate" -c Release --no-build`
   => Passed! Failed: 0, Passed: 33, Skipped: 0, Total: 33.

3. `dotnet test -c Release --no-build` (full suite)
   => Passed! Failed: 0, Passed: 2646, Skipped: 0, Total: 2646, Duration: 1m 33s.

The two previously-known `TlsCertificateMonitorTests` failures
(`AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence`,
`AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored`) are GONE. No other failure
surfaced. No unrelated changes made.
