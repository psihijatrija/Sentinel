# Typed terminal-family migration

Status: **all kill-grade families tagged + parity-tested** (v2.5.7). The remaining
`null`/substring sites are legacy detections that stay on the proven substring path by
design; new terminal emit sites should declare `Family` and add a parity shape.

## Why

Kill authority in Sentinel is decided by classifying each detection into a *terminal
outcome family* (`CredentialDump`, `C2Beacon`, `TokenTheft`, ...). Historically that
classification was inferred from **substring matching against the rule name / evidence /
reasoning text** in `ResponsePolicy.ClassifyTerminalOutcome`. That works, but it is fragile:
rename a rule, or reword its evidence, and the detection can silently fall out of its
kill-grade family - the highest-consequence bug class on a SYSTEM-level responder.

The migration makes each detection able to declare its family **typed**, so classification
does not depend on fragile string matching.

## The mechanism

Three pieces (all already in place):

1. **`TerminalFamily` enum** (`src/Sentinel.Core/TerminalFamily.cs`) - the single source of
   truth for the family taxonomy and the kill-grade set. Canonical string names preserved
   exactly so every existing metadata/evidence/test contract still holds.

2. **`DetectionEvent.Family`** (`src/Sentinel.Core/Models.cs`) - an optional
   `TerminalFamily?`. `null` for legacy detections; set explicitly by migrated monitors.

3. **`ClassifyTerminalOutcome`** (`src/Sentinel.Core/ResponsePolicy.cs`) trusts the typed
   field first, then falls back to the legacy substring path.

## Safety ordering (do not change)

The typed field is consulted in a specific order, and the order is load-bearing:

```
1. IsBenignInstallerNoise(detection)  -> return null   (safety demotion ALWAYS wins)
2. IsWeakObserveSeed(detection)       -> return null   (safety demotion ALWAYS wins)
3. detection.Family.HasValue          -> return typed family   (authoritative)
4. SignalType switch                  -> legacy typed-ish mapping
5. substring match over TerminalOutcomes fragments -> legacy fallback
```

A typed `Family` must **never** override the benign-installer-noise or weak-observe-seed
demotions. This is locked by tests (`Typed_Family_Cannot_Override_Benign_Installer_Noise`,
`Typed_Family_Cannot_Override_WeakObserveSeed`). It means even a wrong/hostile family tag on
a Steam DirectX System32 write or a browser cast-observe stays non-terminal.

## How to migrate a monitor

For each `new DetectionEvent { ... }` that represents a real terminal outcome, add the typed
family next to `SignalType`:

```csharp
_ = _detectionEngine.EmitAsync(new DetectionEvent
{
    RuleName = "Credential Theft: LSASS Process Access",
    SignalType = SignalType.LsassAccess,
    Family = TerminalFamily.CredentialDump,   // <-- add this
    // ...
});
```

Rules:

- Only set `Family` on detections that genuinely represent a terminal outcome. Do **not**
  set it on observe-only / weak / UX-noise detections - leave those `null`.
- Pick the family the detection actually proves (match the legacy substring classification
  it currently gets). If unsure, check what `ClassifyTerminalOutcome` returns today.
- Never set a kill-grade family on a detection that should stay observe-only. The tier law
  and chain confirmation still apply; the typed family only fixes *classification*, not the
  observe-until-chain gating.
- Behavior must be unchanged: after migration, `ClassifyTerminalFamily` returns the same
  family it did before (now via the typed path instead of the substring path).

## Verification per migration

After each monitor:

1. `dotnet build Sentinel.sln -c Release -warnaserror` - must be 0W/0E.
2. `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug` - must stay green.
3. Add the site's emit shape to `TerminalFamilyMigrationParityTests.TaggedTerminalShapes`
   (see below). The parity guard then proves the tag matches the legacy result automatically.

## Test guards (the invariants are locked, not just documented)

Two suites protect this migration; a drift between the typed and legacy paths fails a test
with an obvious name rather than silently changing kill authority:

- **`TerminalFamilyConsistencyTests`** - taxonomy + safety ordering + that the typed path
  *works* (kill-grade string set == typed set, canonical round-trip, both safety demotions
  beat a hostile tag, rename-survival).
- **`TerminalFamilyMigrationParityTests`** (v2.5.7) - that each real tagged site's typed
  result *matches* its legacy result:
  1. **Per-site parity** - for every shape in `TaggedTerminalShapes`, classifying with
     `Family` set equals classifying with `Family` cleared (byte-for-byte). This converts
     the earlier code-review hand-tracing into a regression guard. **Add new tagged sites here.**
  2. **Family-vs-SignalType agreement** - for any tag whose `SignalType` is switch-mapped
     (`LsassAccess`/`CredentialTheft`->CredentialDump, `ReverseShell`, `NetworkC2`->C2Beacon),
     the switch family must equal the tag. Catches a future `NetworkC2` + `Family = Exfil`
     that would silently reclassify because `Family` is trusted first.
  3. **Weak/UX cannot be promoted** - a kill-grade `Family` on any detection carrying
     `WeakObserveSeed=true` or a `WeakChainOnly`/`PureUxObserve` rule fragment still
     classifies null. Encodes the "traps" section below as executable policy.
  4. **Conditional null-siblings** - the untagged branch of each conditional tag
     (`!hive`, `systemHost`, `!hostile`, `!permanent`, staging-path) classifies null.

## Progress log

| Family          | Monitor(s) migrated                                      | Emit sites | Status |
|-----------------|----------------------------------------------------------|-----------:|--------|
| CredentialDump  | `LsassDumpCanaryMonitor`, `Rules` (extras), `NetworkShareMonitor` (SMB lateral, `SignalType.CredentialTheft`) | 5 | done |
| C2Beacon        | `ThreatIntelFeedBlocker`, `NamedPipeMonitor` (Tier1 only), `RpcLateralMonitor` (Tier1 only), `NetworkMonitor` (Classic Malware Port), `ProtocolCoverageMonitors` (mesh + webhook), `GpuProcessMonitor`, `V217Hardening` (decoy-pipe connect), `Rules` (`AttackToolsRule` when category==C2, malicious C2 domain) | 10 | done |
| ReverseShell    | `Rules` (ClickFix Encoded, 0.96/Tier1/kill)              | 1          | done   |
| Injection       | `EtwThreatIntelMonitor` (remote memory injection, 0.95/Tier1/kill; ETW-TI unbacked return frame, 0.88/Tier1/LogOnly observe-until-chain) | 2 | done |
| Evasion         | `ScriptExecutionMonitor` (AMSI bypass, conditional on non-`systemHost`), `EtwThreatIntelMonitor` (unmapped thread), `CriticalMonitors` (Hell's Gate / indirect syscall), `EtwProviderTamperMonitor` (ETW/Event Log Manipulation) | 4 | done |
| TokenTheft      | `CoverageExpansionMonitors` (LPE Scaffold: Privilege Escalation Tool), `CveCoverageMonitors` (Kernel Exploit Loader, via `EmitAsync(family:)`), `FileActivityMonitor` (LegacyHive reparse, conditional on `hive`) | 3 | done |
| WmiPersistence  | `SystemIntegrityMonitors` (WMI Policy Rewrite; Hostile Event Subscription conditional on `hostile`), `EtwEventDispatcher` (WMI-Activity permanent, conditional on `permanent`) | 3 | done |

### Deliberately NOT tagged (kept `null` - correct per policy)

Tagging any of these would **change** the current classification (promote an observe-only /
weak / null detection to a terminal family, or switch an existing family), so they stay
`null` to keep behavior byte-for-byte identical.

C2Beacon-adjacent (emit `SignalType.NetworkC2` but observe-only / weak / demoted):

- `CastDeviceGuard` - observe-only cast connection.
- `PersistentConnectionMonitor` - "C2 Pairing: Failover..." is in `PureUxObserveRuleFragments`.
- `NamedPipeMonitor` high-entropy pipe (Tier2), `RpcLateralMonitor` suspicious-outbound (Tier2).
- `ForumHrWatchMonitor` - domain-specific watch with signed->Tier2 demotion; not cleanly terminal.
- `Rules` `AttackToolsRule` when `category != "C2"` - emits `SuspiciousProcess`; left `null` so the
  substring path (e.g. mimikatz -> CredentialDump) still governs.

Evasion-adjacent:

- `EtwProviderTamperMonitor` "EtwEventWrite Patched in Critical Process" - KillProcessTree/0.95/Tier1,
  but its RuleName/Evidence/Reasoning match **no** Evasion fragment, so it classifies `null` today.
  Tagging it would promote it to kill-grade - a behavior change. Left `null`.
- `ScriptExecutionMonitor` AMSI on `systemHost` - the "AMSI Not Loaded" observe branch; matches no
  fragment today, so the `Family` tag is conditional (`systemHost ? null : Evasion`).
- PID 0 / LogOnly SYSTEM posture checks (BCD, BitLocker, "ETW Session Stopped", hosts-file, etc.) -
  ambient integrity observations, never terminal.

TokenTheft-adjacent (the traps):

- `TokenTheftMonitor` "Non-Service Process with SYSTEM Token" - `SignalType.CredentialTheft` makes
  `ClassifyTerminalOutcome` return **CredentialDump** (via the SignalType switch, before substring),
  not TokenTheft. Tagging TokenTheft would switch its family. Left `null`.
- `TokenTheftMonitor` "SeImpersonatePrivilege from Suspicious Path" - RuleName contains
  "Token Theft: SeImpersonatePrivilege" which is a `WeakChainOnlyRuleFragment` -> `null` today.
- `CveCoverageMonitors` "Installer EoP from Staging" and "AlwaysInstallElevated Enabled" - carry
  `WeakObserveSeed=true` (and PID 0 for the latter) -> `null` today.
- `CoverageExpansionMonitors` "LPE Scaffold: Elevated Process from Staging Path" - Tier2/LogOnly, its
  RuleName matches no TokenTheft fragment -> `null` today.

WmiPersistence-adjacent:

- `SystemIntegrityMonitors` / `EtwEventDispatcher` non-hostile / temporary WMI branches - the
  `Family` tags are conditional (`hostile`/`permanent`) so the non-terminal branches stay `null`,
  matching the substring behavior (only "Hostile Event Subscription" / "WMI-Activity: Permanent" /
  "WMI Policy Rewrite" fragments are terminal).

(Updated as families are migrated.)
