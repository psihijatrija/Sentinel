# PPID Name-Demote Findings — `ShouldDemotePpidToLogOnly`

**Investigation:** READ-ONLY. No source code was changed.
**Target:** `ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(string processName, string? imagePath, bool selfSigned, bool allowlistedDevTool = false)` — `src/Sentinel.Core/ParentPidSpoofDetector.cs:235`.
**Shipped-at:** commit `d63ad9d` "fix: PPID detector never kills allowlisted dev/browser tools on a signature-check race (3.0.0)" (2026-10-04).

---

## Summary answer

The concern is **real, not moot**. The `allowlistedDevTool` flag is derived **purely from the process NAME** with **no signature or path gate** at the call site, and it short-circuits the demote decision **before any path or signature check**. A process merely named `gh`/`git`/`chrome`/etc. running from an untrusted path such as `C:\Temp\gh.exe` has its PPID-spoof kill demoted to `LogOnly`. This is exactly the "attacker-controllable trust on a kill-authority path" that `.kiro/steering/constraints.md` and `docs/constraints.md` forbid.

**Recommendation: TIGHTEN** — trust the allowlisted *name* only when the image path is **null/empty (unresolved)** — the genuine transient-race window. If a path **did** resolve, require the normal signed-or-OS-path check to pass; otherwise let the kill stand. This closes the `C:\Temp\gh.exe` hole without reintroducing the mid-operation kill race, because the race the current code guards against is specifically the *unresolved-path / signature-not-yet-verified* window, and real git/gh/chrome either resolve to a signed path or resolve to no path at all — never to an unsigned path under `\Temp\`.

The comment's claim that "an impostor merely named gh/git is caught by other rules" is **only partially true**: an impostor is caught by other rules **only if it additionally performs** behavioral acts (injection, C2, credential access, unsigned-staging-path execution). The PPID-spoof signal itself — the one kill-grade terminal this detector produces — is neutralized by the name-demote, and no other rule re-derives a *kill* from PPID spoofing alone.

---

## Evidence

### (a) How `allowlistedDevTool` is computed and passed — the single call site

`ParentPidSpoofDetector.Scan` (`src/Sentinel.Core/ParentPidSpoofDetector.cs:161-162`):

```csharp
bool allowlistedDevTool = (isDev || isBrowser);
bool demote = ShouldDemotePpidToLogOnly(proc.ProcessName, imagePath, selfSigned, allowlistedDevTool);
```

where (`ParentPidSpoofDetector.cs:96-99`):

```csharp
bool isDev = _allowlist.IsDevelopmentProcess(proc.ProcessName);
var lowerName = proc.ProcessName.ToLowerInvariant();
bool isBrowser = lowerName is "chrome" or "msedge" or "firefox" or "brave" or "opera" or "vivaldi";
```

Both inputs are **name-only**:

- `AllowlistService.IsDevelopmentProcess(string processName)` (`src/Sentinel.Core/AllowlistService.cs:71-74`) is a pure set-membership test against the static `DevelopmentProcesses` HashSet (`AllowlistService.cs:76-87`, contains `git`, `git-remote-https`, `gh`, `dotnet`, `node`, `python`, `powershell`, `cmd`, etc.). Its own doc-comment states: *"Requires path verification at the call site - this method alone does NOT grant any suppression."* — but the PPID call site does **not** add that path verification before setting `allowlistedDevTool`.
- `isBrowser` is a literal name switch on `proc.ProcessName`.

So `allowlistedDevTool` is `true` for anything **named** `gh` (etc.), regardless of path or signature. `selfSigned` (`ParentPidSpoofDetector.cs:139-142`) *is* a real signature check, but it is passed as a **separate** argument and the method returns on `allowlistedDevTool` **before** `selfSigned` matters in the attacker's favor — see below.

### The demote method short-circuits on name before any path/signature test

`ShouldDemotePpidToLogOnly` (`src/Sentinel.Core/ParentPidSpoofDetector.cs:235-258`):

```csharp
internal static bool ShouldDemotePpidToLogOnly(
    string processName, string? imagePath, bool selfSigned, bool allowlistedDevTool = false)
{
    if (selfSigned) return true;
    // ... (long comment) ...
    if (allowlistedDevTool) return true;                              // <-- name-only exoneration
    if (IsStockWindowsConsoleHost(processName, imagePath)) return true;
    if (!string.IsNullOrEmpty(imagePath) && SecurityValidation.IsOsCriticalPath(imagePath))
        return true;
    return false;
}
```

The `if (allowlistedDevTool) return true;` line executes **before** `IsStockWindowsConsoleHost` and the `IsOsCriticalPath` check, and `allowlistedDevTool` is true purely by name. `imagePath = C:\Temp\gh.exe` is never consulted on this branch.

### (b) Is the name-demote genuinely attacker-controllable, or already gated?

**Genuinely attacker-controllable.** The caller gates `allowlistedDevTool` on nothing but the process name. Contrast this with the **top-of-scan signed-skip** (`ParentPidSpoofDetector.cs:95-104`), which *is* correctly anchored:

```csharp
if (isDev || isBrowser)
{
    // Only skip if the binary is validly signed - no path-based trust
    if (!string.IsNullOrEmpty(imagePath) && _signerTrust.IsSignedFile(imagePath!))
    {
        continue;
    }
}
```

That gate requires **both** a resolved `imagePath` **and** a passing `SignerTrustService.IsSignedFile`. The problem is strictly the *fallthrough* path: when that gate does **not** fire (path unresolved OR signature check failed/raced), execution reaches the kill branch, and there the name-only `allowlistedDevTool` demote fires unconditionally — re-introducing name trust that the top-of-scan gate was careful to avoid.

Note the stricter sibling, `IsStockWindowsConsoleHost` (`ParentPidSpoofDetector.cs:264-293`): it demotes `conhost`/`openconsole` by name **only when the path is empty**; a *resolved* path must be under `\windows\system32\` / `\syswow64\` / an OS-critical path. That is precisely the null-path-only pattern this report recommends for dev/browser names — the console-host path already models the safe shape.

### (2) The exact "signature-check race" the comment describes

- **Top-of-scan signed-skip gate:** `ParentPidSpoofDetector.cs:95-104` (quoted above). Requires `imagePath` resolved **AND** `SignerTrustService.IsSignedFile(imagePath)` true, within one scan tick.
- **Scan cadence:** the detector timer runs every **10 seconds** (`ParentPidSpoofDetector.cs:61`: `TimeSpan.FromSeconds(10)`), not ~2s. (The method/field comments say "2s tick"; the actual period is 10s. Either way the race is per-tick.)
- **Path resolution:** `imagePath` comes from `SecurityValidation.GetProcessImagePath(proc.Id)` (`ParentPidSpoofDetector.cs:76`), which opens a `PROCESS_QUERY_LIMITED_INFORMATION` handle and calls `QueryFullProcessImageName` (`SecurityValidation.cs:771-787`). Short-lived helpers (`gh`, `git-remote-https`) can exit before this resolves, returning `null`. A fallback then reads the ancestry cache's recorded path (`ParentPidSpoofDetector.cs:82-90`).
- **Signature call:** `SignerTrustService.IsSignedFile` (`SignerTrustService.cs:65-91`) → `SecurityValidation.VerifyAuthenticodeSignature` (`SecurityValidation.cs:482`) → native `WinVerifyTrust` (`SecurityValidation.cs:529`), with a catalog-store fallback via `CryptCATAdmin` for catalog-signed binaries (`SecurityValidation.cs:572-653`). This is the slow part: it memory-maps and hashes the PE and walks the trust chain.
- **Mitigations already present against the race:** both `SignerTrustService` and `SecurityValidation` cache results. `SecurityValidation.AuthenticodeCache` (`SecurityValidation.cs:436`) keys on `(LastWriteTimeUtc, Length)` and is checked first (`SecurityValidation.cs:498-500`); `SignerTrustService._cache` keys on path + `LastWrite` (`SignerTrustService.cs:70-91`). So after the first successful verification of a given signed binary, subsequent ticks are a dictionary hit — the signature call does **not** meaningfully race on steady-state ticks for a stable, signed binary. The genuine race is therefore dominated by **(a) the path never resolving** (process already exited) rather than (b) a repeated-slow-verify of an already-cached binary.

**How often does it realistically race?** The dominant race is the *unresolved path* case for ultra-short-lived helpers, which is exactly the case the recommended tightening still demotes. A cold-cache first-sight slow-verify is possible but is a one-time event per `(path)` and is bounded by the cache; it does not recur every push.

### (3) Would tightening close the hole without reintroducing the race?

**Yes.** The precise safe condition:

> Demote by allowlisted *name* only when `string.IsNullOrEmpty(imagePath)` (the transient unresolved-path window). If `imagePath` resolved, do **not** demote on name; fall through to the existing `selfSigned` / `IsStockWindowsConsoleHost` / `IsOsCriticalPath` checks and let the kill stand if those fail.

Why this does not reintroduce the mid-operation kill race:

- The race the current code guards against is the window where **the path or signature has not yet resolved**. A real `gh`/`git` that is mid-push and short-lived resolves to **either** a signed path under Program Files / its install dir (caught by `selfSigned` or the top-of-scan signed-skip) **or** to **no path at all** (caught by the `imagePath == null` demote the tightening preserves). It does **not** resolve to an *unsigned binary under `C:\Temp\`*.
- Conversely, `C:\Temp\gh.exe` is, by construction, a **resolved** path that is **not** signed and **not** OS-critical — the only case the tightening newly refuses to demote. That is the attacker, not the real tool.
- `selfSigned` already covers the legitimate signed-but-outside-top-gate case (`ParentPidSpoofDetector.cs:139-142` recomputes it via `IsSignedFile` OR `VerifyAuthenticodeSignature`), and the Authenticode cache makes it cheap after first sight. So a validly-signed real tool whose top-of-scan skip raced is still demoted via `selfSigned` — not via name.

**Is the signature check reliable/fast enough for the tightened path to be safe?** Yes, with the caveat that it is first-sight-slow then cached. The tightened path does not *depend* on a fresh signature pass to protect the real tool: if the signature check races to a false negative on a resolved path, the real tool is signed and the *next* tick's cached hit demotes it (or the top-of-scan skip does). The only process that stays kill-eligible across ticks is one that is genuinely unsigned at a resolved untrusted path — i.e. the impostor.

### (4) ATT&CK consequence and the "caught by other rules" claim

**Attack enabled by the current unconditional name-demote:** An attacker drops a payload named `gh.exe` (or `git.exe`, `chrome.exe`, …) in `C:\Temp\` and uses PPID spoofing (T1134.004 — set a forged parent via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) to masquerade its lineage and defeat parent-child behavioral analysis. The `ParentPidSpoofDetector` detects the kernel-vs-ETW parent mismatch (the detector's whole purpose) but, because the name is on the dev/browser allowlist, demotes the response from `KillProcess` (0.85, Tier1) to `LogOnly` (0.55, Tier2). The PPID-spoof kill is suppressed by name alone.

**Is the impostor "caught by other rules"?** Partially — and critically, **not for the PPID signal itself**:

- There is **no** rule in the current `src/Sentinel.Core` tree that re-derives a *kill* from PPID spoofing. The historical "Spoofed Process Phoning Home" composite named in `docs/CHANGELOG.md` does **not** exist in current source (grep for `Parent PID Mismatch` / `Phoning Home` / `Spoofed` in `src/Sentinel.Core/**` returns no matches). The PPID detector is the sole producer of the PPID-spoof signal, and its kill is exactly what the demote removes.
- `UnsignedBinaryRule` (`src/Sentinel.Core/Rules.PathProvenance.cs`) **would** flag `C:\Temp\gh.exe` ("Binary executed from user-writeable path"), but only as **Tier2 / Confidence 0.60 / LogOnly** observe fuel — it never kills alone (and `AdvancedResponseEngine` enforces Tier2-never-acts unconditionally).
- The behavioral composites in `BehavioralCorrelationEngine` (`Injected C2 Beacon` 0.98, `Credential Dump + Exfiltration` 0.96, `Fileless Attack Chain` 0.95, `Covert RAT` etc.) key off **`SignalType`** (ProcessInjection, NetworkC2, CredentialTheft, Ransomware, …), **not** off the process name or the PPID signal. They catch the impostor **only if it additionally performs** those behaviors. An attacker who PPID-spoofs to hide lineage and then operates quietly (e.g., long-dwell recon, or injection the memory scanners happen to miss) loses the one dedicated T1134.004 kill that would have fired.

So the comment's defense ("caught by other rules") holds for *noisy* impostors that also trip behavioral terminals, but it is **not** true that the PPID-spoof kill itself is redundant. For the specific job of this detector, the name-demote is the only line of defense and it is being waived by name.

### (5) Which constraint this does/does not violate

It **violates** the hard constraint repeated verbatim in both `.kiro/steering/constraints.md` ("Adversarial mindset…") and `docs/constraints.md` (row "Adversarial mindset: no attacker-controllable trust"):

> *"never grant trust on a signal an attacker controls … A filename, filename prefix, or folder name **alone** must never self-authorize a module … MUST be combined with a non-attacker-controllable anchor: a trusted-root load location … a valid Authenticode signature, and/or a proven legitimate loading host."*

The name-demote grants a trust decision (decline the kill) on `processName` **alone**, with no non-attacker-controllable anchor. It also sits against the spirit of:

- **"Behavioral signals only for kill authority — detect what a process DOES, not what it IS (no filename/path/hash as a primary kill)."** Here a filename is used as the primary basis to *withhold* a kill on a behavioral detection — the inverse abuse, same category (name-based kill-authority decision).
- **"No filename-based primary detection … Process names are trivially spoofed. Filename lists are … observe fuel only."** (Detection Integrity Constraints.)

It does **not** violate the Tier2-never-acts rule or observe-until-chain — the demote direction is *toward* LogOnly, which is "safe" for FPs but is exactly what makes it an attacker-usable evasion here.

Note the distinction: using an allowlisted name to decline a kill when the path is **unresolved** (the recommended tightening) is defensible — there is no resolved attacker-controllable anchor to check, and failing *open* on a transient race for a known dev-tool name is the lesser evil (mirrors the sanctioned `IsStockWindowsConsoleHost` empty-path carve-out). Using the name to decline the kill when a path **did** resolve to an untrusted location is the constraint violation.

---

## Conclusions & recommendation

**TIGHTEN.** Replace the unconditional name demote with a null-path-gated one.

### Precise code-change shape (not applied)

In `ShouldDemotePpidToLogOnly` (`src/Sentinel.Core/ParentPidSpoofDetector.cs:252`), change:

```csharp
if (allowlistedDevTool) return true;
```

to gate on an unresolved path only:

```csharp
// Allowlisted dev/browser NAME demotes the kill only in the genuine transient-race window:
// the image path could not be resolved this tick (short-lived gh/git-remote-https exited
// before QueryFullProcessImageName). If a path DID resolve, name is not enough — fall through
// to selfSigned / stock-console-host / OS-critical-path, so an impostor at C:\Temp\gh.exe is
// NOT exonerated by its name. (selfSigned above already demotes a validly-signed real tool.)
if (allowlistedDevTool && string.IsNullOrEmpty(imagePath)) return true;
```

This mirrors the already-shipped `IsStockWindowsConsoleHost` pattern (name-demote only when path empty; resolved path must pass a non-attacker-controllable check). The caller at `ParentPidSpoofDetector.cs:161-162` needs no change — `imagePath` is already passed. The `demoteTag` branch at `ParentPidSpoofDetector.cs:174-177` continues to work (it only reads `allowlistedDevTool` for the log string; the demote decision now also reflects the path).

Optional hardening (not required for correctness): the caller could also stop setting `allowlistedDevTool` when `imagePath` resolved to a user-writable staging path (`SecurityValidation.IsUserProfileOrStagingPath`), but the method-level null-gate above is the minimal, sufficient fix.

### Tests that would need to change

In `tests/Sentinel.Tests/ParentPidSpoofDetectorTests.cs`:

1. **`ShouldDemotePpidToLogOnly_AllowlistedDevTool_DemotesRegardlessOfPath`** (`:82-87`) — asserts `("gh", @"C:\Temp\gh.exe", selfSigned:false, allowlistedDevTool:true)` returns **true**. Under the tightening this must become **false** (resolved untrusted path, unsigned → kill stands). The test name/comment (which assert "DemotesRegardlessOfPath" is "by design") must be rewritten to the corrected intent — this is the exact stale assertion called out in the brief and in `.agents/tasks/input-integrity-verification.md:77-82`, where a prior refinement test (`allowlistedNameUnresolvedPath`) was *reverted* to match shipped behavior. The tightening restores that original intent.
2. **`ShouldDemotePpidToLogOnly_ReturnsTrue_ForAllowlistedNameWithUnresolvedPath`** (`:59-64`) — asserts `gh`/`git-remote-https`/`chrome` with `null`/`""` path and `allowlistedDevTool:true` return **true**. This stays **green** (the transient-race window is still demoted) and documents the preserved behavior.
3. **`ShouldDemotePpidToLogOnly_ReturnsFalse_ForNonAllowlistedUnresolvedPath`** (`:70-74`) — unaffected (stays green).
4. **New test to add:** an allowlisted name with a resolved untrusted path and `selfSigned:true` (e.g. `("gh", @"C:\Program Files\GitHub CLI\gh.exe", selfSigned:true, allowlistedDevTool:true)`) must still return **true** via the `selfSigned` branch — proving the real signed tool is still protected after tightening.

`tests/Sentinel.Tests/InstallerFalsePositiveTests.cs` `ShouldDemotePpidToLogOnly_WinReducerCase` (`:107-111`) calls the 3-arg overload (no `allowlistedDevTool`) and is **unaffected**.

---

## File / symbol index

- `src/Sentinel.Core/ParentPidSpoofDetector.cs` — `Scan` (`:63`), timer 10s (`:61`), `imagePath` resolve (`:76`), top-of-scan signed-skip (`:95-104`), `isDev`/`isBrowser` (`:96-99`), `selfSigned` (`:139-142`), `allowlistedDevTool` compute (`:161`), demote call (`:162`), `ShouldDemotePpidToLogOnly` (`:235-258`), name short-circuit (`:252`), `IsStockWindowsConsoleHost` (`:264-293`).
- `src/Sentinel.Core/AllowlistService.cs` — `IsDevelopmentProcess` (`:71-74`), `DevelopmentProcesses` set (`:76-87`), `IsUserAllowlisted` path+signature anchor (`:120-150`).
- `src/Sentinel.Core/SignerTrustService.cs` — `IsSignedFile` (`:65-91`), cache (`:27`).
- `src/Sentinel.Core/SecurityValidation.cs` — `VerifyAuthenticodeSignature` (`:482`), `WinVerifyTrust` import (`:302`), `AuthenticodeCache` (`:436`), `GetProcessImagePath` (`:771`), `IsOsCriticalPath` (`:169`), `IsUserProfileOrStagingPath` (`:810`).
- `src/Sentinel.Core/Rules.PathProvenance.cs` — `UnsignedBinaryRule` (Tier2/0.60, flags Temp/Downloads), `FullPathParentChildRule` (SENT-003, Tier2).
- `src/Sentinel.Core/BehavioralCorrelationEngine.cs` — composites keyed on `SignalType`, not PPID/name.
- `src/Sentinel.Core/ChainTracer.cs` — defense-in-depth PPID/OS-path chain-kill skip (`:188-192`).
- `.kiro/steering/constraints.md` / `docs/constraints.md` — "Adversarial mindset: no attacker-controllable trust"; "Behavioral signals only for kill authority"; "No filename-based primary detection".
- Commit `d63ad9d` (3.0.0) — introduced the unconditional name demote; `d2d7ba2` (2.9.9) — the prior unresolved-path fix.

*Content from `docs/CHANGELOG.md` and licensing-neutral project files was rephrased/summarized for this report.*
