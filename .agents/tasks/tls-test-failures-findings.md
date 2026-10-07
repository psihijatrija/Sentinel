# TLS Certificate Monitor — Test Failure Investigation (READ-ONLY)

## Summary (answer first)

Two tests in `TlsCertificateMonitorTests` fail. Both exercise a **self-signed root with no
suspicion signals**, and both get an actual `Confidence` of **0.65** where the assertions
require it to be lower.

| Test | File:Line | Asserts | Actual | Delta |
|------|-----------|---------|--------|-------|
| `AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence` | `tests/Sentinel.Tests/Monitors/TlsCertificateMonitorTests.cs:22` | `Confidence < 0.60` | **0.65** | +0.05 over |
| `AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored` | `tests/Sentinel.Tests/Monitors/TlsCertificateMonitorTests.cs:49` | `Confidence < 0.65` | **0.65** | +0.00 (strict `<` fails on equality) |

**Root cause (c): a stale/self-inconsistent commit, not a product regression and not
nondeterminism.** The scoring code and the two tests were written in the **same commit**
(`46aaa18 "chore: update"`), which added an EKU-capability scoring block to
`TlsCertificateMonitor.AnalyzeCert`. That block adds **+0.25** for a certificate that carries
**no EKU extension** (treated as "All-Purpose" per RFC 5280). The test helper builds its certs
with a bare `CertificateRequest`, so they have **no EKU extension** and pick up the +0.25. The
two failing tests' comments still describe the *pre-EKU* model ("base 0.40, no bonus for
self-signed anymore"), so the assertions were never reconciled with the EKU bonus the same
commit introduced. The failures are **not** caused by the recent input-integrity work
(`c3cd372`), which touched only `InputIntegrityGuard.cs` / `InputIntegrityGuardTests.cs`.

**Recommendation: fix the TEST side** (loosen the two thresholds to accommodate the intentional
EKU All-Purpose bonus), *unless* the product owner decides a bare self-signed root with no EKU
should **not** receive the full All-Purpose penalty — in which case fix the product (gate the
All-Purpose bonus). The test-side fix is lower risk and preserves current detection behavior.
Exact changes for both options are given below. **No change was made.**

---

## Evidence

### 1. The failing tests

Captured from `dotnet test --filter "FullyQualifiedName~TlsCertificateMonitorTests"` run from
`e:\Gorstak\Sentinel` (net48, 2 Failed / 13 Passed / 15 Total):

```
Failed ...AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored [32 ms]
  Error Message:
   Long-lived root should stay below remove threshold, got 0.65
  ...TlsCertificateMonitorTests.cs:line 49

Failed ...AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence [46 ms]
  Error Message:
   Self-signed alone should be < 0.60, got 0.65
  ...TlsCertificateMonitorTests.cs:line 22

Failed!  - Failed: 2, Passed: 13, Skipped: 0, Total: 15, Duration: 696 ms - Sentinel.Tests.dll (net48)
```

Test source (`tests/Sentinel.Tests/Monitors/TlsCertificateMonitorTests.cs`):

- Lines 17-23 — `AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence`:
  ```csharp
  using var cert = CreateTestCert("CN=SomeRootCA", "CN=SomeRootCA", 3650);
  var result = TlsCertificateMonitor.AnalyzeCert(cert);
  Assert.True(result.IsSelfSigned);
  // Base confidence is 0.40, no bonus for self-signed anymore
  Assert.True(result.Confidence < 0.60, $"Self-signed alone should be < 0.60, got {result.Confidence}");
  ```
- Lines 43-50 — `AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored`:
  ```csharp
  using var cert = CreateTestCert("CN=Some New National Root CA", "CN=Some New National Root CA", 3650 * 10);
  var result = TlsCertificateMonitor.AnalyzeCert(cert);
  Assert.True(result.IsSelfSigned);
  Assert.DoesNotContain(result.Reasons, r => r.Contains("No CRL/OCSP"));
  Assert.True(result.Confidence < 0.65, $"Long-lived root should stay below remove threshold, got {result.Confidence}");
  ```

Both certs are produced by the helper, which creates a self-signed cert with **no EKU
extension** (lines 177-186):
```csharp
using var rsa = RSA.Create(2048);
var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var cert = req.CreateSelfSigned(new DateTimeOffset(notBefore), new DateTimeOffset(notAfter));
```

### 2. Product code under test — scoring trace

Class: `TlsCertificateMonitor` in
`src/Sentinel.Core/Monitors/SystemIntegrityMonitors.cs:181`.
Method under test: `internal static CertAnalysisResult AnalyzeCert(X509Certificate2 cert)`
(declared at line ~554).

Scoring walk-through for **both** failing certs (self-signed, long validity, no EKU, benign CN):

1. `double confidence = 0.40;` — base, `tier = Tier2Indicator`.
2. Not in `KnownPublicRootCAs` / `KnownEnterpriseCAs` / `KnownDevToolCAs` → the `isPublicRootCA /
   isEnterpriseCa / isDevTool` caps are skipped; the suspicion-signal block (`!isPublicRootCA &&
   !isEnterpriseCa && !isDevTool`) runs.
3. Validity ≥ 365 days → **no** short-validity (+0.15) and **no** very-short (+0.10).
4. `looksLikeLongLivedRoot = isSelfSigned && validity.TotalDays >= 365*5` is **true** for both
   (3650 days and 36500 days). Therefore the `No CRL/OCSP` penalty (+0.15) is **suppressed** —
   this is exactly what `AnalyzeCert_...MissingCrl_NotScored` relies on and asserts
   (`DoesNotContain "No CRL/OCSP"`), and that part of the test still passes.
5. CN `SomeRootCA` / `Some New National Root CA`: length > 4, not hex-like, not hostname-like → no CN penalties.
6. Not expired; no suspicious keywords; validity `36500` is **not** `> 36500`, so no absurd-validity (+0.20).
7. **EKU block (step 13, lines ~728-764):** certs have no EKU extension, so
   `hasEkuExtension = false` → `isAllPurpose = true` (lines ~737-741). Because the cert is not
   public/enterprise/dev, the gate at line 745 is entered and the `isAllPurpose` branch adds:
   ```csharp
   if (isAllPurpose)
   {
       confidence += 0.25;                     // SystemIntegrityMonitors.cs:761
       reasons.Add("Root cert has no EKU restriction / All-Purpose ...");
   }
   ```
8. `confidence = Math.Min(confidence, 0.99)` → **0.40 + 0.25 = 0.65**.
9. `0.65 < 0.80`, so the cert stays `Tier2Indicator` (not promoted to Tier1).

Net: **0.65** for both. The only non-base contribution is the EKU All-Purpose +0.25.

### 3. Git-history root-cause determination

- `HEAD = c3cd372` `"feat: add InputIntegrityGuard, register AcousticThreatMonitor, remove
  PhantomKeystrokeGuard"`. `git show --stat c3cd372` touches **only**
  `src/Sentinel.Core/InputIntegrityGuard.cs` and
  `tests/.../Monitors/InputIntegrityGuardTests.cs` — **no** TLS/cert/scoring files. Confirms the
  failures pre-date the input-integrity work.
- The failing assertions (`blame -L 20,24` and `-L 45,50`) and the EKU All-Purpose scoring
  (`blame -L 745,765`, including `confidence += 0.25` at line 761) were **all last written in the
  same commit `46aaa18 "chore: update"`** (2026-10-01), the commit directly before HEAD.
  `git log --follow` for both the test file and `SystemIntegrityMonitors.cs` shows `46aaa18` as
  the most recent touch of each.
- `git merge-base --is-ancestor 46aaa18 HEAD` → true. So `46aaa18` is the parent of the
  input-integrity commit; its test failures were already present on that base.

**Interpretation:** This is **not** a product regression introduced by later work, and **not**
environmental nondeterminism (the certs are generated in-process with fixed relative validity;
dates/culture/machine-store are not involved, and the score is a deterministic 0.65 on every
run). It is a **self-inconsistent commit**: `46aaa18` introduced the EKU-capability scoring
(+0.25 for All-Purpose / no-EKU) but left two tests — plus their comments — written against the
earlier "base 0.40, nothing added for a bare self-signed root" model. The test comment
`// Base confidence is 0.40, no bonus for self-signed anymore` is now factually wrong: a
bare self-signed test cert gets +0.25 because it has no EKU extension.

---

## Conclusions & recommendation

The scoring behavior is **intentional and defensible**: under RFC 5280 a root cert with no EKU
extension can sign for *any* purpose (TLS interception *and* code signing), which is a genuine
risk signal, so penalizing the no-EKU/All-Purpose case is a deliberate design choice made in
`46aaa18`. The tests simply were not updated to match. The two certs end at **0.65**, which is
**Tier2Indicator / LogOnly** and **below every removal threshold** in the runtime path
(`PollStoreAsync`: 0.80 for `RemoveCert`/`RemoveCertAndKillAdder`, 0.75 for weak-signal
`RemoveCert`; startup path requires ≥0.90 to remove). Per `.kiro/steering/constraints.md`,
**Tier2 can never trigger a response action.** So neither fix option changes live
detection/removal behavior for these inputs — the disagreement is purely about the test's
expected number.

### Recommended: fix the TEST side (preferred)

Align the two thresholds with the intended scoring (base 0.40 + All-Purpose 0.25 = 0.65 for a
bare self-signed root). This keeps product detection semantics unchanged.

- `tests/Sentinel.Tests/Monitors/TlsCertificateMonitorTests.cs:22`
  — change
  ```csharp
  Assert.True(result.Confidence < 0.60, $"Self-signed alone should be < 0.60, got {result.Confidence}");
  ```
  to
  ```csharp
  Assert.True(result.Confidence <= 0.65, $"Self-signed alone (base + no-EKU/All-Purpose) should be <= 0.65, got {result.Confidence}");
  ```
  and update the stale comment on line 21 from `// Base confidence is 0.40, no bonus for
  self-signed anymore` to note the +0.25 All-Purpose (no-EKU) bonus.
- `tests/Sentinel.Tests/Monitors/TlsCertificateMonitorTests.cs:49`
  — change the strict `< 0.65` to `<= 0.65`:
  ```csharp
  Assert.True(result.Confidence <= 0.65, $"Long-lived root should stay at/below remove threshold, got {result.Confidence}");
  ```
  (The companion assertion `DoesNotContain "No CRL/OCSP"` already passes and should be kept.)

**Reasoning:** the scoring change was intentional and the tests are stale. 0.65 is still below
the 0.75/0.80 removal thresholds, so the stated intent of both tests — "a benign self-signed
root is not treated as a MitM/removal candidate" — remains satisfied. **ATT&CK/detection
impact:** none. Detection coverage for T1553.004 (Install Root Certificate) and T1587.002 /
T1588.004 (adversary code-signing certs) is unchanged; a benign root still logs at Tier2 and is
never removed.

### Alternative: fix the PRODUCT side (only if the design intent is "no All-Purpose penalty for a plain self-signed root")

If the team decides a bare self-signed root with no suspicion signals should score the pure base
0.40, gate the All-Purpose bonus so it does not fire on a long-lived self-signed root that
carries no other signal. Concretely, in `src/Sentinel.Core/Monitors/SystemIntegrityMonitors.cs`
around line 759:

```csharp
// Current:
if (isAllPurpose)
{
    confidence += 0.25;
    reasons.Add("Root cert has no EKU restriction / All-Purpose ...");
}

// Option: don't penalize All-Purpose on an otherwise-clean long-lived self-signed root
if (isAllPurpose && !looksLikeLongLivedRoot)
{
    confidence += 0.25;
    reasons.Add("Root cert has no EKU restriction / All-Purpose ...");
}
```

**Reasoning / tradeoff:** this makes a clean self-signed root score 0.40 again (both tests pass
as originally written). **ATT&CK/detection impact — this WEAKENS detection:** a real root CA
with no EKU constraint is maximally powerful (can sign both TLS and drivers), which is precisely
the T1553.004 + T1587.002 abuse surface the +0.25 was added to catch. Suppressing it for any
long-lived (≥5y) self-signed cert hands attackers a trivial evasion (issue a 10-year
self-signed root with no EKU). For a security product whose stated ethos is "never grant trust
on a signal an attacker controls" (`constraints.md`), this is the **worse** option. Only take it
if product requirements explicitly say a no-EKU self-signed root must not be scored.

### Note / assumption

`c3cd372` (input-integrity) is HEAD; it did not touch TLS code, matching the brief's premise
that these two failures are pre-existing. I did not modify any source. The `global.json` the
brief mentioned does not exist under `e:\Gorstak\Sentinel`; the test project targets
`net48-windows` and the standard `dotnet test` invocation builds and runs cleanly.
