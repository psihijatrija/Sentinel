# Git-push hang / network-egress-block architecture review

**Scope:** READ-ONLY architecture review. No code changed.
**Framing (per recalibration):** The reported "PowerShell `git push` hung indefinitely" happened ~3 Windows installs ago. It is **not** a reproduced incident against today's code and may already be fixed or in code that no longer exists. This report therefore answers the general architecture questions (#3/#4/#5): *in the current `src/` tree, can an outbound network-egress-block / `NetworkIsolate` response fire against a validly-signed trusted-publisher binary (e.g. `git-remote-https.exe`, signer "Johannes Schindelin") driven by a Tier2/observe-grade signal, and is there a signer-based exemption before such a response?*

---

## Summary answer

**A bare Tier2 / observe-grade network or exfil signal CANNOT drive an egress block today.** Every path that creates an outbound firewall BLOCK rule or isolates egress is gated behind `Tier == Tier1Behavioral` **and** `ar` (active-response + chain-authorized / MitM-exempt) in `AdvancedResponseEngine.HandleAsync`. Tier2 is demoted to `LogOnly` unconditionally. The two signals the brief worried about — `AppNetworkPolicyMonitor` ("Network Policy: Unusual Destination") and `DataExfiltrationMonitor` ("Traffic Anomaly: Outbound Volume Spike") — are authored **Tier2 + LogOnly**, are listed in `IsObserveOnlyUserActivityHeuristic`, and are in `PureUxObserveRuleFragments` so they can never seed or complete a chain. They are architecturally incapable of causing a block. **On that question, no fix is needed.**

**However, there is one real, current-code architectural gap for the broader "signed-publisher egress exemption" question:** there is **no signer/trusted-publisher check consulted before a `NetworkIsolate` (or ThreatIntel firewall) response**, analogous to the signed-file refusal that exists for quarantine. In the current `src/` tree a validly-signed binary is **not** exempt from egress blocking:

- `BeaconingDetector.DetermineBeaconResponse` (src/Sentinel.Core/BeaconingDetector.cs:333-347) **deliberately** keeps a validly-signed, Program-Files, high-trust binary (trustScore ≥ 5, Authenticode worth +3) on `NetworkIsolate` rather than exempting it — the comment cites SolarWinds-style supply-chain compromise. That is a defensible design choice, not a bug, but it means "signed by a trusted publisher" is explicitly **not** a get-out-of-egress-block card.
- The `QuarantineManager` `TrustedPublishers` set (with "Johannes Schindelin") that the brief refers to currently exists **only in the `.worktrees/aggressive-dll-sweep` branch**, not in `src/Sentinel.Core/QuarantineManager.cs`. Even there it only guards *quarantine*, never the network-isolate path.

Because `NetworkIsolate` requires a **chain-confirmed or kill-grade-terminal** signal to fire, and because a normal one-shot `git push` matches **none** of the kill-grade terminal families, the current code would not block a routine push from observe-grade noise. A block could only occur if git's connection genuinely tripped a Tier1 terminal (e.g. the push IP appearing in a threat-intel feed, or git being mis-fingerprinted as statistical C2 beaconing). The minimal, constraints-consistent improvement is a **shared trusted-publisher gate in front of the egress-block/isolate executor**, so a validly-signed trusted-publisher process is spared an IP block the same way it is spared quarantine — see Recommendations.

---

## Evidence

### 1. Every egress-block / isolate response is Tier1 + chain-gated

`AdvancedResponseEngine.HandleAsync` is the single response funnel.

- Global observe-until-chain gate (src/Sentinel.Core/AdvancedResponseEngine.cs, ~L430-470): when `ObserveUntilChain` is true (product default, and `constraints.md` says it is locked on), `chainAuthorized = ResponsePolicy.MayPerformDestructiveResponse(...)`. If not chain-authorized (and not DLL-/MitM-exempt), the detection is forced to `Tier2Indicator` + `LogOnly`.
- The `NetworkIsolate` branch (src/Sentinel.Core/AdvancedResponseEngine.cs:571) only sets `shouldIsolateNetwork = true` when `effectiveResponse == NetworkIsolate && effectiveTier == Tier1Behavioral && ar`. `ar` itself requires `ActiveResponse && (!ObserveUntilChain || chainAuthorized || dllExempt || mitmExempt)`.
- `ResponsePolicy.DemoteToObserve` (src/Sentinel.Core/ResponsePolicy.cs:443-448) lowers any `AuthorizedResponse >= NetworkIsolate` to `LogOnly` whenever a signal is demoted to Tier2.
- `constraints.md`: *"Tier2 can never trigger action — enforced unconditionally in `AdvancedResponseEngine.HandleAsync`."*

**Net:** no Tier2 signal can reach `shouldIsolateNetwork`.

### 2. The IP-block executor and its guardrails

`IsolateNetworkTarget` (src/Sentinel.Core/AdvancedResponseEngine.NetworkActions.cs:62-116) adds **both outbound and inbound** Windows-Firewall BLOCK rules for the `TargetIP` via `HNetCfg.FwPolicy2`. A silent outbound BLOCK on an in-flight HTTPS socket is exactly the shape that would make a push hang rather than error — so the executor *could* produce the reported symptom **if** it were ever reached for git's destination IP.

Pre-isolate collateral guards (src/Sentinel.Core/AdvancedResponseEngine.cs, `shouldIsolateNetwork` branch): the target IP is skipped if it is loopback / `0.0.0.0` / broadcast / RFC1918-private (`SecurityValidation.IsPrivateIpAddress`) / multicast / or a known public resolver-or-CDN (`IsLikelyCdnOrPublicResolver`, which only covers Cloudflare 1.1.1/1.0.0, Google 8.8.8/8.8.4, Quad9 9.9.9). **GitHub / git CDN egress IPs are not covered by any of these guards.** There is **no signer-identity guard here at all.**

### 3. The two "scary" monitors are observe-only by construction

- `AppNetworkPolicyMonitor.EmitPolicyAlert` (src/Sentinel.Core/AppNetworkPolicyMonitor.cs:~276-300): "Network Policy: Unusual Destination", `Tier = Tier2Indicator`, confidence ~0.55 (halved further for signed binaries via `SignerTrustService.AdjustConfidence`). It carries `RemoteIp`/`Subnet` metadata, **not** `TargetIP`, so even if it were promoted it would not feed the isolate executor's `TargetIP` lookup. It is listed in `IsObserveOnlyUserActivityHeuristic` (AdvancedResponseEngine.cs) and in `PureUxObserveRuleFragments` (ResponsePolicy.cs), so `IsWeakObserveSeed`/`IsPureUxObserveNoise` exclude it from both the chain buffer and composites. Its `git`/`powershell` attribution risk is real (the `NetworkAllowlist` contains neither `git` nor `powershell`), but the signal is inert at Tier2.
- `DataExfiltrationMonitor` (src/Sentinel.Core/DataExfiltrationMonitor.cs): a large push emits "Traffic Anomaly: Outbound Volume Spike" at `Tier2Indicator`, confidence 0.55, `ProcessId = 0`, `AuthorizedResponse = LogOnly`, flagged `WeakObserveSeed=true`. The rule name deliberately avoids "Exfil*" so it cannot complete an Exfil chain leg, and it is in `PureUxObserveRuleFragments`. It publishes only a soft `ExfiltrationSpikeSignal` for enrichment. **A big push cannot drive a block.**

**On the brief's specific worries (2a large-push volume spike, 2b LOLBin-with-network-child, 2c libexec-path helpers): none can author a block today** — they are all Tier2/observe or simply not emitted as terminal.

### 4. Can a correlation reach a chain-confirmed isolate? (Question #3)

`ResponsePolicy.RegisterAndEvaluateChain` (ResponsePolicy.cs:~730-860) requires either a `NukeComposite`, an `IsAttackClassTerminal` single hit at ≥ `MinTier1Confidence` (0.85), or ≥2 distinct rules within the window **with at least one kill-grade terminal leg at ≥0.85**. The weak network/exfil seeds above are explicitly excluded from the buffer (`IsWeakObserveSeed`). A normal `git push`:
- is not a `NukeComposite`,
- does not match any `IsAttackClassTerminal` rule name,
- produces only Tier2 observe seeds that cannot be terminal legs.

So **a routine push cannot assemble a chain-confirmed nuke/isolate.** The only Tier1 single-signal paths that *author* `NetworkIsolate` are genuine terminal detectors — `ThreatIntelFeedBlocker` (feed-IP match, C2Beacon, 0.92), `BeaconingDetector` (confirmed statistical beaconing), `DnsQueryMonitor`/`RouteTableMonitor`/`NetworkIntegrityMonitors`/`CastDeviceGuard`/`BrowserC2Guard`/`AntiTaoMonitors`/`NetworkShareMonitor`. A one-shot push does not match the statistical-beacon or MitM/route/DNS patterns; the only realistic trigger is the push IP being present in a public threat-intel feed.

### 5. Is a signed/trusted-publisher binary exempt from egress block anywhere? (Question #3/#4 — the gap)

**No.** Searching the whole tree, the only trusted-publisher allowlist (`TrustedPublishers` incl. "Johannes Schindelin") lives in `.worktrees/aggressive-dll-sweep/src/Sentinel.Core/QuarantineManager.cs` and gates **quarantine only** (returns null to refuse quarantining a validly-signed trusted-publisher file). It is **not** present in `src/Sentinel.Core/QuarantineManager.cs` at all (grep: no matches), and it is **never** consulted on the network-isolate path.

`SignerTrustService` (src/Sentinel.Core/SignerTrustService.cs) is explicit that *"being signed does NOT grant trust or exemption"* — it only lowers confidence (`SignedConfidenceMultiplier = 0.5`). And `BeaconingDetector` (BeaconingDetector.cs:333-347) **intentionally** keeps even a validly-signed, Program-Files, high-trust binary on `NetworkIsolate` to defend supply-chain compromise. So the architecture's current answer is: *a valid Authenticode signature from a trusted publisher does not exempt a process from an egress block.*

### 6. `ThreatIntelFeedBlocker` — the most plausible real block path

src/Sentinel.Core/ThreatIntelFeedBlocker.cs:
- Default mode is OBSERVE-ONLY; it does not pre-install feed rules unless `ThreatIntelProactiveFirewall && ActiveResponse`.
- `CheckActiveConnections` (L480-525) emits `Tier1Behavioral`, confidence **0.92**, `Family = C2Beacon`, `AuthorizedResponse = NetworkIsolate` when `ActiveResponse` is on and an established connection's remote IP matches a feed entry (Spamhaus DROP / Feodo / EmergingThreats).
- Because C2Beacon is a kill-grade terminal family, this single Tier1 signal can author an isolate on the matched IP via the executor in §2.
- `GetEstablishedConnections` returns PID 0 (no PID from `IPGlobalProperties`), so attribution is IP-only, not to git — but the IP block is by `TargetIP` regardless of process, so a signed git helper's destination would still be blocked if that IP were ever (falsely) feed-listed.
- There is **no signer check** before this isolate.

### 7. `RuntimeBlocklistService` / `HostsFileGuard` — not a detection auto-block

src/Sentinel.Core/RuntimeBlocklistService.cs is a runtime-mutable desired-set of domain/IP blocks enforced by `HostsFileGuard`. Its only wired caller is DI registration (Sentinel.Service/Program.cs:382) plus the first-run `forum.hr` seed; **no detection/response code calls `BlockIp`/`BlockDomain` automatically.** `NormalizeIp` already refuses loopback/broadcast/Any. This is not an attacker- or FP-driven egress-block path for git.

---

## Conclusions

1. **The observe-grade signals cannot block.** `AppNetworkPolicyMonitor` and `DataExfiltrationMonitor` are Tier2/observe-only and excluded from chains/composites. Per `constraints.md` Tier2 can never act. For the specific "can a bare network/exfil Tier2 signal drive a block" question: **no, and no fix is needed.**
2. **A routine `git push` cannot assemble a chain-confirmed isolate** — it matches no kill-grade terminal family and seeds only weak observe signals.
3. **There is a genuine current-code architecture gap for the general question:** no trusted-publisher / signer gate runs before `NetworkIsolate` (or the ThreatIntel firewall writes). A validly-signed trusted-publisher binary is *not* exempt from egress blocking today; `BeaconingDetector` even keeps signed binaries on `NetworkIsolate` by design. The only realistic way a signed git helper's push would be blocked is a Tier1 terminal detector firing on git's destination IP (most plausibly a false `ThreatIntelFeedBlocker` feed-IP match).
4. The egress guardrails that *do* exist (`IsLikelyCdnOrPublicResolver`, private/loopback/multicast skips) are IP-shape heuristics only and do not cover GitHub/git CDN ranges.

---

## Recommendations (minimal, constraints-consistent — implement nothing here)

1. **Add a shared trusted-publisher egress gate.** Promote the `TrustedPublishers` set (currently only in the `aggressive-dll-sweep` worktree's `QuarantineManager`) into a single shared helper (e.g. `TrustedPublisherPolicy.IsTrustedPublisherProcess(pid)` / `...File(path)`), built on `SecurityValidation.VerifyAuthenticodeSignature` + `TryGetAuthenticodePublisher`, and consult it **before** `shouldIsolateNetwork` fires in `AdvancedResponseEngine.HandleAsync`. If the response is a *pure* egress action (`NetworkIsolate`) and the offending process (or the resolved owner of `TargetIP`) is a validly-signed trusted-publisher binary, demote to `LogOnly`. This mirrors the existing `QuarantineManager` signed-file refusal and satisfies `constraints.md` ("prefer signer identity over path/name", "no attacker-controllable trust" — a forged publisher subject on a *validly-signed* PE is not achievable).
   - **Important scope limit (keep it honest, keep supply-chain defense):** Do **not** let this blanket-exempt `BeaconingDetector`'s confirmed-statistical-beaconing case — that path intentionally blocks even signed Program-Files binaries (SolarWinds rationale). The exemption should apply to *weak/benign* egress triggers (e.g. a lone threat-intel feed-IP match on an outbound connection owned by a signed trusted-publisher process), not to a multi-factor confirmed C2 beacon. Encode this as "trusted-publisher spares egress block **unless** the detection is a confirmed statistical/multi-signal beacon".
2. **Attribution hardening (optional).** `ThreatIntelFeedBlocker.GetEstablishedConnections` returns PID 0, so the isolate cannot even consult the owning process's signer. If recommendation #1 is pursued for this path, switch to the PID-aware `GetExtendedTcpTable` approach already used by `AppNetworkPolicyMonitor` so the signer of the connection owner can be checked before blocking its destination IP.
3. **No action required** on `AppNetworkPolicyMonitor` / `DataExfiltrationMonitor` tiers — they already honor Tier2/observe-only per constraints. (Minor nicety: neither `git`/`git-remote-https` nor `powershell` is in `NetworkAllowlist`, so they generate observe noise during pushes; adding signed-`git` as an allowlist entry would reduce log noise but is not a correctness fix.)

---

*Content from source files was summarized/paraphrased with file:symbol citations; no third-party content reproduced.*
