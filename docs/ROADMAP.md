# Sentinel - Roadmap

**North star:** the best, most bulletproof userland protection an honest EDR can give on a
real Windows desktop people actually use.

This roadmap is deliberately grounded in Sentinel's own documented reality - the residual risks
in `THREAT_MODEL.md`, the known limitations marked in code, and the "intentionally out of scope"
list in `requirements.md`. It is not a wishlist of features that would break the project's
constraints. Anything here must still obey `docs/constraints.md` (userland only, no kernel
driver, Tier2 never acts, observe-until-chain, behavioral kill authority).

Because there is no fixed release schedule, this is organized by **theme and honesty**, not by
version numbers. Pick from the top of a theme when you want to move the needle.

---

## Guiding principles (do not drift from these)

- **Honest over "unhackable."** Every capability states what it is *not* a substitute for.
  Marketing and packs stay technical. Local admin / novel kernel implants can still win.
- **Userland only.** No kernel driver, no direct syscalls, no PPL. The moat is detecting the
  *entire chain* that leads to kernel compromise, not competing in ring 0.
- **Detect behavior, not identity.** Kill authority comes from what a process does, never from
  a name/path/hash.
- **Observe-first.** Weak single signals are LogOnly; only chain-confirmed terminals authorize
  destructive response.
- **Every gap is documented, not hidden.** If a defense is limited, say so in the threat model.

---

## Theme 1 - Close the documented residual-risk gaps

These come straight from `THREAT_MODEL.md` "Bypass Scenarios" where residual risk is MEDIUM or
higher. Each is about *narrowing the race*, not claiming to eliminate it.

| Priority | Gap (source) | Direction | Honest ceiling |
|----------|--------------|-----------|----------------|
| High | **Local admin can stop the service** (B1, residual HIGH) | Faster watchdog re-arm, richer SCM-tamper telemetry, off-host alert-before-suppression so the *evidence* survives even if the service dies | Cannot beat admin in userland; goal is durable evidence + fast detection, not invincibility |
| High | **BYOVD race** (B2, residual MEDIUM) | Tighten prerequisite detection (priv-esc -> cert plant -> .sys drop -> service create), expand LOLDrivers/WDBL blocklist refresh, shrink the 15s poll where cheap | Kernel driver already loaded still wins; win the race earlier, alert before suppression |
| Medium | **ETW blinding is post-hoc** (B3, residual MEDIUM) | Keep prologue-diff detection; add corroborating "telemetry went quiet" heuristics (events/sec floor already exists in EtwSessionGuard - extend to per-provider) | Cannot prevent in-process patch; detect-after-the-fact + correlate the silence |
| Medium | **Command-line-free tradecraft** (B6, residual MEDIUM) | Lean harder on ETW ThreatIntel + MemoryBehaviorAnalyzer so detection does not depend on cmdline exposure | Sophisticated in-memory-only tradecraft remains hard |
| Medium | **In-memory inject into a live game** (v2.2.5 note) | Explore safe, fail-closed ways to inspect game processes without tripping Denuvo (handle-safety-preserving telemetry) | Anti-cheat self-terminates on VM_READ; stays a residual gap unless a safe signal is found |
| Low | **Process hollowing without memory-type change** (EtwThreatIntelMonitor LOW-4) | Add on-disk vs in-memory `.text` section comparison for MEM_IMAGE regions of signed binaries | Expensive; scope to high-value/critical processes only |

---

## Theme 2 - Coverage breadth (generic-class, not per-CVE)

Sentinel's stated strategy (v2.2.4) is generic exploit-*shape* sensors so the next CVE sibling
doesn't need a new campaign pack. Keep extending shapes, not one-offs.

- New delivery vectors as they emerge (the MOTW script-dropper + WPAD/PAC work in v2.3.5 is the
  model: find the *class* of the vector, emit LogOnly observe fuel, let it feed existing
  composites).
- Keep CISA KEV matching current for this workstation's actual asset list.
- Add composite chains only where a real multi-signal terminal exists - avoid detector sprawl.

---

## Theme 3 - Correlation & explainability quality

The v2.0 WeightedCorrelationEngine + score cards + MITRE mapping is the foundation. Improving
*precision* here reduces false positives, which is what actually makes always-on response safe.

- Tune category weights and thresholds against real telemetry from `events.jsonl`.
- Grow EventGraph diversity/fan-out signals as corroboration (never as sole kill).
- Expand `AttackTechniques` MITRE coverage on detections that lack it.

---

## Theme 4 - Evidence durability & trust

"Bulletproof" for a high-profile target is as much about *surviving evidence* as prevention.

- Off-host / append-only evidence-pack backup so B1/B2 suppression can't erase the trail.
- Strengthen the dual audit trail (JSONL primary + Event Log critical) already in v1.9.5.
- Keep evidence packs honest and reportable-grade; never overclaim.

---

## Theme 5 - Reliability & performance hardening

Always-on protection is only bulletproof if it never falls over or bogs the machine down.

- Continue independent-monitor failure isolation and self-healing (MonitorRegistry).
- Watch detection/response latency percentiles (SentinelMetrics) and keep the telemetry queue
  bounded under flood.
- Reduce startup and steady-state cost so users never feel a reason to turn it off.

---

## Explicitly NOT on the roadmap (by design - see requirements.md NFR-7)

These are permanent non-goals. Do not add them; they'd break the project's identity.

- Kernel PPL / ELAM driver (userland is the whole point).
- Pre-kill offensive deception / attacker-hostile tactics (removed for AV compatibility).
- Direct law-enforcement API filing (no consumer EDR API exists).
- Chat/social moderation, offender identification, or offline-abuse detection (coercion defense
  is host-tool behavior only).
- Any "unhackable" marketing claim.

---

## How to use this roadmap

When you want to move forward but don't have a specific task in mind, pick the highest-priority
item from Theme 1 (that's where "bulletproof" actually improves), and ask to spin it into a
feature spec. The steering rules keep the work inside Sentinel's constraints, and the
post-task test hook verifies it before it's called done.
