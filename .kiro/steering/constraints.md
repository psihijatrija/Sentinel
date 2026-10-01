---
inclusion: always
---

# Sentinel - Hard Constraints (Never Violate)

These are non-negotiable rules for the Sentinel codebase. They take precedence over
convenience or brevity when writing or reviewing code. A change that violates any of these
must not be made.

## Highest-priority invariants

- **No kernel drivers, no direct syscalls, no persistence tricks, no self-hiding.** Userland
  only; must remain visible in process list, Task Manager, and event logs.
- **Tier2 can NEVER trigger a response action** - enforced unconditionally in
  `AdvancedResponseEngine.HandleAsync`. No config override, no exceptions.
- **Observe-until-chain.** Kill / quarantine / isolate / host mutation only after multi-signal
  or composite proof of a kill-grade terminal (token theft, credential dump, reverse shell,
  C2 beaconing), or an `IsAttackClassTerminal` solo-confirm at the documented threshold.
- **Tier1 = kill-grade only.** High-confidence terminal classes only; critical score alone
  must not promote noise to Tier1.
- **Behavioral signals only for kill authority** - detect what a process DOES, not what it IS
  (no filename/path/hash as a primary kill).
- **Adversarial mindset: this project exists to defeat attackers, so never grant trust on a
  signal an attacker controls.** Every "allow" path must assume the attacker can name a file
  anything, drop it in any writable location, and pick any folder name. A filename or a folder
  name alone must NEVER self-authorize a module - filename/prefix trust (GPU ICDs, servicing
  names, vendor folders) must always be combined with a non-attacker-controllable anchor: a
  trusted-root load location (OS keep-tree / Program Files) that is not user-writable, a valid
  Authenticode signature, and/or a proven legitimate loading host. Any default-writable
  directory - even inside the Windows tree (`Tasks`, `tracing`, spool color, PLA, `.nuget`
  cache under the user profile) - is a drop, not a trusted tree. When adding a new allow rule,
  first ask "how does an attacker abuse this?" and close that path before merging. Fail closed.
- **No string-built JSON** (use `System.Text.Json`), **no static mutable state**,
  **no `Thread.Sleep` without cancellation**, **no string interpolation into shell commands**.
- **DI required** for all services; **CancellationToken** threaded through every async method;
  **no silent exception swallowing**; **graceful degradation** (a failing monitor must not
  crash the host).

## Full canonical constraints

The complete constraint set - including DLL-unload identity rules, always-on hardening,
transparency requirements, code-quality/testing constraints, and operational limits - lives in
`docs/constraints.md` and is authoritative. Read and honor it in full.

#[[file:../../docs/constraints.md]]
