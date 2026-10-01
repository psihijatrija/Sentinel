---
inclusion: always
---

# Sentinel - Product Overview

Sentinel is a userland-only defensive IDS/EDR for monitoring Windows systems.
Focus: transparency, safety, real-world threat detection, and blue-team education.

- **Platform:** .NET Framework 4.8, Windows only (`net48-windows`), win-x64.
- **Two-process model:** `Sentinel.Service.exe` (Session 0, SYSTEM - the authority for
  detection/response) and `Sentinel.Agent.exe` (user session - tray, hooks, UI).
- **Designed for:** personal system visibility, blue-team education/research, real-world
  detection of malware, ransomware, C2 beacons, and post-exploitation activity.
- **Not designed for:** offensive/red-team tooling, evasion/stealth monitoring, or
  managed enterprise fleet deployment (no kernel/PPL component).

## Authoritative requirements

The full, canonical functional and non-functional requirements live in `docs/requirements.md`
and are the source of truth. When implementing or reviewing changes, honor them exactly
(detection tiers, response contracts, logging, explainability, plugin/IPC/ops-metrics
surfaces, posture rules, and version history).

#[[file:../../docs/requirements.md]]
