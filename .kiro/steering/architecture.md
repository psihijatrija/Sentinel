---
inclusion: auto
name: Sentinel Architecture
description: Sentinel's pipeline architecture, monitor groups, engines, orchestration, and response flow. Load this when adding or modifying monitors, engines, correlation, or response paths, or when a request involves how components fit together.
---

# Sentinel - Architecture

Sentinel follows a clean pipeline with strict separation of concerns:

```
Monitors -> TelemetryFusionEngine -> DetectionEngine -> AdvancedResponseEngine -> JsonlEventLogger
```

- The **fusion layer is passive** - it enriches, builds per-process event chains, and maintains
  the `EventGraph`; it never blocks, kills, or modifies telemetry.
- All components are wired via `Microsoft.Extensions.DependencyInjection`.
- Monitors are registered via `MonitorGroup` (staggered startup, restart policy, health checks) -
  never a flat `AddHostedService`. Each monitor class lives in its group file under `Monitors/`.
- Runtime monitor types live in `Sentinel.Core` (the `Monitors/` folder is layout only).
- The **Service is the authority**; the Agent provides user-session visibility/UI and must never
  expose a way to disable ActiveResponse.

## Authoritative design

The full component inventory (all monitor groups, engines, orchestration, and infrastructure) and
the detailed data flow live in `docs/design.md` and are the source of truth. Consult it before
adding or modifying monitors, engines, or response paths so new work fits the existing layering.

#[[file:../../docs/design.md]]
