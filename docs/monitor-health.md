# Monitor collection and task health

A running task is not proof of telemetry delivery. The health endpoint retains the full registered
roster and reports task state, collection progress, unverified collection, and per-sensor errors.
The dashboard's sensor-health details expose these separately. Supervisor heartbeats cannot clear
a collection error. Watchdog scheduling grace is bounded and never rewrites observed heartbeats.

## Findings from the supplied 20 October 2026 snapshot

The 13:18 UTC metrics identify 133 Running and three Stopped entries:

- `FileVerdictScanner`: watchers were created, then `ExecuteAsync` returned while its initial walk
  ran without supervision. Returning did not prove the callbacks had stopped. Its execution now
  remains alive until shutdown, observes walk failures, and faults on watcher errors so its group
  can restart subscriptions and reconcile through the initial walk.
- `ThreatFoxFeedService`: an offline bundle initializer, not a live feed. Its completed state records
  the loaded entry count; an empty bundle supplies no IOC matches. Online transport remains removed.
- `ThreatIntelFeedBlocker`: a one-time cleanup of retired online-feed firewall rules. Completed does
  not mean ongoing feed coverage. No online feed transport is restored.

The same metrics show the kernel-process and DNS providers accepted, and a live ETW consumer.
They also show Win32 error 5 for the protected Threat-Intelligence provider. Registry-key existence
cannot establish provider access. Sentinel cannot promise access to a protected provider by
running as SYSTEM. Missing Windows components, security policy, and provider restrictions remain
possible causes of telemetry loss; checking startup messages alone cannot distinguish them.

The historical crash file records a default Windows Event Log logging-provider exception on
19 October. The current Program already clears that provider; this patch does not claim to fix an
old crash anew. The supplied snapshot also reports native ETW event loss; compare counter deltas
on the target machine rather than interpreting a running task as complete delivery.

## Collection repairs

- DNS uses the existing real-time session when its DNS provider and consumer are active, with
  structured event-log reads as fallback. The real-time dispatcher previously listened for IDs
  1001/1002 (server configuration); it now uses the provider's query events 3006/3008. Query starts
  enter a bounded queue; overflow remains visible rather than silently losing coverage.
- Event-log DNS reads named `QueryName` XML data instead of localized `FormatDescription` text. It counts
  query-start events once, maintains a record cursor, handles record-ID resets, and bounds each
  poll. It starts at the current log end to avoid replaying history as fresh traffic. Empty reads
  prove only that a read succeeded. `SensorProgress.DnsQueryMonitor.Observations` counts parsed
  queries; initialization/read errors remain visible. There is no DNS-cache fallback in this class.
  This monitor's DNS detections remain unattributed (PID zero), preserving its existing response-authorization boundary.
- The local injection scanner is registered in the `IMonitor` collection and defaults on. It never
  used the legacy feed URL. Its worker reports scan-cycle progress; an empty suspect board does
  not prove protected TI events exist. `EtwSessionGuard` still reports denied providers.
- The process monitor checks the particular provider and consumer, not merely session existence.
  When unavailable it re-enables WMI/snapshots. WMI-free snapshot observations now reach detection,
  but reduced short-lived-process and command-line coverage remains an explicit health error.
  WMI/snapshots deliberately paused while process ETW works are reported as Standby, not Running.
- Declared startup tasks become Completed. Other successful worker exits become Unavailable and
  remain unhealthy, without indefinitely restarting unsupported Windows facilities.

## Verification on Windows

First build and run the native suite on Windows without invoking release scripts:

```powershell
dotnet build Sentinel.sln -c Debug -warnaserror
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Debug --no-build
```

After the changed binaries are deployed through the normal service-install procedure, capture:

```powershell
.\tools\Test-SentinelSensorHealth.ps1 -Probe | Set-Content -Encoding UTF8 .\sensor-health.json
```

The diagnostic script changes no channel configuration or security policy. Its optional probe
issues one unique DNS query below example.com; NXDOMAIN is expected. It reports whether Windows
recorded that exact query, the before/after parsed-query counts, metrics freshness, task errors,
provider statuses, and event-loss deltas. A counter increase alone does not identify the exact
probe, so inspect it alongside the Windows event match and sensor error state. Old binaries
lack the new observation counters; a matching product version alone cannot identify this patch.

The full .NET Framework suite and native collection require Windows. Portable regression tests
can validate parsing, worker lifetime, health transitions, and bounded watchdog grace, but cannot
prove that an altered Windows installation retains usable telemetry channels or protected providers.

Provider schema reference checked during this repair:
https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-DNS-Client.xml
The target machine's provider manifest and live probes remain authoritative for its Windows build.
