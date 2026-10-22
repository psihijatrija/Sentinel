# Desktop privacy and control review — 2026-10-21

Scope: source at `38c647c` (3.3.7), plus the uncommitted NanoAV integration. This is a source review, not observation of an installed Windows system. It neither establishes remote surveillance nor proves the behavior of installed binaries.

## What the source establishes

| Mechanism | Evidence | Privacy/control implication |
| --- | --- | --- |
| Keyboard/mouse hooks and clipboard listener | Agent registers `InputIntegrityGuard`; it installs low-level hooks and a clipboard-format listener | Inspected callbacks count injected-event flags/timestamps and observe clipboard changes; they do not record typed text or read clipboard contents. These are still sensitive desktop mechanisms that need clear user control |
| Cursor, focus, overlay and brightness observations | Agent registers `NeuroBehaviorVisualMonitor` and `ClickjackingGuard`; they inspect desktop/window state, cursor coordinates and brightness | This is desktop activity monitoring, distinct from process/file/network telemetry, and needs explicit disclosure and control |
| Camera/microphone usage metadata | Agent registers usage/session monitors; Full Scan adds `SecurityAuditService` and reads ConsentStore timestamps from loaded user hives | Includes application paths and usage times, not evidence that Sentinel recorded microphone or camera media |
| Audio-loopback capture implementation | `AcousticThreatMonitor` contains `WasapiLoopbackCapture`/`StartRecording` | No registration/reference outside that class was found in current source. Its presence does not establish that capture is active; its health-effect claims are not validated by this review |
| Local audit/evidence | Scan/audit and incident report code includes account names, IPs, paths, commands and machine/user identifiers in relevant outputs | These can be sensitive. Local storage does not remove privacy, retention or export-disclosure obligations |
| Persistence and host changes | Installer sets up Sentinel and SentinelGuard services plus Agent autorun. Service startup invokes `HardeningModule.ApplyOrFail` | Watchdog restart and unconditional hardening reduce user control unless clearly disclosed and reversible |
| Sentinel outbound behavior | Inspected reputation facade returns Unknown; inspected reporting paths/documentation describe removed transport; dashboard uses loopback | No external upload path was identified in the reviewed active paths. This is not a packet capture or proof that every shipped component makes no connection |
| Independent NanoAV | Supplied code includes online hash queries, COM/Run-key installation and independent kill/quarantine/firewall paths | This deliberately changes the offline product boundary if installed. NanoAV is not being passed through Sentinel's response policy; the user's requested coexistence-only changes do not resolve its upstream runtime defects |

## Current disposition

3.3.8 retains Sentinel's existing desktop-monitor behavior. No specific removal or consent-control change is included in this release. The replacement NanoAV engine was discarded; the integration preserves the supplied source with coexistence-only edits. No telemetry was collected from an installed Windows machine for this review, and no installed settings were changed.

Possible product changes require an explicit scope choice: remove automatic desktop/activity monitoring while retaining core protection; retain the features with clear controls/disclosure; or finish documentation only.

Regardless of the choice, evidence required before stronger claims includes reviewing the exact installed binary hashes, native Windows runtime behavior, autoruns/services, controlled network captures, audit retention and the actual UI/installer disclosures. Source inspection alone cannot resolve those questions.
