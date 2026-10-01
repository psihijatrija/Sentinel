# Sentinel - Council of Elders Architecture

**Status:** Historical architecture rationale. **Runtime inventory and versions are authoritative in `design.md` (v2.2.9).** This document explains the President/Council mental model; do not treat monitor tables here as the live registration list.

**Last updated note:** v2.5.6 - hardening is always-on; module identity unload (`ModuleIdentity` + `DllUnloadEngine`) is the live PE-map backbone; generic CVE-class monitors live in `design.md`. `ALLOCVM_REMOTE` added to `IsAttackClassTerminal` solo-confirm path. EDR-killer process names are **not** President's Law (LogOnly observe fuel). All monitor classes are `namespace Sentinel.Core`.

---

## The model in one paragraph

Sentinel is **GIDR**, with a council. GIDR is the President: it watches what
processes **do** at runtime, and when behavior crosses the line, it kills the
chain. Final word. The Council " all advisory detection modules built into
Sentinel's C# codebase " advises with signals, weight, and context. The Council
**never** authorizes a kill on its own. The Council **never** vetoes the
President. Two specific signals carry significant weight: the 3-API ADS file
verdict, and any detector targeting the user directly (audio/webcam hijack,
keylogging, cursor takeover, fake UAC, etc.).

**v0.9.0 change:** All council members are now built into the C# binary. No
external PowerShell scripts required. The `ConsultantSignalIngestor` remains
for optional external integration but is not needed for core functionality.

```
        """"""""""""""""""""""""""""""""""""""""""""""""""
        "'            PRESIDENT " GIDR core               "'
        "'     runtime behavioral detection (closed list) "'
        "'     final word on kill / quarantine / chain    "'
        """""""""""""""""""""""""""""""""""""""""""""""""""
                 consults "' before non-catastrophic kills
                          -1/4
        """"""""""""""""""""""""""""""""""""""""""""""""""
        "'              COUNCIL OF ELDERS                 "'
        "'                                                "'
        "'  """""""""""""""""  """""""""""""""""""""""""  "'
        "'  "' ADS verdict   "'  "' Attack-on-user (high  "'  "'
        "'  "' (3 APIs HMAC) "'  "' weight): audio/webcam "'  "'
        "'  "'  significant  "'  "' /keylog/UAC/cursor    "'  "'
        "'  """"""""""""""""""  """"""""""""""""""""""""""  "'
        "'  """"""""""""""""""""""""""""""""""""""""""""" "'
        "'  "' Consultants (PS / C# / YARA / IoCs)       "' "'
        "'  "' contribute confidence, never decide       "' "'
        "'  """""""""""""""""""""""""""""""""""""""""""""" "'
        """""""""""""""""""""""""""""""""""""""""""""""""""
```

---

## The President's law (kill triggers " closed list)

GIDR's behavioral set, ported as-is. **Any one of these alone ' kill chain.**
Nothing else kills.

| Behavior | Detector |
|----------|----------|
| Credential dumping (LSASS / SAM / known dumpers) | `CredentialDumpDetection` |
| Ransomware mass-write + shadow copy delete | `RansomwareDetection` |
| Reverse shell / C2 callback | `NetworkMonitor` PID-correlated |
| C2 beaconing (statistical) | `NetworkMonitor` |
| Process injection / hollowing | `MemoryExecutionDetection` |
| Fileless / in-memory execution | `MemoryExecutionDetection` |
| Audio routed to mic (hypno / impersonation) | `AudioHijackDetection` |
| Webcam hijack by unverified parent | `WebcamHijackDetection` (new " mirror) |
| ETW / AMSI tampering | `EtwTampering` checks |
| Autonomous malware phoning home from temp/appdata | `NetworkMonitor` + path heuristic |
| DLL hijacking with module integrity mismatch | `ModuleValidationDetection` |
| DLL injection detected + active unload response | `BrowserDllMonitor` / `DiskWideDllScanner` + `DllUnloadEngine` |
| Lateral movement (PsExec / WMI exec / WinRM unexpected) | `ProcessMonitor` + `NetworkMonitor` |
| Honeypot decoy access | `HoneypotMonitor` |
| ADS verdict = `unsafe` from 3-API consensus | `VerdictGateRule` (E1) |
| Sentinel self-protection tampering | `SelfProtection` |
| WFP filter blocking Sentinel's network traffic | `WfpIntegrityMonitor` |
| BYOVD vulnerable driver loaded (hash/name match) | `DriverLoadMonitor` |
| Network silencing of Sentinel (EDRSilencer) | `ConnectivityCanaryMonitor` |

**Adding to this list requires explicit user sign-off and a doc update.** This
is the most dangerous edit possible to Sentinel.

---

## What the Council can and cannot do

### The Council CAN
- Emit detection signals into `DetectionEngine` as Tier2 (default) or Tier1
  (only if origin is in the President's closed list)
- Contribute confidence weight to `ScoringEngine` / `AkinatorEngine`
- Feed `BehavioralCorrelationEngine` so multiple consultant signals on one
  PID/file within 120 s can produce a v2.0 composite (which **is** kill-authorized)
- Apply hardening / blocklists at install time (`Registry`, `IPSecPolicy`,
  `PiHole`, `DNSDotDoH`, `ASR`, `Hardening`)

### The Council CANNOT
- Issue `KillProcess` directly
- Suppress a President's kill (no allowlists, no exemptions, no veto)
- Promote its own signal to a President's-law origin without a doc update

### Two privileged Councilors (significant weight)

**1. ADS Verdict (the 3-API consultant, HMAC-signed on disk)**
- `unsafe` from CIRCL / Cymru / MalwareBazaar consensus ' behaves as a
  President's-law signal (kills on exec). This is the only Councilor whose
  signal alone authorizes a kill.
- `safe` from all three ' reduces correlation weight on demoted Tier1 signals
  for that PID. Does **not** suppress President's-law kills (a signed binary
  doing ransomware still dies).
- `unknown` / API outage ' no effect, never implicit `safe`.

**2. Attack-on-user detectors (weight -2 in scoring & correlation)**
The following Councilors get doubled weight because their false-positive risk
is low and their target (the user) is high-value:

- `AudioHijackDetection` (already President's-law)
- `WebcamHijackDetection` (already President's-law)
- `KeyScrambler` events (keylogger attempted / scrambling triggered)
- `PhantomKeystrokeGuard` (injected keystrokes blocked)
- `CursorTakeoverDetection`
- `FakeUacDetection`
- `LNKProtection` (malicious LNK aimed at user)
- `CookieMonitor` (session theft attempt)
- `NeuroBehaviorMonitor` anomaly score
- `RansomwareScarewareDetection` scareware patterns
- `Guard` (unsigned DLL detected " user data at risk)
- `Retaliate` (browser phoning home " user data exfiltration)

Two of these Councilors weighted-correlating on one PID within 30 s '
Composite-grade detection ' kill via the v2.0 composite path.

---

## Council roster (complete inventory " verified May 2026)

### Already integrated (EDR core " in-process C#)
| Project | Artifacts | Role |
|---------|-----------|------|
| `Antivirus` | 1 .ps1 | 3-API hash reputation (' `HashReputationService`) |
| `EDR` | 5 .ps1 + JSON | IOC tables, scripted detections |
| `GEdr` | 32 .cs + 18 .yar | Detection rule library, YARA signatures |
| `GIDR` | 28 .cs + 18 .yar | Reference architecture, ChainTracer, YARA |
| `LocalEDR` | 14 .cs | Additional detection rules |

### v2.0.0 " DLL Analysis & Active Response (ported from Antivirus.ps1)
| Component | Role |
|-----------|------|
| `DllUnloadEngine` | Active response: unloads malicious DLLs via CreateRemoteThread+FreeLibrary. Rate-limited (10/min), never touches system-critical processes. |
| `UacBypassSurfaceMonitor` | Proactive scan: COM AutoElevation vectors, manifest autoElevate binaries, copy-drop vulnerabilities. Scan interval: 15 min. |
| `DllEntropyAnalyzer` | Shannon entropy analysis on DLLs in high-risk paths + loaded modules. Detects packed/encrypted payloads (threshold 7.2) and random hex-named DLLs. |
| `DllLoadFailureMonitor` | Event Log monitoring: System Event ID 7 (DLL load failures), SideBySide manifest errors. Indicators of failed hijacking attempts. |
| `BrowserDllMonitor` | ELF Catcher: browser-specific DLL injection detection. Scans chrome/edge/firefox/brave/opera for injected modules. Active unload for ELF-pattern DLLs. |
| `DiskWideDllScanner` | Disk-wide scan: all drives for unsigned/suspicious DLLs not yet loaded. Feeds HashReputationService for live threat intel. Active unload on IoC match. |

### Detection consultants (PowerShell ' JSONL drop)
Each drops `%ProgramData%\Sentinel\consultants\<name>.jsonl`, ingested by
`ConsultantSignalIngestor` (new component). All emit **Tier2 only** unless
correlated via `BehavioralCorrelationEngine`.

| Consultant | Signal | Weight |
|-----------|--------|--------|
| `DragonBreathHunter` | Campaign IOC hits (RONINGLOADER, Gh0st RAT, NSIS trojans, rogue DLLs, C2 ports, persistence) | Normal |
| `NeuroBehaviorMonitor` | Focus abuse, flash stimulus, topmost abuse, cursor jitter, color distortion/inversion | **-2** (attack-on-user) |
| `RansomwareScarewareDetection` | Window titles with 2+ scareware keywords (encrypted, bitcoin, ransom, etc.) | **-2** |
| `FakeUacDetection` | Non-trusted process with UAC/system dialog window title | **-2** |
| `CursorTakeoverDetection` | Low-variance non-zero cursor velocity (automated movement) | **-2** |
| `CookieMonitor` | Chrome Cookies DB hash change ' session theft | **-2** |
| `LNKProtection` | UNC-path .lnk files on Desktop/Start Menu/Taskbar | **-2** |
| `Guard` | Unsigned DLL detected in Program Files/AppData | Normal |
| `Retaliate` | Browser connection to non-standard port without recent navigation | Normal |
| `GShield` | Memory scan (shellcode/injection APIs), browser unsigned module unload, deep file scan (entropy/packer/shellcode IOCs), rootkit HTTP-active unsigned process | Normal |
| `KeyScrambler` | Keylogger attempted / scrambling triggered (event consumer only) | **-2** |

### Install-time hardening Councilors (apply config, no runtime kill output)
These run once at Sentinel install or on-demand. They produce no runtime
detection events but Sentinel monitors for regression of their settings.

| Consultant | Artifacts | What it hardens |
|-----------|-----------|-----------------|
| `GodsProtection` | 1 .ps1 (1380 lines) | secedit policy, 30+ services disabled, firewall lockdown, certificate cleanup, bowser.sys removal, watchdog with auto-revert |
| `GSecurity` | GSecurity.bat + 9 .reg + 5 .ps1 | PS1/REG launcher, binary permissions (consent.exe, winmm.dll, WMI/dllhost/conhost), UAC, 20+ remote services disabled, DEP AlwaysOn |
| `Hardening` | Hardening.cmd + 3 .ps1 + 1 .reg | SMBv1 disable, NTLM hardening, firewall (block SMB/RDP/WinRM), services, account lockout, UAC, autorun/USB disable, Office macros, Defender CFA/ASR |
| `Consent` | Consent.cmd | UAC consent.exe ACL hardening (Console Logon only) |
| `Creds` | 1 .ps1 | LSASS PPL enable, credential caching disable, cached creds clear, auditing enable |
| `GRules` | 1 .ps1 (740 lines) | YARA/Sigma/Snort rule download + apply, ASR rules |
| `CVE-MitigationPatcher` | 1 .ps1 (486 lines) | CISA KEV catalog fetch, scriptable CVE mitigations |
| `Registry` | 26 .reg files | Immunity (P3P blocklist, 18 MB), Firewall, Privacy (MRU cleanup), Services (SvcHostSplit), Restrictions (SRP), GShield (disallowed certs), IPSecPolicy, ComputerPolicy, UserPolicy, Games, Browsers, etc. |
| `PiHole` | 3 .ps1 + 2 .reg | DNS-level blocking + blocklists |
| `ASR` | 1 .ps1 | Attack Surface Reduction rules |
| `IPBlock` | 1 .ps1 | Malicious IP blocklists |
| `IPSecPolicy` | 1 .ps1 | IPSec-based blocking |
| `DNSDotDoH` | 1 .ps1 | DNS-over-HTTPS/DoT enforcement |
| `GShield` | 1 .ps1 (994 lines) | Also does install-time: password rotator, self-protection |
| `GS` | Setup.bat + GSecurity.inf | LGPO security template import |
| `Troll/Unbridge` | Unbridge.cmd | Network registry ACL hardening, bridge removal |
| `MiniFilterDrivers` | MiniFilterDrivers.cmd | Removes bfs.sys, unionfs.sys (kernel drivers " Sentinel is userland but this is safe install-time cleanup) |
| `Pac` | 1 .reg | Proxy auto-config |

### Out of scope (not Councilors)
**Offensive/evasion:** `Unhooker` (AMSI/ETW/Defender patching " would be killed by Sentinel's own ETW tampering rule).
**Anti-security:** `Bios.cmd` (disables DEP, integrity services, TPM, ELAM, hypervisor, VSM).
**Maintenance/cleanup:** `RamCleaner`, `Vacuum`, `Riddance`, `PDQ`, `BCDCleanup`, `Stripper`, `Debloat`, `Provisioning`, `Persistance`, `PhantomRemover` (login diagnostics).
**Performance/gaming:** `GPerf`, `GameCache`, `GamingScripts`, `Benchmark`.
**Non-security:** `Browsers`, `gorstak-site`, `Notes`, `Hrvatski`, `Love4Free`, `AutoHotkey`, `BabylonianTime`, `GTalk`, `GVPN`, `Mp3ToMp4`, `Rainmeter`, `Store`, `Zerch`, `UniversalTime`, `CPythonWrapper`, `Corrupt`, `GBrowser`, `GKodi`, `GorstaksAI`, `GPrep`, `GRun`, `Audio`, `NetworkRepair`, `Spoofer`, `SystemMonitor` (WinForms GUI), `Patcher` (CVE patcher already covered), `Retaliate` (already covered under detection), `Backup`, `Ceprkac`.

---

## Implementation steps

In strict order; each step is independently shippable.

| # | Step | Why |
|---|------|-----|
| M1 | Remove `TrustedPublisherCheck` and the publisher-allowlist code path | Vendor allowlist; violates "kill on bad behavior, period" |
| M2 | Demote every non-President's-law Tier1 rule to LogOnly in `AdvancedResponseEngine` | Fixes the v0.6.x Steam/Windsurf regression |
| M3 | Add `FileVerdictAds` (read/write/HMAC) | Library helper, no behavior change |
| M4 | Add `FileVerdictScanner` background service | Walk drives + watch new files, write ADS markers |
| M5 | Add `VerdictGateRule` + `SafeProcessExemptionRegistry` | ADS verdict applied at exec time |
| M6 | Add `WebcamHijackMonitor` | Mirrors `AudioHijackMonitor` |
| M7 | Wire `NeuroBehaviorMonitor` to emit Tier1 on anomaly threshold | Promotes existing service into a Councilor |
| M8 | Add `ConsultantSignalIngestor` (tails JSONL drop directory) | Plumbing for PowerShell Councilors |
| M9 | Port PowerShell Councilors one by one to drop JSONL | Each ships independently |
| M10 | Apply attack-on-user weight -2 in `ScoringEngine` / correlation | Honors "attacks on the user have significant weight" |

After **M2**, the Steam/Windsurf regression is fixed. Everything after M2 is
additive Councilor wiring.

---

## Constraints (hard rules " never violate)

- No vendor / publisher / signer / process-name allowlists. Trust is per-file
  via the ADS verdict, signed with a per-machine HMAC key.
- All-3-APIs-failed   `safe`. Outage resolves to `unknown`.
- No static-signal kill (entropy / unsigned / YARA / IoC / hash alone).
- No Council member kills directly.
- Adding a behavior to the President's-law list requires this doc to be
  updated and explicit user sign-off.
- v2.0 hard rules from `constraints.md` carry over (no kernel drivers, no
  direct syscalls, no string-built JSON, no `Thread.Sleep` w/o cancellation,
  no static mutable state, etc.).

---

## Tests that must exist before this is "done"

- **Demotion contract:** synthetic `BeaconingRule` / `AttackToolsRule` /
  `ReverseShellRule` (heuristic match) / `HollowProcessRule` / `CampaignIocRule`
  detection at confidence 1.0 with active response on ' `LogOnly`.
- **President's-law:** synthetic `CredentialDumpDetection`,
  `RansomwareDetection` (mass-write subset), `AudioHijackDetection`,
  `MemoryExecutionDetection`, `VerdictGateRule(unsafe)` at confidence  0.85 '
  `KillProcess` via chain trace.
- **Composite kill preserved:** all single rules demoted, but `Active
  Ransomware Chain` (0.99) composite ' `KillProcess`.
- **Council single-signal:** any Councilor signal at confidence 1.0 alone '
  `LogOnly`.
- **Attack-on-user weighting:** two attack-on-user Councilors correlating on
  one PID within 30 s ' composite ' `KillProcess`.
- **ADS round-trip / HMAC tamper / expiry** as standard.
- **Signed-doing-ransomware:** ADS-`safe` PID exhibiting
  `RansomwareDetection` mass-write ' still killed.


