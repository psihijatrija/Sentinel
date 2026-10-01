# Sentinel - Requirements

**Version: 2.2.9**

---

## Project Overview

Userland-only defensive IDS/EDR for monitoring Windows systems.  
Focus: transparency, safety, real-world threat detection, and blue-team education.

---

## Intended Use & Scope

**Designed for:**
- Personal system visibility and monitoring
- Blue-team education and security research
- Real-world detection of malware, ransomware, C2 beacons, and post-exploitation activity

**Not designed for:**
- Offensive security or red-team tooling
- Evasion or stealth monitoring
- Deployment as a managed enterprise agent (no managed fleet / PPL kernel component)

---

## Functional Requirements

### FR-1: Detection Tiers

The system must implement two detection tiers with strictly enforced response contracts:

- **Tier 1 (Behavioral):** Active response allowed when `Sentinel:ActiveResponse` is true (default **true**). `EnforceActiveResponse` (default **false**) - when true, treats disabling ActiveResponse as tampering and force-re-enables it. Default false allows lab/observe installs to stay passive.
- **Tier 2 (Indicator):** Log only - response action is **never** permitted regardless of configuration.

### FR-2: Tier 1 Detection Rules

The system must detect the following behavioral threats:

| ID | Threat | Key Technique |
|----|--------|--------------|
| T1-01 | LSASS credential dumping | Known dumper names, LSASS-targeting command patterns, dump file names |
| T1-02 | Reverse shell / C2 callback | Encoded PowerShell, LOLBin abuse, C2 framework indicators, suspicious ports |
| T1-03 | Process injection / hollowing | Known injection tools, hollowing APIs, suspicious parent-child process relationships |
| T1-04 | Ransomware activity | Shadow copy deletion, backup destruction, bulk file renames, ransomware extensions |
| T1-05 | Security tool evasion | AMSI bypass, ETW patching, event log clearing, AV/EDR process termination |
| T1-06 | Kernel-observed injection | VirtualAllocEx, VirtualProtect RWX, NtMapViewOfSection, APC injection, SetThreadContext (ETW Threat Intelligence provider) |
| T1-07 | C2 beaconing | Statistical detection via coefficient of variation on connection intervals |
| T1-08 | Process hollowing | Memory vs disk image path mismatch via GetMappedFileName |
| T1-09 | Persistence mechanisms | Registry Run/RunOnce keys, scheduled tasks, WMI event subscriptions, service creation |
| T1-10 | Privilege escalation | UAC bypass (COM, manifests), token manipulation, named pipe impersonation, DLL hijacking |
| T1-11 | Known attack tools | C2 frameworks, credential tools, network attack tools, AD attack tools, LOLBin abuse |
| T1-12 | Campaign IOCs | Known malicious hashes, domains, IPs, file names, threat campaign patterns |
| T1-13 | Phantom keystrokes | Injected keystrokes detected via `LLKHF_INJECTED` flag and blocked via `WH_KEYBOARD_LL` |
| T1-14 | Network: Unauthorized Network Bridge | Virtual bridge detection and active SetupAPI uninstallation |
| T1-15 | Network: Primary Adapter Disabled | Baselined physical adapter disabled state detection and active restoration |
| T1-16 | Network: Unauthorized DNS Change | NameServer configuration registry lock and browser DoH policy enforcement |
| T1-17 | BYOVD / planted driver certs | Driver load + cert-trace; neutralize via service stop/SCM key remove (no System32 driver mass-delete) |
| T1-18 | Token theft / potato-class impersonation | Non-service SYSTEM tokens from user-writable paths (OS false positives suppressed) |
| T1-19 | Digital coercion / surveillance toolkit | Covert surveillance + remote channel, remote-control abuse toolkit, session theft + abuse channel, stalkerware persistence chain (host-tool composites only; no chat moderation) |
| T1-20 | AI agent / MCP abuse | Coding agents spawning shells, LOLBins, credential tools; burst recon patterns |
| T1-21 | Package supply-chain runtime | Package managers spawning LOLBins; executables under package trees; AI agent config poison (CLAUDE.md, .cursorrules, MCP configs) |
| T1-22 | Indirect syscall / Hell's Gate | Non-image executable memory containing a well-formed stub table: `mov r10,rcx; mov eax,SSN; syscall; ret` or a copied ntdll SharedUserData prologue, with 3+ distinct SSNs (loose JIT `0F 05` bytes are not a hit) |
| T1-23 | MitM attack chain | Planted self-signed root cert removal, ghost process -> rogue Cast kill, FCM Send-Tab-to-Self block, rogue Cast firewall block (when `MitmDefense.Enabled`) |
| T1-31 | Local network path MitM (v2.6.0) | >=2 distinct local-network tamper vectors (ARP poisoning, DNS hijack, route injection, adapter bridging, rogue WPAD/PAC proxy, Wi-Fi deauth flood / evil-twin BSSID) within the correlation window -> `Network Tamper: Local MitM Chain` composite -> protective VPN shield (when `VpnShield.Enabled`): raise tunnel, clean path, verify clean, drop. Fail-safe holds tunnel until verified clean |
| T1-24 | Lazarus Dream Job (CVE-2026-68820 campaign) | SecurityPDF / FudModule names, libmupdf sideload in staging, Temp\\new.exe from PDF parent, published C2; does **not** patch afd.sys |
| T1-25 | LegacyHive (CVE-2026-62832) | Another user's HKU hive loaded while not logged on; hive-path reparse; custom HKU names |
| T1-26 | Cloud Files / ShieldBreak (CVE-2026-62713) | Unknown CfApi sync roots; Cloud Files placeholders in staging; OneDrive exempt |
| T1-27 | Generic kernel-EoP / isolation-FS loaders | Staging unsigned PE matching exploit/CVE/Device\\Afd shape; unionfs/wcifs drops (not afd.sys patch) |
| T1-28 | Installer / Package Manager EoP | msiexec MSI from staging; ms-appinstaller / winget HTTP source; AlwaysInstallElevated |
| T1-29 | WMI persistence + policy rewrite | Filter/consumer/binding triple; hostile CommandLine/ActiveScript consumers; WmiPrvSE/wmiadap module walk; StdRegProv Policies hive attribution; WMI-Activity ETW 5859-5861 |
| T1-30 | Infostealer credential access + collect/package/exfil | Non-owning process reads browser credential/session stores (Login Data, Web Data, Cookies, Local State, key4.db, logins.json) or developer/cloud secrets (`.ssh`, `.aws`, `.azure`, gcloud, `.kube`, `.docker`, `.npmrc`, `.netrc`, `.git-credentials`, GnuPG) with Restart-Manager PID attribution; archive of user document trees; kill only when correlated with outbound (composites C-28/C-29). Raw file-access legs are Tier2 observe (LSASS-free stealer coverage) |

### FR-3: Tier 2 Detection Rules

The system must detect the following indicators (log only):

| ID | Indicator |
|----|-----------|
| T2-01 | Unsigned binary execution outside trusted system paths |
| T2-02 | High-entropy process names (Shannon entropy > 4.2) |
| T2-03 | Suspicious Win32 API names in command line, post-exploitation recon commands, persistence mechanism patterns |
| T2-04 | Dynamic rules (`DynamicRulesEvaluator`) and consultant JSONL signals (sticky LogOnly; never kill) |
| T2-05 | Optional OS service outbound activity (DiagTrack, whesvc, etc.) - observe-only, never stop/kill/isolate |
| T2-06 | Bulk transfer / torrent client traffic volume spikes - observe-only, never classified as Exfil terminal |
| T2-07 | KEV patch posture (CVE-2026-68820): Win11 UBR below 9168 or last CU before 2026-08-11 - LogOnly + toast, never force-patch |
| T2-08 | Missed Patch Tuesday: last CU before the latest second Tuesday after 7-day grace - LogOnly + toast, never force-patch |
| T2-09 | MOTW-strip PE / ISO / VSIX / .rdp / AppInstaller in Downloads - LogOnly (game ISOs never a kill seed) |
| T2-10 | ClickFix encoded Run, VS Code encoded shell, RDP client LOLBin spawn - LogOnly observe fuel |
| T2-11 | Update/servicing-surface abuse (`UpdateServicingMonitor`): a servicing actor (`TrustedInstaller`/`tiworker`/`wusa`/`dism`/`dismhost`/`expand`/`extrac32`/`pkgmgr`) spawning a shell/LOLBin/credential tool; CAB/MSU extraction to a path outside WinSxS/servicing/Temp staging (CVE-2021-40444 `..\` class); an unsigned or non-Microsoft-signed binary named as a servicing actor; a plain-HTTP or non-Microsoft WSUS/`AutoConfigURL`-style update source - all LOLBin/servicing observe fuel, never a solo kill (composes with `RegistryMonitor` service-drop + `FileActivityMonitor` writes) |
| T2-12 | Content smuggling in a container at rest (`ArchiveContentInspector` via `FileVerdictScanner`/`FileReputationEngine`): bounded, bomb-safe inspection of `.zip`-family archives and shallow scan of `.iso`/`.img` disk images for decompression-bomb ratios, nested archives, and embedded PE / script-host members. LogOnly `WeakObserveSeed` (file contents + names are attacker-controlled -> never a solo kill); seeds correlation so a later extract-and-detonate terminal completes a respondable chain. Fail-closed and hard-capped (container/total-decompressed <=512 MB, <=4096 entries, depth <=3, 8 s budget) so a zip bomb can never DoS the scanner |

### FR-4: Composite Detections

The system must implement two correlation engines that fire composite detections:

**BehavioralCorrelationEngine** - hand-authored, 60-second window:

| ID | Composite | Min Confidence |
|----|-----------|---------------|
| C-01 | Active Ransomware Chain | 0.99 |
| C-02 | Injected C2 Beacon | 0.98 |
| C-03 | Credential Dump + Exfiltration | 0.96 |
| C-04 | In-Memory Implant Active | 0.96 |
| C-05 | Named Pipe C2 + Network Beaconing | 0.95 |
| C-06 | Fileless Attack Chain | 0.95 |
| C-07 | DGA + C2 Beaconing | 0.94 |
| C-08 | Token Theft + Lateral Movement | 0.93 |
| C-09 | Dropped Payload Active | 0.93 |
| C-10 | Spoofed Process Phoning Home | 0.92 |
| C-11 | Evasion + Persistence Install | 0.91 |
| C-12 | Escalation + C2 Channel | 0.90 |
| C-13 | Covert RAT: Unsigned + Hidden + Network | 0.88-0.92 |
| C-14 | Confirmed C2 Beacon: Unsigned Process | 0.88-0.93 |
| C-15 | Covert C2: Unsigned + Sustained Connection | 0.90 |
| C-16 | Covert Surveillance + Remote Channel | 0.94 |
| C-17 | Remote Control Abuse Toolkit | 0.93 |
| C-18 | Session Theft + Abuse Channel | 0.95 |
| C-19 | Stalkerware Persistence Chain | 0.92 |
| C-20 | Lazarus Dream Job Chain | 0.95 |
| C-21 | LegacyHive Privilege Escalation Chain | 0.92 |
| C-22 | Cloud Files Hydration Tamper Chain | 0.91 |
| C-23 | Kernel Exploit Loader Chain | 0.94 |
| C-24 | Installer / Package Manager EoP Chain | 0.92 |
| C-25 | MOTW Bypass Execution Chain | 0.91 |
| C-26 | VS Code Workspace Abuse Chain | 0.91 |
| C-27 | WMI Persistence + Policy Rewrite | 0.94 |
| C-28 | Infostealer: Credential Access + Outbound | 0.95 |
| C-29 | Data Staging + Exfiltration | 0.93 |

**WeightedCorrelationEngine (v2.0)** - explainable score cards:

- Category weights summed per PID within a 90s window (Credential=50, Injection=44, Persistence=31, Network=18, BYOVD=60, etc.)
- Emits `Weighted Correlation: Multi-Signal Threat` when total >= threshold (default 100), >=2 distinct categories, and a terminal-family contribution or high score
- Every detection receives `ScoreCardTotal`, `ScoreCardBreakdown`, `ScoreCardExplanation` metadata
- Optional EventGraph diversity boost (0-25 pts) when `EnableGraphBoost=true`
- Config: `Sentinel:WeightedCorrelation` (`Enabled`, `Threshold`, `MinDistinctCategories`, `EnableGraphBoost`)

### FR-5: Monitoring Sources

| Source | Mechanism | Fallback |
|--------|-----------|---------|
| Process events | ETW kernel provider (Kernel-Process) | WMI Win32_ProcessStartTrace |
| Injection API calls | ETW Threat Intelligence provider | None (log warning, continue) |
| Network connections | GetExtendedTcpTable / GetExtendedUdpTable (IPv4+IPv6 TCP+UDP) | None |
| File activity | FileSystemWatcher | None |
| Process memory | Process.Modules enumeration + module count tracking | None |
| Process ancestry | CreateToolhelp32Snapshot (~5s refresh) | WMI on constrained SKUs |
| Webcam/Mic access | Process module enumeration (camera/mic DLL detection) | None |
| Hash reputation | CIRCL + MalwareBazaar + optional VT proxy | Unknown (fail closed for Safe) |
| Windows Event Log trail | Application log / source Sentinel (IDs 1000-1500) | Self-disables gracefully on stripped Windows |
| PE / URL ML scoring | Offline FastTree models (`MlModels/pe_model.zip`, `url_model.zip`) | Skipped if models absent; soft signal only |
| WMI-Activity ETW | Microsoft-Windows-WMI-Activity events 5859-5861 (permanent consumer / binding) | `WmiPersistenceMonitor` 30s poll of filter/consumer/binding |
| Sensitive file access | `SensitiveFileAccessMonitor` FileSystemWatcher on user profiles for credential/session stores + dev secrets + document archives; Restart Manager (`RmGetList`) owning-process attribution | None (event-driven) |
| Update/servicing surface | `UpdateServicingMonitor` polls servicing actors (`TrustedInstaller`/`tiworker`/`wusa`/`dism`/`dismhost`/`expand`/`extrac32`/`pkgmgr`) for anomalous children, CAB/MSU extraction outside WinSxS/servicing/Temp staging, and unsigned/non-Microsoft servicing binaries (`SignerTrustService`); WSUS/`AutoConfigURL`-style plain-HTTP or non-Microsoft update source. All Tier2/LogOnly observe fuel | `GetProcessCommandLine`/`GetParentProcessId` via WMI `Win32_Process`; degrades to process-name enumeration if WMI absent |

### FR-6: Response Actions

| Action | Condition |
|--------|-----------|
| Log detection + log response (`LogOnly`) | Always for Tier2; consultant signals; ActiveResponse disabled (lab); allowlist demotion; IDE host protection; observe-until-chain pending |
| Kill process / process tree | Tier1 with kill authority when `ActiveResponse=true` and chain confirmed; rate-limited (`MaxKillsPerMinute`, default 15) |
| Quarantine / QuarantineAndKill | DPAPI machine-scope under `%ProgramData%\Sentinel\Quarantine`; refuse OS-critical paths; max 128 MB; production ACL SYSTEM+Admins |
| NetworkIsolate | Public C2 IP only: firewall block (COM), DNS flush, ARP entry purge (native). Skip private/LAN/link-local/multicast/CDN resolvers. Rate-limited (`MaxNetworkIsolatesPerMinute`, default 10) |
| RemoveCert / RemoveCertAndKillAdder | Planted / high-confidence rogue certificates |
| RemoveRegistryEntry | Malicious autorun / service / COM persistence |
| DismountVolume (wired v2.8.4) | Chain-confirmed Tier1 kill whose process runs from a mounted ISO -> `IsolationResponseEngine.HandleIsoThreatAsync`: kill process tree, `Dismount-DiskImage`, delete backing `.iso`. ISO origin resolved from non-attacker-controllable anchors (OS-recorded mounted-image + process image path); degrades to plain kill (never dismounts an unrelated volume) if origin unconfirmed. Also drives Docker (`HandleDockerThreatAsync`, via `ContainerId`) and VM (`HandleVmThreatAsync`, via VM host PID) containment alongside the kill. VHD/SUBST fallback drives are dismounted by `VolumeMountMonitor` |
| VpnShieldUp (v2.6.0) | Confirmed local network tamper: raise a userland RAS VPN tunnel (visible; no kernel), clean the path (unbridge / re-enable adapters / restore DNS), verify clean, then drop the tunnel. Fail-safe: hold tunnel if not verified clean. Non-kill (ordered below KillProcess). Gated on `VpnShield.Enabled` (`ProductPosture.AllowsVpnShield`, default off); prefers trusted `ProviderProfile`, VPN Gate fallback only if opted in |

**ActiveResponse model:**

| Source | Behavior |
|--------|----------|
| `Sentinel:ActiveResponse` | Default **true** in config and install |
| `Sentinel:ObserveUntilChain` | Default **true** - demotes all kill/quarantine/isolate to LogOnly until multi-signal chain confirms terminal attack |
| `Sentinel:ChainConfirmMinSignals` | Default **2** - distinct rules on same PID within window required |
| `Sentinel:ChainConfirmWindowSeconds` | Default **300** - rolling correlation window |
| `Sentinel:SilentObserve` | Default **true** - no toasts or auto evidence packs until chain-confirmed |
| `Sentinel:EnforceActiveResponse` | Default **false** - when true, AntiTamper force-re-enables ActiveResponse if flipped off |
| CLI `--active-response` | Optional force-enable at service start (legacy / override; not required for normal install) |

**Removed (not required):** pre-kill **DeceptionEngine** / attacker-hostile deception tactics. Removed for Defender / AV compatibility; design rule is "no offensive deception tactics."

### FR-7: Logging

- Output format: JSONL (newline-delimited JSON), `System.Text.Json` only
- Default path: `%ProgramData%\Sentinel\events.jsonl`
- Size-based rotation: 20 MB per file, up to 5 rotated files
- Each entry must include: `type`, `timestamp`, `data` (with `ruleName`, `evidence`, `reasoning`, `confidence`, `tier`, `processName`, `processId`, `metadata`)
- Rate limiting: max **1000** entries/second, burst of **5000**
- File sharing: `FileShare.ReadWrite` - concurrent readers must not be blocked
- Graceful degradation: log file access failure must NOT crash the service
- Self-healing: writer must retry opening the file on each write if the initial open failed
- Stale file handling: locked/inaccessible files renamed to `.stale.<timestamp>` and fresh file created
- **Windows Event Log trail (v1.9.5):** critical events additionally written to Application log / source `Sentinel` (IDs 1000-1500) when available. Self-disables on barebone Windows. Config: `Sentinel:WindowsEventLog`. Never replaces JSONL as primary.

### FR-8: Explainability

Every `DetectionEvent` must include:
- `RuleName` - which rule fired
- `Evidence` - what was specifically observed
- `Reasoning` - why it is suspicious (human-readable)
- `Confidence` - 0.0-1.0 score calibrated per rule
- `Metadata` - key-value pairs with raw observable data
- `AttackTechniques` - MITRE ATT&CK technique IDs where applicable (v2.0)
- `ScoreCardTotal` / `ScoreCardBreakdown` / `ScoreCardExplanation` - weighted correlation score card fields when emitted by WeightedCorrelationEngine (v2.0)

### FR-9: Configuration & CLI

- Primary configuration: compiled defaults in the binary. Optional DPAPI `config.enc` for Hardened Mode / victim identity only. Disk JSON is not loaded.
- CLI may support:
  - `--active-response` - force-enable Tier1 destructive actions (does not replace default-true config)
  - `--log <path>` - override log file path
  - `--verbose` - enable debug logging
- CLI flags override config when present

### FR-9a: Agent Settings UI (v1.7.9+)

The user-session Agent must provide a Settings window (tray menu + double-click):
- Overview of protection / service status and recent detections
- Event log viewer (from `events.jsonl`)
- Report-to-police helper: load evidence packs, edit affidavit fields, open national portal, attach ZIP workflow
- Quarantine listing / open folder (**must not** create the quarantine directory as the interactive user)
- Safety page: plain-language scope of digital coercion toolkit defense (what it does / doesn't do)
- Ops page (v2.0): live metrics from IPC or `ops_metrics.json` fallback
- Must **not** expose any user-level ActiveResponse disable control
- Must not use balloon tips / Win32 notification APIs that deadlock under hardened WpnService removal

### FR-10: Deduplication

- `DetectionEngine` must suppress identical `(RuleName, ProcessId)` detections within **10s (Tier1)** / **30s (Tier2)**
- Network / monitor-level secondary cooldowns may apply per monitor

### FR-11: Threat proxy authentication (v1.6.0 / v1.8.1)

- Outbound threat report / VT proxy calls must HMAC-sign `{timestamp}.{path}.{body}` with `ThreatReporting:ProxySharedSecret`
- Headers: `X-Sentinel-Timestamp`, `X-Sentinel-Signature` only
- Must **not** transmit the shared secret in any header
- Fail closed (skip reporting) if secret missing or shorter than 16 characters

### FR-12: Evidence packs (v1.7.7-1.7.8 / v1.9.3-1.9.4)

- Automatic local evidence packs under `%ProgramData%\Sentinel\IncidentReports` on every chain-confirmed nuke
- Reportable-grade defaults: integrity seal (SHA-256 + machine HMAC), victim affidavit, chain of custody, ZIP export, national portal helper
- Digital coercion toolkit detections add honest technical scope + optional LE-oriented harm checkboxes
- Does **not** auto-file with law enforcement

### FR-13: Self-protection

- Service runs as SYSTEM; Agent is user-session UI/hooks only
- Binary / config integrity and ActiveResponse enforcement via `AntiTamperGuard`
- Safe Mode service registration
- Kill and isolate budgets with Tier1 budget-exhaustion visibility
- `SelfPathGuard` hardlink-aware self-exclusion checks in DetectionEngine and AdvancedResponseEngine (v2.0)

### FR-14: Plugin architecture (v2.0)

- Interfaces: `IDetector`, `ITelemetryProvider`, `ICorrelationRule`, `IResponsePlugin`
- `PluginRegistry` DI singleton - register correlation rules without editing core files
- `RulePackLoader` - loads HMAC-signed `*.pack.json` packs from `%ProgramData%\Sentinel\rules\packs\` as `FragmentCorrelationRule` plugins; fail-closed on invalid HMAC
- See `docs/RULE_PACKS.md`

### FR-15: Service<->Agent IPC (v2.0)

- `ServiceAgentIpcHost` named pipe `SentinelIpc-v2` with HMAC token authentication
- Commands: `ping`, `ops`, `health` (read-only) plus `scan` / `scan_status` (on-demand audit). No ActiveResponse control over the pipe
- HMAC token stored under `%ProgramData%\Sentinel\Secure\.ipc_token` (SYSTEM + Admins full; **Interactive Users read** - not all Authenticated Users)
- Agent falls back to `ops_metrics.json` file when pipe is unavailable

### FR-16: Ops metrics (v2.0)

- `OpsMetricsPublisher` writes `%ProgramData%\Sentinel\ops_metrics.json` every ~10s
- Metrics include: telemetry/sec, detections/sec, drops, composite/weighted counts, correlation latency percentiles
- Agent Settings -> Ops page displays live metrics (prefers IPC, falls back to file)

### FR-17: Observe-first / work-first posture (v1.9.7)

- Default install must **not** proactively reshape the host: no IPSec lockdown, no RPC/Cast/FCM firewall blocks, no service disable beyond Telnet + Remote Registry, no ASR Block re-arm, no RDP force-logoff, no USB auto-disable
- Older leftover IPSec/FW/ASR lockdown rules from pre-1.9.7 builds must be **removed** on upgrade
- Full kiosk lockdown available only via `RestrictivePortHardening: true`
- Any new proactive host mutation must gate on `ProductPosture.TryProactiveHostLockdown` and ship unit tests that default-deny

### FR-18: MitM defense suite (v2.0.1)

- `Sentinel:MitmDefense` opt-in suite for post-incident MitM attack response
- Default `Enabled: false` on clean installs
- When enabled: `TlsCertificateMonitor` removes high-confidence planted roots immediately; `GhostProcessMonitor` kills invisible/empty-name PID -> Cast without the normal 2-scan wait; `CastDeviceGuard` auto-blocks rogue Cast by IOC MAC prefix and known IPs; `NullSessionGuard` blocks FCM TCP 5228; `AdvancedResponseEngine` exempts MitmDefense actions from ObserveUntilChain demotion
- Config fields: `Enabled`, `RemovePlantedCerts`, `BlockFcmPushChannel`, `AutoBlockRogueCast`, `RogueCastMacPrefixes`, `KnownRogueCastIps`

### FR-21: Protective VPN-shield remediation (v2.6.0)

- `Sentinel:VpnShield` opt-in remediation for confirmed local network tampering (path-level MitM)
- Default `Enabled: false` on clean installs (`ProductPosture.AllowsVpnShield` gate)
- Trigger: the `Network Tamper: Local MitM Chain` composite fires when **>= 2 distinct** local-network
  tamper vectors (`ARP`, `DNS`, `Route`, `Bridge`, `AdapterDown`, `WPAD`, `WiFiDeauth`, `WiFiEvilTwin`)
  occur within the correlation window. A single vector never self-confirms; WPAD (a `WeakObserveSeed`)
  also continues to feed the existing `WPAD Proxy Hijack Chain`
- Action (`ResponseAction.VpnShieldUp`, non-kill, ordered below `KillProcess`): `VpnShieldEngine` raises
  a userland RAS VPN tunnel (`rasapi32`, visible - no kernel driver, no self-hiding), asks
  `NetworkInterfaceGuard` to clean (unbridge / re-enable adapters / restore DNS), verifies the path is
  clean for `CleanSweepsRequired` consecutive sweeps, then drops the tunnel
- **Fail-safe:** if the path cannot be *verified* clean (or verification errors), the tunnel STAYS UP;
  on `MaxShieldSeconds` expiry the incident is escalated and the tunnel is held - never silently dropped
- Trusted `ProviderProfile` (paid Proton/Mullvad or corporate RAS entry) is preferred; VPN Gate public
  relays are a fallback only when `UseVpnGateFallback` is set and no trusted profile exists, and the
  incident log records the volunteer-relay tradeoff
- Chain confirmation must never rewrite a `VpnShieldUp` action into a process nuke; process-level
  threats (C2, DoH exfil, covert mesh/webhook) are still answered with kill/isolate, not a tunnel
- Config fields: `Enabled`, `ProviderProfile`, `UseVpnGateFallback`, `VpnGateEntryName`,
  `VerifyIntervalSeconds`, `CleanSweepsRequired`, `MaxShieldSeconds`

### FR-19: Settings dashboard (v2.2.2)

- Tray **Settings** / double-click opens the **built-in** WinForms dashboard (`AgentDashboardForm`)
- Do not open a browser or `http://` URL for Settings
- The localhost web dashboard is not started
- (v2.2.0 leftover, if HTTP UI is ever re-enabled: bearer-only, no Referer auth, no secrets in `GET /`)

### FR-20: Game-path reputation skip (v2.2.0)

- On-execute file reputation may skip known entertainment install trees
- Skip MUST refuse user-profile / Temp / Downloads / Desktop / Documents paths (`ShouldSkipReputationForGamePath`)
- Memory-inspect skip (`IsGameOrAntiCheatPath`) is not a reputation skip and is not a trust grant
- A fake `steamapps\common` under `%AppData%` must still be reputation-scanned

---

## Non-Functional Requirements

### NFR-1: Safety
- Active response is enabled by default; President's Law categories cannot be allowlist-suppressed into silent kill bypass
- The tool must not self-replicate or hide itself as malware would
- No kernel drivers required for core detection (userland EDR)
- Never quarantine OS-critical / WRP paths
- Never NetworkIsolate private/LAN addresses
- Weak single-signal heuristics (shell+port, Downloads network, SeImpersonate alone, bulk-transfer tools, System32 redistributable writes) must be LogOnly - never kill seeds
- DLL unloaders (`DllUnloadEngine`) exempt from observe-until-chain: FreeLibrary on identity failure; quarantine hijack-name plants on drop (file only, never kill the host from that path)

### NFR-2: Reliability
- Monitors must fail independently - one monitor failure must not crash the service
- All exceptions must be caught and logged; no silent failures
- All `IDisposable` / `IAsyncDisposable` objects must be properly disposed
- Telemetry queue must be **bounded** (DropOldest under flood) to prevent OOM
- Optional features (ETW, Event Log, toast, TI proxy) must fail soft and self-disable permanently after hard failure - JSONL and core detection continue

### NFR-3: Performance
- Must not materially impact system performance during normal operation
- Detection deduplication must prevent log flooding
- Process ancestry snapshot must use atomic swap (no reader blocking)

### NFR-4: Portability of Privilege
- Service requires SYSTEM for full detection/response
- Agent runs as logged-in user with reduced capability (UI / session hooks only)
- Degradation / missing elevation must be logged clearly

### NFR-5: Testability
- Detection rules and response contracts must be unit-testable without live malware
- Tier2 response contract must be verified by automated test
- Composite detection logic must be testable with mock detection engine
- Security remediations covered by versioned suites (e.g. `V181SecurityHardeningTests`, `V200PlatformTests`)
- `ProductPostureTests` must verify all proactive host mutation defaults are deny

### NFR-6: Response-path hygiene
- Prefer native APIs / P/Invoke / COM for kill, firewall, DNS, ARP
- Installer and some integrity helpers may still shell `sc`/`icacls`/`netsh`/`secedit`/`LGPO` (documented exceptions)
- Prefer cancellable async delays; short `Thread.Sleep` allowed only for documented settle/STA cases
- No async/await on Agent STA thread - all background work on dedicated `Thread` instances

### NFR-7: Intentionally out of scope
- Pre-kill offensive deception (removed for AV compatibility)
- Kernel PPL / ELAM driver
- Full threat-intel certificate pinning (partial: Worker HMAC path preferred)
- Direct law enforcement API filing (no consumer EDR API exists)

---

## Document history (parity)

| Version | Notes |
|---------|--------|
| 1.7.9 | Agent Settings UI requirements added |
| 1.8.1 | ActiveResponse defaults, response matrix, proxy auth, quarantine ACL, no DeceptionEngine, dedup windows, isolate private-IP deny |
| 1.8.3 | Observe-first: protect on confirmed attack; weak path/port/shell heuristics LogOnly; IPSec attack-only by default; `RestrictivePortHardening` opt-in full lockdown |
| 1.9.3 | Observe-until-chain chain-confirm model; silent observe; chain-confirmed packs always; weak seed never chain-nuke |
| 1.9.4 | Digital coercion / surveillance toolkit composites; Safety UI page; platform-agnostic host-tool scope |
| 1.9.5 | Windows Event Log trail (critical only); graceful degradation on barebone Windows |
| 1.9.7 | Work-first posture law; ProductPosture gate; proactive host mutation default-deny |
| 1.9.9 | Privacy service observe-only; bulk transfer / torrent = T2 observe, never Exfil terminal |
| 2.0.0 | WeightedCorrelationEngine + score cards; MITRE ATT&CK mapping; plugin architecture + signed rule packs; ops metrics; Service<->Agent IPC; SelfPathGuard; EnforceActiveResponse default corrected to false |
| 2.0.1 | MitmDefense suite requirements (FR-18); planted-cert / ghost-Cast / rogue-Cast / FCM opt-in defense |
| 2.2.0 | FR-19 dashboard bearer (no Referer auth); FR-20 game-path reputation skip; V217 monitors registered; kiosk LGPO must not weaken the host |
| 2.2.3 | T1-24 Dream Job; T1-25 LegacyHive; T1-26 Cloud Files/ShieldBreak; KEV UBR toast; C-20-C-22 |
| 2.2.4 | T1-27/T1-28 generic CVE-class; T2-08-T2-10 MOTW/ClickFix/Patch Tuesday; C-23-C-26; CveShield Windows OS KEV |
| 2.2.5 | Module identity unload: foreign mapped PE FreeLibrary-APC immediately; count is not a signal; MZ/compact unbacked RWX execute-strip |
| 2.2.6 | Keep all of Windows except Temp; never kill host unless a user-writable drop failed to unmap; JIT RWX (no MZ) is not ALLOCVM_REMOTE |
| 2.2.7 | Module identity unload is permanent Tier1; hijack-name plants quarantined on drop (file only); no config flag may disable |
| 2.2.8 | T1-29 WMI triple + policy rewrite; C-27; WMI-Activity ETW provider #10; wmiadap module walk |
| 2.2.9 | Unified web dashboard in native window; WebDashboardService re-enabled; BrowserLauncher removed |
| 2.5.9 | T1-30 infostealer credential-access + collect/package/exfil; `SensitiveFileAccessMonitor` (browser cred/session stores + dev secrets + document archives, Restart-Manager PID attribution); composites C-28 Infostealer: Credential Access + Outbound, C-29 Data Staging + Exfiltration; raw file-access legs Tier2 observe, kill only via composite |
| 2.6.0 | T1-31 local network path MitM; FR-21 protective VPN-shield remediation; `VpnShieldEngine` + `VpnShieldConfig`; `ResponseAction.VpnShieldUp` (non-kill, `ProductPosture.AllowsVpnShield` default off); composite `Network Tamper: Local MitM Chain` (>=2 distinct tamper vectors incl. WPAD + Wi-Fi deauth/evil-twin); raise userland RAS tunnel -> clean -> verify clean -> drop, fail-safe holds tunnel |
| 2.6.3 | T2-11 update/servicing-surface abuse; `UpdateServicingMonitor` (CoreDetection group): servicing actors spawning shells/LOLBins/cred tools, CAB/MSU extraction to abnormal paths (CVE-2021-40444 `..\` class), unsigned/non-Microsoft servicing binaries via `SignerTrustService`, plain-HTTP/non-Microsoft update source; all Tier2/LogOnly observe fuel, composes with `RegistryMonitor` service-drop + `FileActivityMonitor` writes; never self-authorizes a kill |
