# Sentinel - Design Document

**Version: 2.8.3**

---

## Platform

- **Product (Core / Service / Agent / Tests):** .NET Framework 4.8, Windows only (`net48-windows`)
- **Installer:** framework-dependent publish via `installer/build.ps1` (requires .NET Framework 4.8 on the target PC; Setup offers the Microsoft download if missing)
- **Optional tooling:** `tools/Sentinel.MlTrainer` targets `net10.0-windows` (build host needs .NET SDK 10)
- Architecture: win-x64

---

## Architecture Overview

Sentinel follows a clean pipeline architecture with strict separation of concerns:

```
Monitors -> TelemetryFusionEngine -> DetectionEngine -> AdvancedResponseEngine -> JsonlEventLogger
                                                         
               EventGraph     BehavioralCorrelationEngine  (+ WeightedCorrelationEngine v2.0)
           (queryable graph)   hand-authored composites     score cards + threshold emit
                                                     
                               (composite detections via EmitAsync)
                                                     ChainTracer (kill + quarantine)
                                                     OpsMetricsPublisher -> ops_metrics.json
```

### Source layout of the kill-authority code (v2.7.9)

The three largest safety-critical types are split across files for reviewability. The split is
purely structural (C# `partial class` for the engines; per-domain files for the rules) - the
compiled types and behavior are unchanged:

- **Detection rules** (the `IDetectionRule` set) live in per-domain files: `Rules.CredentialAccess.cs`,
  `Rules.Ransomware.cs`, `Rules.ReverseShell.cs`, `Rules.Injection.cs`, `Rules.PrivEsc.cs`,
  `Rules.AttackTools.cs`, `Rules.CampaignIoc.cs`, `Rules.SupplyChain.cs`, `Rules.VerdictGate.cs`,
  `Rules.PathProvenance.cs` (there is no single `Rules.cs` type - it was always a container).
- **`AdvancedResponseEngine`** is a `partial class`: the decision layer (`HandleAsync`, Tier1-only
  branch guards, observe-until-chain gate, pre-action audit) is in `AdvancedResponseEngine.cs`; the
  low-level network/certificate P/Invoke executors are in `AdvancedResponseEngine.NetworkActions.cs`.
- **`BehavioralCorrelationEngine`** is a `partial class`: the per-PID composite cascade and shared
  buffers/locks are in `BehavioralCorrelationEngine.cs`; the host-wide (PID 0) network-tamper /
  VPN-shield subsystem is in `BehavioralCorrelationEngine.NetworkTamper.cs`.

### v2.0 platform additions

| Component | Role |
|-----------|------|
| `WeightedCorrelationEngine` | Explainable category weights; emits when Total >= Threshold |
| `AttackTechniqueMap` | MITRE ATT&CK technique IDs on detections |
| `PluginRegistry` + interfaces | Extensibility surface for detectors / correlation / response |
| `RulePackLoader` | RSA-SHA256 signed `*.pack.json` -> `ICorrelationRule` plugins |
| `EventGraph.GetProcessDiversity` | Graph fan-out boost for weighted score cards |
| `ServiceAgentIpcHost` / `ServiceAgentIpcClient` | HMAC authenticated named pipe with nonce replay prevention (ops/health/scan) |
| `OpsMetricsPublisher` | Writes `%ProgramData%\Sentinel\ops_metrics.json` |
| `SelfPathGuard` | Hardlink-aware install self-exclusion |
| `EncryptedConfigStore` | DPAPI `config.enc` for Hardened Mode / victim identity only; cannot disable detection or rewrite compiled HMAC |
| `ProductInfo.Version` | `2.6.0` |
| `VpnShieldEngine` + `VpnShieldConfig` | **v2.6.0.** Protective VPN-shield remediation for confirmed local network tampering (raise userland tunnel -> clean -> verify clean -> drop; fail-safe holds tunnel). New `ResponseAction.VpnShieldUp`; `ProductPosture.AllowsVpnShield` gate (default off) |

All components are wired via Microsoft.Extensions.DependencyInjection. No static mutable state anywhere.

### Telemetry Fusion Layer

Every monitor feeds raw telemetry through the `TelemetryFusionEngine` before the `DetectionEngine`. The fusion layer:
1. Enriches events with cross-source context
2. Builds temporal event chains per-process
3. Maintains the `EventGraph` for causal/temporal queries
4. Produces `FusedTelemetryContext` with behavioral velocity, diversity, and multi-vector flags

The fusion layer is PASSIVE - it never blocks, kills, or modifies telemetry.

---

## Two-Process Architecture

| Process | Session | Runs As | Purpose |
|---------|---------|---------|---------|
| `Sentinel.Service.exe` | Session 0 | SYSTEM | Core detection, response, ETW, network, file, registry monitoring |
| `Sentinel.Agent.exe` | User session | Logged-in user | Tray icon, keyboard hooks, screen/webcam, UI attack detection |

The Service is the authority. The Agent provides user-session visibility and UI.
`AgentWatchdog` (Service-side) monitors Agent liveness and relaunches it if killed.

---

## Component Inventory

### Service-Side Monitors (SYSTEM session)

Organized by MonitorGroup. Each group has staggered startup, independent failure restart, and priority-based resource allocation.

#### Group 1: Critical (starts immediately, restarts indefinitely)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `AntiTamperGuard` | Service self-reinstall, anti-suspend timing, binary integrity, encrypted config monitoring | 2s timing / 10s integrity |
| `IPSecIntegrityGuard` | Self-heals GSecurity IPSec: **attack-only** ports by default; full lockdown if `RestrictivePortHardening` | 30s |
| `AsrPolicyGuard` | Verifies Defender ASR Block rules (Policy hive); re-applies on drift/tamper | 60s |
| `AgentWatchdog` | Polls for Agent process; relaunches via CreateProcessAsUser if absent | 10s |
| `SyscallStubMonitor` | Compares ntdll/amsi function prologues against startup baseline; indirect syscall pattern detection | 30s |
| `ConnectivityCanaryMonitor` | Verifies Sentinel can reach threat intel endpoints; detects EDRSilencer | 45s |
| `EtwSessionGuard` | Checks UnifiedEtwSession IsActive + events/sec floor; auto-recreates | 3s |
| `EtwProviderTamperMonitor` | Checks EtwEventWrite patches in critical processes; detects logman/wevtutil manipulation | 30s |
| ~~`AmsiIntegrityCheck`~~ | **Removed v2.3.10** (its `AmsiScanBuffer`/`amsi.dll` string literals were a Kaspersky ML trigger on `Sentinel.Core.dll`). AMSI/ETW integrity coverage preserved via `SyscallStubMonitor` (ntdll prologue baseline) + `ScriptExecutionMonitor.CheckAmsiIntegrity` (Event 4104). | - |
| `HoneypotDllMonitor` | **v2.2.0 registered.** Decoy DLLs in `{install}\honeypot\` only (never next to Sentinel.exe) | FSW + 60s replant |

#### Group 2: CoreDetection (2s start delay, max 5 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `RansomwareIoMonitor` | High-frequency I/O rate monitoring for bulk rename/encrypt patterns | continuous |
| `BeaconingDetector` | Statistical CV analysis of connection intervals per (PID, Remote, Port) | 30s |
| `BehavioralBaselineService` | Learns normal processes, paths, parent-child, network destinations | continuous |
| `FileVerdictScanner` | Lazy background hash reputation scanning + ADS tagging (CIRCL/MalwareBazaar/VT) | background walk |
| `ConsultantSignalIngestor` | Tails external consultant signal JSONL under ProgramData; owner-checked. Emits via `SubmitConsultantSignalAsync` (sticky **Tier2 + LogOnly** - never kill/isolate) | continuous |
| `GhostProcessMonitor` | Detects PIDs with network connections but empty/unresolvable process names | 15s |
| `EphemeralProcessMonitor` | Catches short-lived processes via Prefetch + Event 4688 polling | 5s |
| `ModuleValidationMonitor` | Scans critical process modules for unsigned/tampered DLLs (baseline + detect) | 30s |
| `RuntimeModuleIntegrityMonitor` | Per-process module baseline; detects new suspicious DLLs appearing post-baseline | 60s |
| `DllEntropyAnalyzer` | Shannon entropy analysis on loaded DLLs; flags packed/encrypted (>=7.2) | periodic |
| `DllLoadFailureMonitor` | Event Log ID 7 + SideBySide errors for failed DLL hijack attempts | periodic |
| `DiskWideDllScanner` | Scans all drives for unsigned/suspicious DLLs at relaxed intervals | periodic |
| `PersistentConnectionMonitor` | Detects long-lived connections (webhooks, C2 pairing) and failover on drop | 10s |
| `DataExfiltrationMonitor` | Host-wide outbound volume spikes; **torrent/P2P/aria2 bulk transfer = observe-only** (never Exfil terminal) | 15s |
| `AdsDataStagingMonitor` | Detects non-standard NTFS Alternate Data Streams (>1KB) in Temp/Downloads | periodic |
| `ScriptExecutionMonitor` | PowerShell Event 4104, parent-child anomalies, AMSI bypass, SAM extraction, script drops | 10s |
| `UpdateServicingMonitor` | Update/servicing-surface abuse: servicing actors (`TrustedInstaller`/`wusa`/`dism`/`expand`/`extrac32`/`pkgmgr`) spawning shells/LOLBins/cred tools, CAB/MSU extraction to abnormal paths (CVE-2021-40444 `..\` class), non-Microsoft/HTTP WSUS source, unsigned/oddly-signed servicing binaries. All signals Tier2/LogOnly (never self-authorizes a kill); composes with `RegistryMonitor` service-drop + `FileActivityMonitor` writes | 12s |
| `ScriptHardeningMonitor` | PS history integrity, SBL enforcement, downgrade, obfuscation scoring, profile persistence | 8s |
| `NamedPipeMonitor` | Polls `\\.\pipe\` for C2/lateral movement patterns; GetNamedPipeServerProcessId attribution | 15s |
| `RpcLateralMonitor` | Detects outbound lateral movement via RPC/DCOM/WMI/WinRM (ports 135/445/5985/5986) | 10s |
| `TokenTheftMonitor` | Detects non-service SYSTEM tokens and SeImpersonatePrivilege from user-writable paths | 20s |
| `CloudSyncExfilMonitor` | Monitors cloud sync directories for burst file staging; detects rclone/megasync | 15s |
| `LnkShortcutMonitor` | Real-time FileSystemWatcher on Desktop/Start Menu/Taskbar/Startup (all profiles); UNC/protocol/LOLBin remote launch | FSW + startup scan |
| `AgenticProcessMonitor` | AI coding agents / MCP toolchains spawning shells, LOLBins, credential tools; burst recon patterns | 8s |
| `PackageRuntimeMonitor` | Package-manager postinstall LOLBins, exe under package trees, AI agent config poison (CLAUDE.md/Cursor/MCP) | 10s + FSW |
| `LpeScaffoldMonitor` | Potato-class tools and elevated staging PEs (Phase A) | periodic |
| `InitialAccessMonitor` | Browser/Office -> LOLBin, staging LOLBins | periodic |
| `PersistenceSurfaceMonitor` | IFEO, accessibility, Winlogon, COM hijack | periodic |
| `DreamJobCampaignMonitor` | **v2.2.3.** Lazarus Dream Job: SecurityPDF / FudModule / libmupdf sideload / Temp\\new.exe / C2 IOCs (not afd.sys) | 15s |
| `EdrKillerDetectionMonitor` | **v2.2.0 registered.** Known EDR-killer **process names** - LogOnly observe fuel (rename bypasses) | 5s |
| `DecoyPipeMonitor` | **v2.2.0 registered.** Default CS/Metasploit pipe-name honeypots | continuous |
| `CveClassCoverageMonitor` | **v2.2.4.** Generic kernel-EoP / MSI / winget / VS Code / ClickFix / MIDI / RDP-client userland shape | 18s |
| `MotwBypassMonitor` | **v2.2.4 / v2.3.5.** MOTW-strip PE **and script droppers** (`.hta`/`.js`/`.vbs`/`.wsf`/`.ps1`/`.lnk`/`.chm`), ISO/VHD, VSIX, .rdp, AppInstaller in Downloads/Desktop/Temp | 40s |
| `ContainerIsolationTamperMonitor` | **v2.2.4.** unionfs/wcifs/bindflt staging (CVE-2026-72971); AlwaysInstallElevated | 30s |
| `WpadProxyMonitor` | **v2.3.5.** WPAD / PAC auto-proxy config (`AutoConfigURL`) - rogue DHCP Option 252 / MITM proxy hijack (CVE-2026-62755 class). Composite `WPAD Proxy Hijack Chain` | 45s |
| `SensitiveFileAccessMonitor` | **v2.5.9.** FileSystemWatcher on user profiles for browser credential/session stores + developer/cloud secrets + document archives; Restart Manager owning-process attribution. LSASS-free infostealer coverage. Raw legs Tier2/LogOnly; kill only via composites `Infostealer: Credential Access + Outbound` / `Data Staging + Exfiltration` | FSW (event-driven) |

#### Group 3: CredentialProtection (4s start delay, max 3 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `CanaryFileMonitor` | Deploys decoy files in ransomware-target directories; any access triggers alert | 10s |
| `BrowserCredentialGuard` | Monitors Chromium + Firefox credential files (Login Data, Cookies, key4.db, logins.json) | 30s |
| `BrowserC2Guard` | Headless chrome-as-proxy detection, CDP session hijacking, extension manifest integrity scanning | 30s |
| `NativeMessagingHostGuard` | **v2.7.1.** Baselines browser native-messaging host registrations (registry + on-disk manifests); new host with unsigned/user-writable target -> Tier1, else Tier2. Closes page->extension->native-host->local-app bridge | 60s |
| `LocalControlChannelMonitor` | **v2.7.1.** Non-browser, non-ancestor local process connected to a loopback listener owned by a GUI/browser-like app -> control-channel pairing. Script-host/user-writable client -> Tier1, else Tier2 | 20s |
| `MicrosoftAccountGuardMonitor` | TokenBroker cache, PRT extraction, Azure AD token theft tool detection | 30s |
| `NullSessionGuard` | Enforces LimitBlankPasswordUse, RestrictAnonymous, EveryoneIncludesAnonymous; optional FCM TCP 5228 block when `BlockFcmPushChannel=true` | 60s |
| `BuiltinAdminGuard` | Monitors built-in Administrator account (RID 500); disables if found active | 15s |
| `RemoteLogonHardeningGuard` | **v2.7.6.** Denies network + RDP logon for local admin-class accounts (SeDenyNetworkLogonRight / SeDenyRemoteInteractiveLogonRight via secedit); clears auto-logon leak (AutoAdminLogon=0, Winlogon DefaultPassword, LSA DefaultPassword secret). Never touches passwords. Posture-gated | 5 min |
| `RemoteSessionGuard` | WTSEnumerateSessions; force-logoff non-console remote sessions (RDP etc.); never session 0 / console | 5s |
| `TokenPrivilegeAuditMonitor` | **v2.2.0 registered.** SeDebug/SeImpersonate from user-writable paths | 20s |

#### Group 4: NetworkIntegrity (6s start delay, max 3 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `ArpSpoofMonitor` | GetIpNetTable P/Invoke; detects gateway MAC change, ARP poisoning, virtual OUI | 15s |
| `DnsResponseValidationMonitor` | Resolves canary domains; validates against expected CIDR ranges | 1min |
| `PublicIpMonitor` | Checks public IP via Cloudflare/ipify/icanhazip; detects geo/ASN shift | 5min |
| `WifiSecurityMonitor` | Polls Wi-Fi state via netsh; detects deauth flood, open network, encryption downgrade | 15s |
| `NetworkInterfaceGuard` | Removes bridges via SetupAPI, restores disabled adapters, locks DNS. **v2.6.5** DNS-change confidence reputation-aware via `PublicDnsResolvers` allowlist (known public resolver -> 0.45, unknown -> 0.88) | 15s |
| `WinsockLspIntegrityMonitor` | **v2.6.5.** Walks Winsock2 protocol/namespace catalogs; flags non-Microsoft/unsigned LSP provider DLLs, missing providers, and chain gaps. Tier1 LogOnly (never rewrites the catalog) | 10min |
| `AppDnsExfilMonitor` | Detects non-browser processes connecting to known DoH resolvers on port 443 | 500ms |
| `NetworkShareMonitor` | Monitors SMB shares, admin share access (C$/ADMIN$/IPC$), inbound sessions | 15s |
| `NetworkReinfectionDetector` | Monitors NIC state changes; flags new suspicious processes after network reconnection | on NIC event |
| `ReinfectionCorrelator` | Tracks killed/quarantined hashes across reboots; scans for reappearance | 60s |
| `DnsCrossValidator` | Resolves test domain via system + direct Cloudflare; detects router DNS poisoning | periodic |
| `TrafficVolumeBaseline` | NIC BytesSent spikes; bulk-transfer clients (torrent/P2P) -> observe-only, not Exfil | 30s |
| `OutboundConnectionWhitelist` | Monitors/enforces outbound connections against allowed IP subnets | periodic |
| `RemoteAccessMonitor` | Scans for 35+ remote access tools; TeamViewer/AnyDesk/cloudflared LogOnly; **v2.5.3** ngrok/chisel/frpc/tailcat kill-grade | 60s |
| `ThreatIntelFeedBlocker` | Spamhaus/Feodo/ET feeds in memory; **observe-only by default** (no proactive FW); reactive `NetworkIsolate` on live hit when `ActiveResponse`; optional `ThreatIntelProactiveFirewall` | 4h refresh / 30s conn |
| `UdpFlowMonitor` | **v2.4.8.** `GetExtendedUdpTable` OWNER_PID + Kernel-Network UDP ETW. LOLBin/Temp/classic-port UDP. LogOnly | 2s |
| `IcmpAnomalyMonitor` | **v2.4.8.** `GetIcmpStatisticsEx` IPv4+IPv6 type counters: echo flood, inbound Redirect, unreachable storm. LogOnly | 5s |
| `WfpNetEventMonitor` | **v2.4.8.** `FwpmNetEventSubscribe0` (no callout driver). GRE/ESP/AH/SCTP/L2TP + drop bursts. Unknown-proto fallback | event / 15s |
| `VoipSessionMonitor` | **v2.4.8.** SIP/STUN/H.323/IAX/MGCP + RTP-like binds from unexpected processes. Discord/Teams/Zoom/Steam skipped | 3s |
| `CovertMeshMonitor` | **v2.5.2.** Userspace WG/DERP/STUN overlays (tailcat and copycats). Official Tailscale skipped. **Kill-grade C2** | 3s |
| `CovertWebhookMonitor` | **v2.5.2.** Webhook/bot-API exfil from script hosts / Temp. Discord.exe skipped. **Kill-grade C2** | 4s |

#### Group 5: SystemIntegrity (10s start delay, max 3 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `FirewallIntegrityMonitor` | Polls firewall profiles via netsh advfirewall; detects disable/bulk rules | 60s |
| `SecureBootIntegrityMonitor` | Checks Secure Boot, test signing, kernel debug via registry+bcdedit | 5min |
| `WindowsUpdateIntegrityMonitor` | WU service + AU policy + stale installs + **v2.2.3 KEV UBR (CVE-2026-68820 / KB5121003)** + **v2.2.4 missed Patch Tuesday** | 10min |
| `ScheduledTaskMonitor` | Polls scheduled tasks via schtasks; multi-indicator suspicious task analysis | 60s |
| `CriticalServiceGuard` | Monitors 15 critical services for crash storms via SCM events (7034/7031) | 10s |
| `RegistryMonitor` | WMI-based monitoring of Run keys, Services, CLSID COM hijacking | continuous |
| `WmiPersistenceMonitor` | **v2.2.8.** Filter + consumer + binding triple (`root\subscription` and `root\default`); hostile LOLBin consumers are a persistence terminal | 30s |
| `WmiPolicyRewriteMonitor` | **v2.2.8.** HKLM/HKU Policies hive fingerprint; attribute writes to WmiPrvSE/wmiadap/scrcons | 15s |
| `WmiProviderIntegrityMonitor` | Enumerates __Win32Provider objects; Authenticode on provider DLLs; module walk of **WmiPrvSE + wmiadap** | 5min |
| `WorkFoldersExfilMonitor` | Detects unauthorized Work Folders activation; active response: kills service | 15s |
| `PrivacyServiceOutboundMonitor` | **Observe-only:** optional OS services (DiagTrack, whesvc, ...) running + public remotes; never stop/kill/isolate | 15s |
| `ServiceProcessMap` | Service name <-> PID map (shared `svchost` attribution for privacy observe) | on demand |
| `TlsCertificateMonitor` | Monitors LocalMachine\Root + TrustedPublisher; baselines at startup. BYOVD follow-up: exact cert **thumbprint** match only -> stop service + delete SCM key (does **not** delete `System32\drivers\*.sys`) | 60s |
| `UacBypassSurfaceMonitor` | Detects COM AutoElevation vectors and manifest autoElevate + copy-drop | periodic |
| `HostsFileGuard` | Monitors hosts file for suspicious modifications (C2 IP redirects, security domain blocking); users may freely edit. Enforces a localhost/loopback baseline only. Only enforces FCM `mtalk.*` lines when `MitmDefense.Enabled` or `BlockFcmPushChannel=true` (appends missing lines, never overwrites). Enforces the **union** of `EnforcedDomainBlocks`/`EnforcedIpBlocks` (operator config) and `RuntimeBlocklistService` (runtime): domains via hosts line + wildcard NRPT (browser-authoritative via DoH-off), IPs via in/out firewall rules - self-healing, posture-gated. **v2.8.7:** un-blocking is deliberate - wildcard NRPT rules and firewall rules are torn down (`RemoveStaleDomainBlocks`/`RemoveStaleIpBlocks`) when an entry drops out of the desired set; the automatic startup `CleanupRetiredForumHrArtifacts` un-block was removed. Hosts-file sinkhole lines are NEVER cleared to ensure threats cannot auto-allow themselves. `forum.hr` is re-added as a default block seeded by `RuntimeBlocklistService` | FSW + 30s |
| `BrowserDnsPolicyGuard` | Disables DoH system-wide across all browsers; 15s self-healing | 15s |
| `BootIntegrityGuard` | Monitors BCD, boot drivers, EFI partition for bootkit indicators | 60s |
| `CveShieldHardener` | Fetches CISA KEV feed; maps against local assets; generates block rules | 4h |
| `ApplicationIntegrityMonitor` | Cuckoo Egg Detection - baselines protected apps (SHA-256 + Authenticode) | FSW + 30s |
| `PseudoSandbox` | Lightweight behavioral sandbox via restricted Job Objects | on-demand |
| `AcousticThreatMonitor` | Detects harmful audio frequencies via WASAPI loopback + Goertzel algorithm | continuous |
| `WfpIntegrityMonitor` | Scans WFP filters for BLOCK rules targeting Sentinel/EDR processes | 30s |
| `DriverLoadMonitor` | BYOVD via Event 7045 (PID when > 4), registry, **interactive user** .sys drops (not SYSTEM profile); cert-tracing | 15s |
| `GpuProcessMonitor` | GPU helper sandbox-escape (child/net/post-ex DLL) + trojanized GPU .sys names | periodic |
| `KernelModuleAuditMonitor` | **v2.2.0 registered.** NtQuerySystemInformation module list; logs pre-existing RTCore64/WinRing0 | 30s |
| `LegacyHiveMonitor` | **v2.2.3.** HKU hive loaded for a user who is not logged on (CVE-2026-62832); custom HKU names | 20s |
| `CloudFilesHydrationMonitor` | **v2.2.3.** Unknown CfApi sync roots + Cloud Files placeholders in staging (ShieldBreak / CVE-2026-62713). Does not disable OneDrive | 30s |

#### Group 6: Peripheral (30s start delay, max 2 restarts)

| Component | Mechanism | Interval |
|-----------|-----------|----------|
| `BluetoothMonitor` | Monitors BT device registry and service state; detects BadBT HID pairing | 15s |
| `PhantomDeviceMonitor` | ARP table scanning for new LAN devices; probes suspicious ports; firewall blocks | 45s |
| `DeviceInstallMonitor` | Baselines PnP devices/drivers; detects new device installs and BYOVD | 15s + WMI event |
| `MtpTransferGuard` | Blocks non-media file transfers to/from MTP devices (phones/tablets) | 5s |
| `VolumeMountMonitor` | Detects RAM disks, PMEM, VeraCrypt, VHD; extends FileActivityMonitor dynamically | 5s |
| `CastDeviceGuard` | Empty `TrustedCastDevices` = observe-only **unless** `MitmDefense.Enabled` (then auto-block rogue Cast IOCs / phantom spoof); non-empty = enforce allowlist + FW block | 5s |
| `MitmDefense` (config suite) | Post-incident: planted-cert remove + FCM Send-Tab-to-Self block + ghost->fake-Chromecast kill + rogue Cast FW | - |
| `WslMonitor` | Monitors WSL process spawns, suspicious commands, new distro installs | 10s |
| `RawDiskAccessMonitor` | Detects processes opening raw disk device paths via NtQuerySystemInformation handles | 20s |
| `PrintSpoolerMonitor` | Monitors print spooler for bulk spool file creation and XPS exfiltration | 15s |
| `SandboxEscapeMonitor` | Monitors Windows Sandbox, Docker, Hyper-V for escape indicators | 15s |
| `HardwareSecurityGuard` | Checks IOMMU/VT-d, Secure Boot, BitLocker encryption status | 60s |
| `UsbHidWhitelist` | Baselines connected HID devices; disables unknown HID keyboards (BadUSB) | 15s |
| `PhysicalAccessMonitor` | Correlates idle periods with hardware changes on user return | on idle return |

### Service-Side Standalone Monitors (not in a MonitorGroup)

| Component | Mechanism | Notes |
|-----------|-----------|-------|
| `EtwProcessMonitor` | ETW kernel provider (Kernel-Process); IMonitor interface | Falls back to WMI |
| `EtwThreatIntelMonitor` | Microsoft-Windows-Threat-Intelligence ETW provider. The old full-system 5s EnumModules walk was removed (v2.4.6, LatencyMon fix); the monitor now scans only PIDs flagged on `InjectionSuspectBoard` (recent remote-TI activity) on an 8s loop: unmapped thread starts, unbacked RWX regions in high-value targets, and (v2.9.0) ETW-TI STACKWALK return-frame analysis for unbacked call frames. Heavy inspection stays off the ETW callback thread. | Requires elevation |
| `DnsQueryMonitor` | Microsoft-Windows-DNS-Client ETW provider; IMonitor | Requires elevation |
| `WmiProcessMonitor` | Win32_ProcessStartTrace WMI event subscription | Disabled when ETW active |
| `FileActivityMonitor` | FileSystemWatcher on user profile + dynamic paths. Relevance via `SecurityFileScope.IsRelevantOrHighRisk`: extension allow-list (hot-path noise filter) OR high-risk drop directory (Startup/Temp/ProgramData/Public) + magic-byte content sniff (v2.9.1) - so a payload with a novel extension in a staging location is not skipped | Singleton |
| `NetworkMonitor` | GetExtendedTcpTable/UdpTable P/Invoke, IPv4+IPv6 | Singleton |
| `LsassDumpCanaryMonitor` | Scans system-wide process handles for unauthorized lsass.exe read access | 30s |
| `RouteTableMonitor` | GetIpForwardTable P/Invoke; detects route injection, default route hijack | 15s |
| `MemoryBehaviorAnalyzer` | Module identity (path+signer): one EnumModules baseline then Kernel-Process ImageLoad; prune PID caches every 5s; foreign modules unloaded via DllUnloadEngine | 5s prune / ImageLoad |
| `TokenIntegrityMonitor` | GetTokenInformation(TokenIntegrityLevel); detects Medium->High without UAC | 45s |
| `CredentialCanaryMonitor` | Plants/monitors honeypot credentials in Windows Credential Manager | periodic |
| `LocalServerMonitor` | Detects suspicious processes listening on localhost (mounted ISO/VHD origins) | 20s |
| `AppNetworkPolicyMonitor` | Per-app network destination learning and enforcement (30-min learning phase) | 15s |
| `UsbDeviceFingerprinter` | USB device baseline via VID:PID:Serial; BadUSB detection; failed-enum disable + verified PnP removal (pnputil fallback, periodic zombie re-sweep) | 30s |

### Agent-Side Monitors (user session)

| Component | Mechanism | Notes |
|-----------|-----------|-------|
| `TrayIconService` | System tray NotifyIcon; **Settings** / double-click opens native `AgentDashboardForm` with embedded WebBrowser. **No** `ShowBalloonTip` | WinForms STA |
| `AgentDashboardForm` | Thin WebBrowser shell hosting `http://localhost:19845` (WebDashboardService). IE11 Edge emulation for CSS grid/flexbox. **v2.2.9+:** replaces the old WinForms sidebar panels | WinForms STA |
| `WebDashboardService` | Loopback HTTP dashboard + REST API + WebSocket on localhost:19845. Bearer token auth. Serves `DashboardHtml` at GET / | BackgroundService |
| `DashboardHtml` | Self-contained HTML/CSS/JS served by WebDashboardService - the full dashboard UI | Static class |
| `ScreenCaptureMonitor` | Detects DXGI desktop duplication + transparent overlay phishing windows | 15-25s |
| `WebcamMicMonitor` | Detects background camera/mic access via DLL analysis (Media Foundation, WASAPI) | 20s |
| `AudioHijackMonitor` | Module-based detection of output-to-mic redirection (virtual audio cables) | periodic |
| `MicSessionMonitor` | Standalone microphone session monitoring (defense-in-depth with WebcamMicMonitor) | periodic |
| `NeuroBehaviorVisualMonitor` | Focus steals, cursor jumps, brightness oscillations, large transparent topmost overlays | 1s sample |
| `BrowserExtensionMonitor` | Baselines extensions; detects new extensions with dangerous permissions | 30s |
| `PhantomKeystrokeGuard` | WH_KEYBOARD_LL hook; blocks software-injected keystrokes | continuous |
| `ClickjackingGuard` | Mouse hook; detects injected clicks, cursor teleport, fake UAC/credential prompts | continuous |
| `WebcamHijackMonitor` | Monitors ConsentStore for webcam/microphone access by new apps | periodic |
| `ShellWatchdog` | Monitors explorer.exe responsiveness via SendMessageTimeout; auto-restarts shell | 5s |
| `ScarewareWindowMonitor` | Window-title scareware / fake UAC / fake Defender dialogs (>=2 keywords) | 10s |
| `CursorTakeoverMonitor` | Low velocity-variance continuous cursor motion (bot/RDP-takeover style) | 3s sample |
| `CookieIntegrityMonitor` | SHA-256 integrity on Chrome/Edge/Brave cookie DBs (alert-only; no force-restore) | 5 min |

### Engines

| Component | Role |
|-----------|------|
| `MlThreatScorer` | Offline FastTree models (`MlModels/pe_model.zip`, `url_model.zip`) for PE static malware prior and lexical URL/host risk. Soft signal only; never sole kill. Trained via `tools/Sentinel.MlTrainer` from C/datasets. |
| `FileReputationEngine` | Multi-signal file score (hash TI + static PE + optional PE ML + signer + path context). Composite 0-100. |
| `DetectionEngine` | Runs all `IDetectionRule` instances against incoming telemetry. **Bounded** channel (10k, DropOldest). Tiered deduplication (10s Tier1, 30s Tier2). Consultant signals sticky Tier2/LogOnly. Records metrics via `SentinelMetrics`. |
| `AdvancedResponseEngine` | Single point of action enforcement. Tier2 always log-only. With `ObserveUntilChain` (default), Tier1 destructive actions only after `ResponsePolicy` chain confirm (C2/exfil/token/shell/cred-dump/BYOVD) or DLL-unload exempt path; then full nuke. Private/LAN IPs never firewall-isolated. |
| `ResponsePolicy` | Observe-until-chain classifier: terminal outcomes, benign System32 redistributable noise, multi-signal PID buffers, silent-observe gates. |
| `TelemetryFusionEngine` | Correlates raw telemetry across all sources into per-process event chains. Produces `FusedTelemetryContext` with behavioral metrics. |
| `EventGraph` | In-memory graph of processes, files, and network endpoints with temporal/causal edges. Supports incident timeline queries. |
| `MemoryBehaviorAnalyzer` | Scans mapped modules (permanent): startup EnumModules baseline + Kernel-Process ImageLoad. `ModuleIdentity` allow/deny on first sight of a path in that PID. Foreign modules unloaded immediately via DllUnloadEngine; detection stays Tier1. Count growth is not a signal. Missing image path remains Tier2 observe. |
| `ProcessAncestryCache` | `CreateToolhelp32Snapshot` refreshed every 5s (WMI fallback for Server Core/IoT). Provides parent name resolution. |
| `BehavioralCorrelationEngine` | Time-windowed (60s) multi-signal correlator. Fires composite `DetectionEvent`s via `IDetectionEngine.EmitAsync`. |
| `BeaconingDetector` | Statistical C2 beacon detection. Tracks inter-connection intervals. Fires when CV < 0.40 with 5+ observations. Multi-factor Authenticode trust verification. |
| `ScoringEngine` | Weighted multi-factor threat scoring with source weights, category base scores, corroboration bonuses. |
| `FileReputationEngine` | Composite file trust scoring (0-100) aggregating CIRCL, MalwareBazaar, VirusTotal (via proxy), static PE analysis, signer trust. |
| `DllUnloadEngine` | Unloads mapped modules that fail identity. Hijack-name plants quarantined on drop (file only, including steamapps). Never FreeLibrary lsass/csrss/wininit/DISM/NTLite. No VM_READ on games. |
| `ChainTracer` | Attack chain walker: kills non-critical processes in chain, quarantines binaries, removes persistence. |
| `IncidentResponseService` | Automated incident resolution: persistence removal, quarantine orchestration. Integrates with ChainTracer. |
| `VpnShieldEngine` | **v2.6.0.** Protective VPN-shield remediation for confirmed local network tampering. On the `Network Tamper: Local MitM Chain` composite (>=2 distinct tamper vectors: ARP/DNS/Route/Bridge/AdapterDown/WPAD/WiFiDeauth/WiFiEvilTwin), raises a userland RAS VPN tunnel (visible; `rasapi32`, no shell), asks `NetworkInterfaceGuard` to clean (unbridge / re-enable adapters / restore DNS), verifies clean for `CleanSweepsRequired` sweeps, then drops the tunnel. Fail-safe: holds the tunnel if not verified clean. Trusted `ProviderProfile` preferred; VPN Gate fallback only if opted in (logged as a tradeoff). Gated on `ProductPosture.AllowsVpnShield` (default off). New `ResponseAction.VpnShieldUp` (non-kill, ordered below KillProcess); never promoted to a process nuke on chain-confirm. |
| `IsolationResponseEngine` | Handles threats from isolated environments: ISO dismount, Docker stop+rm+rmi, Hyper-V/VM stop. |
| `DynamicRulesEvaluator` | Loads HMAC-signed JSON rules from `{BaseDirectory}/rules`. Install-entropy signing key; fail-closed if missing. Property allowlist + SecureCompare. |
| `ResponseCoordinator` | Per-PID semaphore-based response serialization. Prevents duplicate kills, supports escalation. |
| `ReinfectionCorrelator` | Tracks killed/quarantined hashes across reboots. Scans for reappearance of known-bad. |

### Orchestration Layer

| Component | Role |
|-----------|------|
| `SentinelOrchestrator` | Central coordination: routes detections through incident grouping before response. Per-PID response locks. |
| `IncidentManager` | Groups detections into unified incidents by PID/parent/hash. Lifecycle: Open -> Active -> Responded -> Closed. |
| `MonitorRegistry` | Supervises all monitors with heartbeat tracking. Auto-restarts crashed monitors. Death fires anti-tamper. |
| `StartupSequencer` | Phased dependency-ordered boot: Infrastructure -> Engines -> Monitors -> Validators. |
| `ContextBus` | Thread-safe pub/sub for cross-monitor enrichment signals. Bounded channels, TTL-based expiry. |
| `MonitorGroup` | Infrastructure class grouping monitors with staggered startup, restart policies, health checks. |

### Infrastructure & Utilities

| Component | Role |
|-----------|------|
| `JsonlEventLogger` | JSONL output to events.jsonl. Thread-safe, rate-limited, size-rotated, self-healing. |
| `SecureCacheStore` | DPAPI machine-scope encryption + HMAC integrity for persisted cache files. |
| `HashReputationService` | Two-tier caching (memory + DPAPI disk). 3-API lookup: CIRCL, MalwareBazaar, VT proxy. |
| `QuarantineManager` | DPAPI machine-scope quarantine under `%ProgramData%\Sentinel\Quarantine`. Production path: SYSTEM+Admins FullControl (inherit) + Interactive this-folder-only List/Traverse (UAC-safe Explorer). Sample blobs stay unreadable to Users. Max 128 MB/file. Restore path-validated (no OS-critical write). Agent never creates the folder. |
| `SignerTrustService` | Centralized Authenticode verification (WinVerifyTrust + catalog fallback). Trusted publisher cache. |
| `AllowlistService` | User/dev/gaming/publisher allowlists. President's Law rules never suppressed. |
| `SecurityValidation` | Input validation, Authenticode (embedded + catalog), process image path, OS-critical paths, private IP classification, constant-time `SecureCompare`. |
| `SentinelMetrics` | Performance counters with histograms (P50/P90/P95/P99) for detection and response. |
| `SentinelHealthCheck` | Structured health checks: process, memory, handles, log file, quarantine, thread pool. |
| `StartupSelfTest` | Verifies ETW, DPAPI, quarantine, log file, and rule loading before activating monitors. |
| `ThreatReportService` | Reports threats to MalwareBazaar/URLhaus/AbuseIPDB via Cloudflare Worker proxy (HMAC-auth). |
| `AutoIncidentReporter` | v1.7.7/1.7.8/1.9.3/1.9.4: Reportable-grade evidence packs, integrity seal (SHA-256+HMAC), victim affidavit, zip export, TI share, national portals. Chain-confirmed / composite nukes always write a pack. Coercion-toolkit packs add honest technical scope + optional harm checkboxes. Does not file police reports. |
| `CoercionAbusePolicy` | v1.9.4: Platform-agnostic classification of remote-control / surveillance / session-theft toolkit signals; pack + toast wording. Not chat moderation. |
| `SentinelEventLogWriter` | v1.9.5: Critical-only Windows Event Log trail (Application/Sentinel). Self-disables on stripped Windows; JSONL remains primary. |
| `SentinelEventLogHeartbeatService` | v1.9.5: Optional low-frequency Event Log heartbeat for SIEM gap detection. |
| `LawEnforcementPortals` | Country -> cybercrime portal directory (IC3, Action Fraud, MUP, ...); INTERPOL info-only. |
| `IoCScanner` | Loads threat intel indicators from DPAPI-encrypted external cache. |
| `InstallerHeuristics` | Installer name / Inno extractor / benign prefetch + **`IsLikelyInstallerPath`** (Downloads/Desktop/Program Files; not AppData\Roaming or bare Temp). Used for HighRisk demotion. |
| `HardeningModule` | Native C# hardening: service disabling, registry security settings, LGPO policy, ACL enforcement. |
| `UnifiedEtwSession` | Single real-time ETW session subscribing to 9 kernel/system providers via raw P/Invoke. |
| `EtwEventDispatcher` | Routes raw ETW events by provider GUID to typed telemetry objects. |
| Config integrity | `AntiTamperGuard` hashes `config.enc` + own binary. Disk JSON is not a config source. |
| `ProxyAuthHelper` | HMAC-SHA256 of `{timestamp}.{path}.{body}` with `ThreatReporting:ProxySharedSecret` (server-side secret; **not** install entropy). Headers: `X-Sentinel-Timestamp`, `X-Sentinel-Signature` only - never send the secret. |
| `ParentPidSpoofDetector` | Detects PPID spoofing via CreateToolhelp32Snapshot parent-child validation. |
| `SafeProcessExemptionRegistry` | Tracks processes confirmed safe by VerdictGateRule to prevent redundant scanning. |
| `FileVerdictAds` | Reads/writes ADS-based verdict tags on scanned files to avoid re-scanning. |
| `ToastService` | System toast notification delivery for user-visible alerts (Agent-side). |

---

## Detection Rules

### Tier 1 - Behavioral (active response allowed via President's Law)

| Rule | Category | Key Signals | Confidence Range |
|------|----------|-------------|-----------------|
| `LsassAccessRule` | CredentialDump | LSASS-targeting cmdline tokens, dump file names | 0.85-0.92 |
| `RansomwareDetectionRule` | Ransomware | Shadow copy deletion, bulk renames, I/O rate, 100+ extensions | 0.68-0.99 |
| `ReverseShellRule` | ReverseShell | Encoded PowerShell, LOLBins, C2 ports, C2 framework strings | 0.80-0.93 |
| `ThreatIntelInjectionRule` | ProcessInjection | Kernel-observed VirtualAllocEx, VirtualProtect RWX, APC, SetThreadContext | 0.72-0.93 |
| `PrivilegeEscalationRule` | PrivilegeEscalation | UAC bypass, token manipulation, named pipe impersonation, DLL hijacking | 0.80-0.95 |
| `AttackToolsRule` | SecurityEvasion | C2 frameworks, credential tools, AD tools, LOLBin abuse (60+ patterns) | 0.75-0.97 |
| `CampaignIocRule` | CampaignIoC | Known malicious hashes, domains, IPs, campaign patterns | 0.78-0.92 |
| `CampaignDetectionRule` | CampaignIoC | Multi-indicator campaign matching (CobaltStrike, QBot, Emotet, TrickBot) | 0.70-0.90 |
| `ClickFixDetectionRule` | ReverseShell | Paste-and-run / FakeCAPTCHA exploits from explorer/browser | 0.78-0.92 |
| `NpmSupplyChainRule` | SecurityEvasion | node/npm/yarn/pnpm spawning shell with download/encode patterns | 0.75-0.90 |
| `ChromeRemoteDebuggingRule` | CredentialDump | Browser launched with --remote-debugging-port by non-browser parent | 0.85 |
| `DllSideloadingDetectionRule` | ProcessInjection | Signed Microsoft utilities executing from user-writable paths | 0.80-0.90 |
| `VerdictGateRule` | AntiTamper | On-execute reputation check; blocks Malicious/HighRisk binaries | 0.80-0.95 |

### Tier 2 - Corroborating Signals (log only, feeds correlation engine)

| Rule | Key Signals | Confidence Range |
|------|-------------|-----------------|
| `UnsignedBinaryRule` | Unsigned binary outside system paths, staging path boost | 0.50-0.68 |
| `DynamicRulesEvaluator` | HMAC-signed JSON rules from install `rules/`; allowlisted fields only | varies (rule-defined; still Tier2-enforced at response) |

### Composite Detections (BehavioralCorrelationEngine)

Emitted as Tier1 `DetectionEvent`s directly via `EmitAsync`. Requires signals from different sources within a 60s window on the same PID.

| Composite | Confidence | Trigger Combination |
|-----------|-----------|---------------------|
| Active Ransomware Chain | 0.99 | 2+ distinct ransomware signals from different rules |
| Injected C2 Beacon | 0.98 | Kernel-observed injection + C2 network |
| Credential Dump + Exfiltration | 0.96 | LSASS/credential access + outbound network |
| In-Memory Implant Active | 0.96 | Memory anomaly (injection/RWX) + network callback |
| Named Pipe C2 + Network Beaconing | 0.95 | Suspicious named pipe + C2 network beaconing on same PID |
| Fileless Attack Chain | 0.95 | AMSI/ETW/security evasion + shell or C2 |
| DGA + C2 Beaconing | 0.94 | High-entropy/rapid DNS + periodic beacon |
| Token Theft + Lateral Movement | 0.93 | Token manipulation + RPC/SMB/pipe lateral movement on same PID |
| Dropped Payload Active | 0.93 | Unsigned/staged binary + C2 communication (catch-all) |
| Confirmed C2 Beacon: Unsigned Process | 0.88-0.93 | Unsigned binary + periodic beaconing pattern (staging path boost) |
| Spoofed Process Phoning Home | 0.92 | PPID spoofing + network communication |
| Evasion + Persistence Install | 0.91 | Security evasion + persistence mechanism |
| Covert C2: Unsigned + Sustained Connection | 0.90 | Unsigned binary maintaining 60s+ outbound connection |
| Escalation + C2 Channel | 0.90 | Privilege escalation + outbound C2 |
| Covert RAT: Unsigned + Hidden + Network | 0.88-0.92 | Unsigned from staging path + C2 network (recon activity boost) |

---

## Telemetry Types

| Type | Source | Consumed by |
|------|--------|-------------|
| `ProcessTelemetry` | `EtwProcessMonitor`, `WmiProcessMonitor` | All Tier1 rules, `TelemetryFusionEngine` |
| `NetworkTelemetry` | `NetworkMonitor`, `UnifiedEtwSession` (Kernel-Network) | `ReverseShellRule`, `BeaconingDetector` |
| `FileActivityTelemetry` | `FileActivityMonitor`, `UnifiedEtwSession` (Kernel-File) | `RansomwareDetectionRule` |
| `ThreatIntelTelemetry` | `EtwThreatIntelMonitor`, `EtwEventDispatcher` (ETW-TI events; stashes captured STACKWALK frames on `InjectionSuspectBoard`) | `ThreatIntelInjectionRule`; `EtwThreatIntelMonitor.ScanOneProcessStack` (off-thread unbacked-frame analysis) |
| `RegistryTelemetry` | `UnifiedEtwSession` (Kernel-Registry) | `RegistryMonitor` |
| `DnsTelemetry` | `UnifiedEtwSession` (DNS-Client) | `DnsQueryMonitor` |
| `FirewallTelemetry` | `UnifiedEtwSession` (Firewall) | `FirewallIntegrityMonitor` |
| `TaskSchedulerTelemetry` | `UnifiedEtwSession` (TaskScheduler) | `ScheduledTaskMonitor` |
| `DetectionEvent` (direct) | `NamedPipeMonitor`, `WmiPersistenceMonitor`, other monitors | Direct emission to `DetectionEngine.EmitAsync` |

---

## Response Actions

| Kind | When |
|------|------|
| `LogOnly` | Always for Tier2; consultant signals; Tier1 when `ActiveResponse=false` (lab/observe); allowlist demotion; IDE host protection |
| `NetworkIsolate` | Tier1: firewall block of **public** C2 IP (COM `INetFwPolicy2`); DNS flush (`DnsFlushResolverCache`); ARP entry purge (`DeleteIpNetEntry`). Skips private/LAN/link-local/multicast/CDN resolvers. Rate-limited (`MaxNetworkIsolatesPerMinute`, default 10). |
| `KillProcess` | Tier1 with kill authority, confidence gate, via ChainTracer / direct kill; budgets (`MaxKillsPerMinute`, default 15) |
| `KillProcessTree` | Same as above but walks and kills entire process tree |
| `Quarantine` | DPAPI-encrypted file quarantine to `%ProgramData%\Sentinel\Quarantine` (<=128 MB; OS-critical paths refused; Interactive browse-only on the folder) |
| `QuarantineAndKill` | Kill process + quarantine binary + place lock file |
| `RemoveRegistryEntry` | Removes malicious autorun/service/COM entries |
| `DismountVolume` | Dismounts ISO/VHD/SUBST drives hosting threats |
| `RemoveCert` | Removes suspicious root certificates from store |
| `RemoveCertAndKillAdder` | Removes planted certificate + kills the process that installed it (BYOVD cert-trace) |

### ActiveResponse model (current - observe-until-chain)

| Source | Behavior |
|--------|----------|
| `Sentinel:ActiveResponse` (default **true**) | Master arming switch - destructive actions still require chain confirm when ObserveUntilChain is on |
| `Sentinel:ObserveUntilChain` (default **true**) | Demote all kill/quarantine/isolate/host mutation to LogOnly until multi-signal proof of terminal attack (C2 beacon, exfil, token theft, reverse shell, cred dump, BYOVD) |
| `Sentinel:ChainConfirmMinSignals` (default **2**) | Distinct rules on same PID within window + >=1 terminal outcome -> nuke |
| `Sentinel:ChainConfirmWindowSeconds` (default **300**) | Rolling correlation window |
| `Sentinel:SilentObserve` (default **true**) | No toasts / auto evidence packs until chain-confirmed; chain-confirmed nukes always pack + critical toast (v1.9.3) |
| `Sentinel:EnforceActiveResponse` (default **false**) | When true, `AntiTamperGuard` force-re-enables ActiveResponse if flipped off |
| DLL unload exemption | `DllUnloadEngine` FreeLibrary on mapped identity failure and quarantine of hijack-name disk plants may act immediately (never kill the host on disk plant) |
| CLI `--active-response` | Optional force-enable at process start (legacy) |
| Central gate | `ResponsePolicy` + `AdvancedResponseEngine`; composites tagged `ChainConfirmed=true` |

---

## Key Design Rules

- **Dependency Injection** - all components receive dependencies via constructor injection
- **No static mutable state** - `ConcurrentDictionary`, `Channel<T>`, `SemaphoreSlim` for shared state
- **Cancellation preferred** - prefer `Task.Delay(ct)` / async loops. Some short `Thread.Sleep` remain in Agent STA paths, USB PnP settle delays, and Service main keep-alive (`Timeout.Infinite`)
- **No silent failures** - all exceptions caught and logged; monitors fail independently
- **Graceful degradation** - ETW -> WMI fallback; ThreatIntel ETW unavailable -> continue without
- **Startup self-test** - Verifies ETW, DPAPI, quarantine, log file, and rule loading before activating monitors
- **Tier2 enforcement** - `AdvancedResponseEngine` hard-codes `LogOnly` for all `Tier2Indicator` events regardless of configuration
- **Consultant signals never escalate** - `DetectionEngine` refuses Critical re-promotion when `Metadata.ConsultantSignal=true`
- **Deduplication** - `DetectionEngine` suppresses identical `(RuleName, ProcessId)` pairs within 10s (Tier1) / 30s (Tier2)
- **Bounded telemetry** - detection queue capacity 10_000, `DropOldest` under flood
- **All file reads use `FileShare.ReadWrite | FileShare.Delete`** - Sentinel observes, never obstructs
- **Monitors are grouped by function and priority** - critical self-protection first, peripheral last
- **Response path: prefer native APIs** - kill/firewall/DNS/ARP use COM/P-Invoke. **Exceptions still present:** installer `sc.exe`/`takeown`/`icacls`; hardening/LGPO/`secedit`; some monitors still call `netsh` (WFP export, IPSec show, Cast allow rules). Goal is no LOLBins on the kill hot path
- **No offensive deception tactics** - removed to avoid AV heuristic false positives on the Sentinel binary

---

## Logging

`JsonlEventLogger` writes newline-delimited JSON to `%ProgramData%\Sentinel\events.jsonl`.

- Thread-safe via `SemaphoreSlim`
- `System.Text.Json` only - no string-built JSON
- Size-based rotation at 50 MB, up to 5 rotated files
- Rate-limited: max 1000 entries/second, burst of 5000
- `FileShare.ReadWrite` - concurrent readers never blocked
- Self-healing: retries on write failure; renames stale locked files

---

## Unified ETW Session Architecture

Single real-time ETW trace session replacing per-monitor polling:

```

                    UnifiedEtwSession                                  
   Single real-time trace session (SentinelUnifiedTrace)              
   64 buffers x 256KB, QPC timestamps, AboveNormal priority          
                                                                      
   PROVIDERS:                                                         
   1. Microsoft-Windows-Kernel-Process     -> ProcessTelemetry        
   2. Microsoft-Windows-Kernel-File        -> FileActivityTelemetry   
   3. Microsoft-Windows-Kernel-Registry    -> RegistryTelemetry       
   4. Microsoft-Windows-DNS-Client         -> DnsTelemetry            
   5. Microsoft-Windows-Threat-Intelligence-> ThreatIntelTelemetry    
   6. Microsoft-Windows-PowerShell         -> ProcessTelemetry (4104) 
   7. Microsoft-Windows-Firewall           -> FirewallTelemetry       
   8. Microsoft-Windows-TaskScheduler      -> TaskSchedulerTelemetry  
   9. Microsoft-Windows-Kernel-Network     -> NetworkTelemetry        
  10. Microsoft-Windows-WMI-Activity       -> WMI persistence (5861)  

```

- **P/Invoke only**: Raw Win32 ETW APIs. No TraceEvent NuGet (embeds AV-triggering strings).
- **Single thread**: ProcessTrace blocks on a dedicated background thread.
- **Graceful degradation**: If ETW session fails, all monitors continue with poll-based implementations.
- **WMI deduplication**: When ETW is active, `WmiProcessMonitor.Disable()` prevents duplicate events.

---

## v1.6.8 Additions

### New Monitor: BrowserC2Guard (Group 3: CredentialProtection)

Full browser-based C2 detection expanding `ChromeRemoteDebuggingRule`:

| Detection Mode | Confidence | Response |
|----------------|-----------|----------|
| Headless Chrome-as-proxy (debug port + non-browser parent) | 0.78-0.90 | KillProcessTree |
| CDP session hijacking (non-browser WebSocket to debug port) | 0.88 | NetworkIsolate |
| Extension manifest: dangerous permissions (debugger, nativeMessaging, proxy) | 0.55-0.78 | LogOnly |

### Expanded Monitors

| Monitor | What was added |
|---------|----------------|
| `EtwThreatIntelMonitor` | VirtualQueryEx-based detection of unbacked RWX regions in high-value targets (ALLOCVM_REMOTE + PROTECTVM_REMOTE effects). Runs every 3rd cycle. Provider GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`. |
| `SyscallStubMonitor` | Indirect syscall / Hell's Gate table detection via ReadProcessMemory. Scans non-image executable memory for well-formed `mov r10,rcx; mov eax,SSN; syscall; ret` or copied ntdll prologues. Fires at 3+ distinct SSNs (0.92). Name-based JIT skips are not used. |
| `PrintSpoolerMonitor` | PrintNightmare-class exploitation: baselines printer driver DLLs, detects new unsigned DLLs in spool\drivers, catches spoolsv.exe spawning unexpected child processes. |
| `WslMonitor` | Container-to-host lateral movement: (1) WSL writing to sensitive host paths via /mnt/c/, (2) WSL interop spawning security-sensitive Windows .exe, (3) Docker overlay filesystem processes accessing host resources. |

### New Composite Detections (BehavioralCorrelationEngine)

| Composite | Confidence | Trigger Combination |
|-----------|-----------|---------------------|
| Named Pipe C2 + Network Beaconing | 0.95 | Suspicious named pipe + C2 network beaconing on same PID |
| Token Theft + Lateral Movement | 0.93 | Token manipulation + RPC/SMB/pipe lateral movement on same PID |

### ContextBus Integration (v1.6.8)

| Monitor | Signal Published | Consumed By |
|---------|-----------------|-------------|
| `NamedPipeMonitor` | `NamedPipeSignal` | BehavioralCorrelationEngine, ChainTracer |
| `TokenTheftMonitor` | `TokenTheftSignal` | BehavioralCorrelationEngine, ChainTracer |

---

## v1.7.0 Additions

### Enhanced Monitor: DriverLoadMonitor - BYOVD Certificate Tracing

Full cert-revocation chain for BYOVD attacks. When a vulnerable/suspicious driver is detected, Sentinel now traces back to the signing certificate and revokes it if planted.

| Capability | Description | Confidence | Response |
|------------|-------------|-----------|----------|
| Cert extraction | Authenticode cert extracted from detected .sys binary | - | - |
| TrustedPublisher plant detection | Checks if signing cert is in TrustedPublisher store (not a known public CA) | 0.95 | RemoveCertAndKillAdder |
| Root CA plant detection | Checks if cert issuer is a planted Root CA (fake Chromecast/IoT CA pattern) | 0.95 | RemoveCertAndKillAdder |
| Cross-driver scan | After cert revocation, scans System32\drivers for other .sys files signed by same cert | 0.93 | Disable+Delete service |
| CurrentUser store coverage | Also checks CurrentUser\TrustedPublisher and CurrentUser\Root | 0.95 | RemoveCertAndKillAdder |

**Attack chain closed:**
```
1. Attacker plants fake cert in TrustedPublisher
2. Attacker signs driver with that cert -> Windows DSE validates
3. Sentinel DriverLoadMonitor detects new kernel driver (Event 7045 / registry / .sys drop)
4. Cert-trace: extracts Authenticode cert -> finds it in TrustedPublisher -> NOT a public CA
5. Fires RemoveCertAndKillAdder -> cert removed from store
6. Scans System32\drivers -> disables all services using that cert
7. Driver cannot be reloaded (DSE will now reject it)
```

**Public CA protection:** Well-known vendor and CA certs (DigiCert, Microsoft, NVIDIA, Intel, Realtek, etc.) are never revoked - only non-public planted certs trigger revocation.

---

## v1.7.4 Additions

### ThreatIntelFeedBlocker (Service - NetworkIntegrity)

| Item | Value |
|------|--------|
| Feeds | Spamhaus DROP, Feodo Tracker recommended, EmergingThreats block list |
| Refresh | Startup (+45s delay) then every 4h |
| Firewall | COM `HNetCfg.FwPolicy2` batch rules (100 IPs/rule, IN+OUT), max 5000 rules / 2000 IPs per feed |
| Connection check | Every 30s against active established TCP remotes; Tier1 + `NetworkIsolate` on hit |
| CIDR policy | Prefix /8-/32 only (rejects /0-/7) |

### LnkShortcutMonitor (Service - CoreDetection)

| Item | Value |
|------|--------|
| Mechanism | FileSystemWatcher `*.lnk` + full initial scan |
| Paths | All `C:\Users\*\Desktop|Start Menu|Taskbar|Startup` + Common Desktop/Programs/Startup |
| Resolution | COM `IShellLink` + binary UNC fallback |
| Detections | UNC target, `search-ms:`/`ms-msdt:`/`http(s):`, LOLBin+remote args |
| Response | Tier1 + Quarantine (delete fallback) |
| Note | Sole LNK guard - poll-based `LnkUncGuard` heuristics folded in; not dual-registered |

### Agent user-session ports (from PowerShell Detection/)

| Monitor | Interval | Response |
|---------|----------|----------|
| `ScarewareWindowMonitor` | 10s | Tier1 + KillProcessTree (scareware >=2 keywords / fake system title) |
| `CursorTakeoverMonitor` | 3s sample | Tier2 LogOnly (low velocity variance + motion) |
| `CookieIntegrityMonitor` | 5 min | Tier2 LogOnly (Chrome/Edge/Brave cookie DB hash change) |

---

## v1.8.1 Additions

### Security audit remediations + doc/code parity

| Item | Value |
|------|--------|
| Proxy auth | `ProxyAuthHelper` / Worker: HMAC only; **no** cleartext `X-Sentinel-Auth` |
| Telemetry queue | `Channel.CreateBounded` 10k DropOldest |
| Dynamic rules | Property allowlist; SecureCompare HMAC; async reload debounce |
| Consultant | Sticky Tier2 + LogOnly (no scoring kill escalation) |
| BYOVD neutralize | Exact thumbprint only; stop service + SCM key; **no** `System32\drivers` file delete |
| NetworkIsolate | Private/LAN/multicast denied; ARP entry flush restored via `DeleteIpNetEntry` (native) |
| Quarantine | Production ACL SYSTEM+Admins; Agent never mkdir; 128 MB cap; restore path guards |
| Diagnostics | ProgramData\Sentinel ACL locked before early service traces |
| Installer demotion | `IsLikelyInstallerPath` required for HighRisk->Tier2 demotion |
| Tests | `V181SecurityHardeningTests`; full suite ~945 |

### Restored capability (ARP flush)

| Item | Detail |
|------|--------|
| Original | v5.9.0 (`4e92102`, **Gorstak**): NetworkIsolate = firewall + `arp -d` + DNS flush |
| Dropped | During LOLBin-free rewrite of `AdvancedResponseEngine` (`8d47e14` chore:update / COM firewall era) - shell `arp.exe` removed, native replacement not added |
| Restored | v1.8.1: `FlushArpEntry` via `iphlpapi!DeleteIpNetEntry` (no process spawn) |

### Not missing (clarifications)

| Design name | Reality | Who |
|-------------|---------|-----|
| `ConfigIntegrityMonitor` | Never a standalone class; logic in `AntiTamperGuard` | Doc naming only (clarified v1.7.0, Gorstak) |
| Tray `ShowBalloonTip` | Intentionally removed - WpnService hardening deadlocks STA | Gorstak (v1.4.x / tray rewrite); use Settings UI + event log |
| `BrowserCredentialTheftRule` | Never implemented as `IDetectionRule`; covered by `BrowserCredentialGuard` | Backlog only |

## v1.8.0 Additions

### TokenTheft false-positive hardening

| Item | Value |
|------|--------|
| Problem | Built-in `Memory Compression` / `Registry` (SYSTEM token, empty image path) treated as potato/token theft -> kill-grade + police packs every cooldown |
| Fix | Expanded OS allowlists; empty path not suspicious; empty path + OS name skipped; unknown empty path LogOnly 0.55 only |
| Cooldown | Per-PID/rule alert cache 60 minutes (was 5) |
| Packs | `AutoIncidentReporter.IsTokenTheftOsFalsePositive` blocks LE packs for those FPs; Token Theft pack cooldown >= 1 hour |
| Tests | `V180FeatureTests` |

## v1.7.9 Additions

### Agent Settings UI

| Item | Value |
|------|--------|
| Entry | Tray **Settings** (bold) / double-click |
| Form | `AgentDashboardForm` - thin WebBrowser shell hosting embedded web dashboard on localhost:19845 |
| Pages | Overview - Events - System Scan - Quarantine - Report to Police - Safety - Ops Metrics - Tools - About |
| Filing | Edit affidavit in web UI -> Save Affidavit API call -> Send Report opens national portal link; pack folder path shown |
| Prefs | `%LocalAppData%\Sentinel\user_report_prefs.json` |
| Not exposed | ActiveResponse toggle (service-only); balloon tips |

## v1.7.8 Additions

### Reportable-grade evidence quality

| Item | Value |
|------|--------|
| Policy | `ReportableGradeOnly` (default true); MinConfidence 0.85; kill floor 0.80 |
| Seal | `MANIFEST.sha256` + machine-bound `MANIFEST.hmac` + `evidence_manifest.json` |
| Affidavit | `victim_affidavit.txt` (post-seal fill; excluded from hash list) |
| Custody | `chain_of_custody.txt` (timeline + handoff table; excluded from hash list) |
| Export | `.zip` + `.zip.sha256` |
| Verify | `AutoIncidentReporter.VerifyPackIntegrity` |

## v1.7.7 Additions

### Automatic attack incident reporting

| Item | Value |
|------|--------|
| Hook | `SentinelOrchestrator.ProcessDetectionAsync` after response (async, non-blocking) |
| Pack root | `%ProgramData%\Sentinel\IncidentReports\AUTO_*` |
| TI share | Existing `ThreatReportService` / Worker (hash, URL, IP) when secret configured |
| LE filing | Human: national portal URL embedded in pack + toast |
| Not supported | Direct INTERPOL / police API auto-file (does not exist for consumers) |

Config section: `AutoIncidentReporting` (see CHANGELOG 1.7.7 / 1.7.8).

## v1.7.6 Additions (superseded in v2.6.9)

### Forum.hr policy: removed in v2.7.6, RE-ADDED as a default block in v2.8.7 (history)

The forum.hr hosts-file block and wildcard NRPT rule (restored in v2.6.9 after the v1.7.6
`ForumHrWatchMonitor` was deleted) were **removed entirely in v2.7.6**, then **re-added in v2.8.7**
as a default block - this time through the generic `RuntimeBlocklistService` rather than a
hardcoded special case. Current state:

| Item | Value |
|------|--------|
| Hosts baseline | `HostsFileGuard` enforces the localhost/loopback header only (`HostsBaselineLines`). No external domain is baked into the baseline |
| Runtime blocklist | `RuntimeBlocklistService` is the shared runtime block surface (`BlockDomain`/`UnblockDomain`/`BlockIp`/`UnblockIp`, persisted). `forum.hr` is seeded as a default block on first run (guarded by a persisted seed marker so an explicit unblock survives restarts) |
| Enforcement | `HostsFileGuard.EnforceConfiguredBlocks` enforces the **union** of `RuntimeBlocklistService` and the operator `EnforcedDomainBlocks`/`EnforcedIpBlocks` arrays: domain = hosts line (apex + `www`) + wildcard NRPT (`.domain` -> `0.0.0.0`); IP = in/out firewall rules. Posture-gated (`MayEnforceConfiguredBlocks`), self-healing on the 30s scan |
| Un-block (deliberate) | A block is torn down only when it drops out of the desired set (wildcard NRPT rule and firewall rules deleted; hosts-file sinkhole lines are never cleared to prevent threats from auto-allowing themselves). The old automatic startup `CleanupRetiredForumHrArtifacts` un-block was **removed in v2.8.7** - machines are no longer blindly un-blocked |
| Reusable capability | `BuildDomainNrptRule(ruleGuid, domainSuffix, sinkhole)` builds the wildcard NRPT rule; `NrptRuleGuidForDomain` derives its stable GUID |
| Behavioral pairing | The forum.hr *behavior* (a page taking control of a browser) is caught by `LocalControlChannelMonitor.ClassifyPairing` regardless of domain; `SentinelConfig.RiskyPairingOrigins` (seeded with `forum.hr`) is an aggravator only, never a verdict |

## v1.7.5 Additions

AV-safe PowerShell residual ports. **Not** included (high AV heuristic risk): KeyScrambler keyboard injection, FocusLock network lockdown, Preferences JSON mutation, mass browser kills.

### HardeningModule (install / ApplyOrFail)

| Capability | Source | Mechanism |
|------------|--------|-----------|
| Defender ASR Block rules (14 GUIDs) | `GEDR_ASR_Rules.ps1` + expanded set | Policy hive `...\ASR\Rules` value `"1"`; excludes prevalence-based unknown-exe rule (installer FP) |
| Credential residual | `Creds.ps1` | `RunAsPPL=1`, `DisableDomainCreds=1`, `CachedLogonsCount=2`, WDigest off |
| Browser residual | `Browsers.ps1` | WebRTC localhost IP handling policy (Chrome/Edge/Brave); CRD remote-access host policies off; disable `chrome-remote-desktop-host` / `chromoting` |

### AsrPolicyGuard (Service - Critical)

| Item | Value |
|------|--------|
| Interval | 60s (20s initial delay) |
| Check | `HardeningModule.IsAsrPolicyIntact()` - every required GUID present and Block |
| Response | Re-apply + Tier1 LogOnly Anti-Tamper detection on drift |

### RemoteSessionGuard (Service - CredentialProtection)

| Item | Value |
|------|--------|
| Source | `Credentials/ES.ps1` |
| Mechanism | `WTSEnumerateSessions` + `WTSLogoffSession` (no qwinsta/rwinsta shell) |
| Interval | 5s |
| Terminate | Non-console Active/Connected/Disconnected remote sessions |
| Never | Session 0, active console session id, WTSListen/Init/Down/Reset stubs |
| Response | Force logoff + Tier1 LogOnly (0.92) |

---

## Hardening at install (HardeningModule.ApplyOrFail)

Applied once at service start (best-effort, non-fatal failures):

1. DLL search path restriction (`SetDllDirectory` / `SetDefaultDllDirectories`)
2. **IPSec GSecurity (v1.8.3):**
   - **Default:** attack-only ports (Telnet, rsh/rlogin/rexec, TFTP, RPCBind, classic RAT ports 666/1337/4444/31337/...). **Not** SSH/RDP/SMB/SOCKS/Docker/DB.
   - **`RestrictivePortHardening: true`:** also blocks the broader service set (SSH, RDP, SMB, WinRM, DBs, discovery, ...).
3. Safe Mode registration + inbound RPC ephemeral block (lateral movement)
4. **Service disable (v1.8.3):** always Telnet + Remote Registry; RDP/SSH/WinRM/TeamViewer/UPnP only if restrictive
5. Registry security (LSA, TLS 1.3, SEHOP, Spectre/Meltdown, AlwaysInstallElevated, firewall profiles). Remote WMI/WinRM registry clamps only if restrictive
6. DEP AlwaysOn (`bcdedit /set nx AlwaysOn`)
7. LGPO import of embedded `GSecurity.inf` (only remaining intentional shell-out for policy template)
8. ASR Block rules, credential hardening residual, browser/CRD policy hardening

Self-heal loops: `IPSecIntegrityGuard` (30s, rebuilds current profile), `AsrPolicyGuard` (60s), plus various integrity monitors.

### Response posture (v1.8.3)

| Class | Behavior |
|-------|----------|
| Confirmed attack (LSASS, ransomware, injection, BYOVD, SYSTEM token, composites) | Authorized kill/quarantine/isolate when `ActiveResponse` |
| Weak user-activity heuristics (shell+port, Downloads net, SeImpersonate alone, rclone, unusual subnet) | **LogOnly** at emit + `AdvancedResponseEngine.IsObserveOnlyUserActivityHeuristic` safety net |

---

## v2.2.5 Additions

Module identity is the PE-map backbone. Count is not a signal.

| Item | Reality in 2.2.5 |
|------|------------------|
| `ModuleIdentity` | Path tree + Microsoft signature allow/deny. Keep: Windows/Edge WebView/GPU/.NET/WebView2 user-data, process image, app dir except unsigned sideload names, Microsoft-signed Program Files |
| `DllUnloadEngine` | Unloads mapped modules that fail identity. Hijack-name plants quarantined on drop (file only). explorer/svchost scanned. Never FreeLibrary lsass/csrss/wininit/DISM/NTLite |
| `MemoryBehaviorAnalyzer` | 5s identity scan. "Module Count Growth" removed |
| `EtwThreatIntelMonitor` | Ceprkac/WebView2/browsers high-value. MZ or compact unbacked RWX -> strip execute. Large non-MZ JIT ignored |

## v2.2.4 Additions

Generic CVE-class coverage. Does not patch kernel races. Folder `Monitors/` is file layout; types live in `namespace Sentinel.Core`.

| Item | Reality in 2.2.4 |
|------|------------------|
| Kernel EoP loaders | `CveClassCoverageMonitor` - exploit/CVE/Device\\Afd shape from staging. Composite `Kernel Exploit Loader Chain` |
| Installer / winget | MSI from staging; ms-appinstaller; AlwaysInstallElevated. Composite `Installer / Package Manager EoP Chain` |
| MOTW / ISO / ClickFix | Delivery-folder sensors (PE **and script droppers** missing MOTW, v2.3.5); game ISOs LogOnly. Composite `MOTW Bypass Execution Chain` |
| WPAD / PAC proxy hijack | `WpadProxyMonitor` - rogue `AutoConfigURL` / DHCP Option 252 (v2.3.5). Composite `WPAD Proxy Hijack Chain` |
| VS Code SFB | Encoded shell from Code/Cursor. Composite `VS Code Workspace Abuse Chain` |
| unionfs | User-writable isolation-filter .sys (CVE-2026-72971) |
| CveShield | Windows OS-class KEV matches WorkstationOs; no synthetic PoC hashes |
| Patch Tuesday | Toast if last CU is before the latest second Tuesday (7-day grace) |
| Namespace | `V217Hardening.cs` is `Sentinel.Core` - there is no second monitor type universe |

## v2.2.3 Additions

August 2026 Patch Tuesday userland coverage. Does not patch kernel races.

| Item | Reality in 2.2.3 |
|------|------------------|
| Dream Job | `DreamJobCampaignMonitor` + campaign/IOC rules + SHA-256 seed. Composite `Lazarus Dream Job Chain` |
| KEV posture | Win11 26100/26200 UBR below 9168 -> LogOnly + critical toast. Never auto-patch |
| LegacyHive | Loaded HKU for a user who is not logged on; hive-path reparse. Composite with token/UAC |
| Cloud Files / ShieldBreak | Unknown CfApi sync roots; staging placeholders. OneDrive placeholders are not junction kills |
| `IoCScanner.AddHashes` | Union; CveShield dummy salts no longer wipe campaign hashes |

---

## v2.2.0 Additions

Honest remediations. Several 2.1.8 "fixes" were not in force until this version.

| Item | Reality in 2.2.0 |
|------|------------------|
| Dashboard auth | `LoopbackDashboardAuth` - Authorization Bearer or `?token=`. Referer is ignored. Token is **not** in `GET /`. Tray opens `DashboardLaunchUrl`. |
| V217 monitors | Registered in MonitorGroups (see inventory above). Dead code until 2.2.0. |
| Honeypot DLLs | `{install}\honeypot\` only - never `version.dll` next to Sentinel.exe |
| EDR-killer names | LogOnly observe fuel, not President's Law |
| Game reputation skip | `ShouldSkipReputationForGamePath` - user profile / Temp / Desktop cannot skip |
| ChainTracer | System32 / SysWOW64 only (`Windows\Temp` is quarantinable) |
| AgentWatchdog | Install-dir image path; `lpApplicationName`; same Authenticode publisher; unsigned pair Debug-only |
| DriverLoadMonitor | Interactive user profile roots; Event 7045 PID; pre-existing RTCore logged |
| BrowserC2Guard | Per-user LocalAppData extension trees, not SYSTEM profile |
| GSecurity.inf | Password length 12 + complexity; audit on; FIPS not touched |
| Worker | `RATE_LIMITER.limit` after HMAC; MB `/report/hash` is lookup+comment |
| EncryptedConfigStore | `SCFG2` HMAC envelope; leftover JSON cannot set `ObserveUntilChain=false` |
| President's Law | No DnsAnomaly / NetworkAnomaly |
| Tests | `V220SecurityHardeningTests` |

## v2.1.8 Additions

### New Components (previously undocumented)

| Component | Location | Role |
|-----------|----------|------|
| `WebDashboardService` | Sentinel.Agent | Local HTTP dashboard (`http://localhost:19845`); CSRF + bearer from tray `?token=` (Referer is not auth) |
| `DashboardHtml` | Sentinel.Agent | Static HTML/CSS/JS generator for the web dashboard |
| `ScanEngine` | Sentinel.Core | On-demand file/directory scan engine; powers `/api/scan` from dashboard and `scan` IPC command |
| `GpuProcessMonitor` | Sentinel.Core/Monitors | Detects crypto-mining via GPU compute usage patterns (non-gaming, non-video processes) |
| `LegacyVerdictSidecarPurgeService` | Sentinel.Core | Cleanup service for deprecated verdict sidecar files from pre-ADS versions |
| `BulkTransferNoise` | Sentinel.Core | Noise suppression for legitimate bulk transfer clients (torrent, P2P, aria2) |
| `EnrichmentSignals` | Sentinel.Core | Cross-monitor enrichment signal types for ContextBus pub/sub |

### Security Fixes (v2.1.7)

| Fix | Description |
|-----|-------------|
| RT-2026-H1/H3 | Binary integrity hash verification before Agent launch (AgentWatchdog + self-restart + AntiTamperGuard) |
| RT-2026-M1 | Worker: nonce consumed AFTER HMAC verification (prevents DoS via pre-consumption) |
| RT-2026-M3 | WebDashboard: bearer from tray launch URL; Referer never grants access (closed in 2.2.0) |
| RT-2026-M4 | Worker: input validation on /report/hash, /report/url, /report/ip before upstream forwarding |
| RT-2026-M5 | Worker: removed X-Forwarded-For IP fallback, error message leak, updated to v2.1.7 |

### New Detection Capabilities (v2.1.7)

| Component | Category | Description |
|-----------|----------|-------------|
| `AmsiIntegrityCheck` | Anti-Tamper | Verifies AmsiScanBuffer/AmsiOpenSession prologues against startup baseline (detects VEH/breakpoint/patch AMSI bypass) |
| `EdrKillerDetectionMonitor` | Observe (v2.2.0) | Name-only LogOnly on known EDR-killer process names. Rename bypasses. Wired in 2.2.0. |
| `KernelModuleAuditMonitor` | SystemIntegrity | NtQuerySystemInformation(SystemModuleInformation) enumeration; detects stealth driver loads bypassing SCM events |
| `TokenPrivilegeAuditMonitor` | CredentialProtection | Enumerates processes holding SeDebugPrivilege/SeImpersonate from non-admin paths (potato attacks, token theft) |
| `HoneypotDllMonitor` | Anti-Tamper | Plants decoys in `{install}\honeypot\` (v2.2.0). Not next to Sentinel.exe. |
| `DecoyPipeMonitor` | Anti-Tamper | Creates secondary pipes with common C2 names; any connection = immediate Tier1 with process attribution |
| Critical response budget | Response | Chain-confirmed multi-signal detections bypass per-minute rate limit (separate unlimited budget) |

---

## Remaining Backlog

- [x] **Agent-side monitor documentation** - Inventory complete as of 1.7.5 (includes 1.7.4 PS ports).
- [x] **design.md <-> code parity (1.8.1)** - ActiveResponse model, proxy auth, NetworkIsolate ARP, quarantine ACL, BYOVD neutralize, consultant sticky LogOnly.
- [x] **NetworkIsolate ARP flush** - Restored as native P/Invoke (was shell `arp -d` in v5.9.0).
- [ ] **BrowserCredentialTheftRule** - Never a removed type; optional standalone rule (monitor already covers).
- [x] **Authenticated Service<->Agent IPC** - v2.0 HMAC-SHA256 auth with nonce replay prevention on named pipe (`ServiceAgentIpcHost`).
- [ ] **Installer per-file ACL race** - Upgrade still broad `takeown`/`icacls` window.
- [ ] **LSA/TPM third factor for entropy** - Cache/rule HMAC still MachineGuid + `.install_entropy`.
- [ ] **ThreatIntelFeedBlocker PID attribution** - `IPGlobalProperties` lacks PID; connection hits currently alert without owning process kill.
- [ ] **Threat intel cert pinning** - CIRCL/MB HTTPS use default system trust (Worker path is HMAC-auth).
- [ ] **KeyScrambler / FocusLock** - Intentionally not ported (AV heuristics / high operational cost).
- [ ] **Further unit tests** - More coverage still welcome for NamedPipe/RpcLateral/CloudSync/EtwProvider/BrowserC2 (partial coverage exists in V16x-V18x suites).
