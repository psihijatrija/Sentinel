# Sentinel - Threat Model

## Firewall defaults, policy stores, and monitoring (3.2.3)

The service manages PersistentStore and, when the OS exposes it, the local computer Group Policy store (`localhost`). It mirrors Sentinel's own process blocks into local Group Policy and inspects ActiveStore, including rule filters, enforcement status, profile settings, and BFE/MpsSvc health. It never writes a domain GPO. Effective domain exceptions, disabled/overridden profiles, missing rules, or non-enforced filters produce visible conflicts and a dashboard attention state instead of a protected claim. A trimmed image without a local GPO store uses PersistentStore; missing NetSecurity/PowerShell means policy management is unavailable and is reported, while COM self-block reconciliation and offline detection continue.

Inbound allow rules in both local stores are disabled and retained. Outbound allow rules and default outbound actions are preserved; Sentinel's own outbound self-blocks remain intentional. Firewall profiles are enabled and default inbound policy is Block in the two writable local stores. Exact DHCP-service UDP 68/67 and 546/547 rules are exempt. System-only ICMPv6 error/control types 1-4 and neighbour/router discovery 133-136 are exempt to preserve outbound IPv6; echo and arbitrary application ICMPv6 rules are not. The policy does not automatically enable an existing disabled essential rule.

Registry tree notifications trigger coalesced rechecks, with a 15-second polling fallback. These are detection/reconciliation intervals, not an atomic prevention guarantee: an unapproved exception may exist briefly before reconciliation. New exceptions and re-enabled unapproved exceptions are disabled again on refresh/restart. Windows changes cannot be reliably distinguished from manual changes from the Enabled flag, so opt-in is explicit. Approval is bound to the store, exact rule name, and complete filter identity; changed definitions lose approval. Privileged approval/revocation is not exposed over the user-session web/pipe API.

Administrators can approve an existing rule from an elevated terminal in the install directory:

```powershell
.\Sentinel.Service.exe --allow-inbound PersistentStore 'Exact-Rule-Name'
.\Sentinel.Service.exe --allow-inbound localhost 'Exact-GPO-Rule-Name'
.\Sentinel.Service.exe --deny-inbound PersistentStore 'Exact-Rule-Name'
```

The names are the rule `Name` identifiers, not translated display names or wildcard patterns. No new arbitrary rule or command is created by these operations. Windows Firewall UI can still disable an approved exception; enabling an unapproved exception there is temporary until the next reconciliation.

An ACL-protected, atomic rollback journal records original enabled/profile states before changing them, supports interrupted operations, and is serialized across service/administrator processes. Uninstall restores matching recorded original states and removes owned self-blocks; changed rule definitions are skipped and reported. `Sentinel.Service.exe --restore-firewall` is an elevated rollback command that first stops the service/watchdog. Starting Sentinel again resumes the baseline. Preserve the journal for recovery; a malformed/unsafe journal fails visibly rather than silently replacing the original state.

The fixed, embedded NetSecurity management script runs through an absolute Windows PowerShell path with no profile. Script text is embedded code; request/rule data travels as JSON, not command interpolation. Output, execution time, and pre-authentication pipe input are bounded. This management-only bridge is the reason PowerShell is used here: the firewall COM API does not offer the required policy-store selection. No online lookup is involved.

## Runtime exploit observation (3.2.3)

Existing ETW process/module, credential-access, injection, script, file, DNS, and network sensors remain active. A new bounded, passive cross-process rule correlates recent non-loopback networking with an evasive script child for all process identities, including Defender/security software, browsers, games, and OS hosts. It handles expiry/PID-reuse reset and emits Tier2 LogOnly context, never exploit proof or kill authority. Classic-port observations now cover browsers/games too and remain Tier2; a port alone is not a kill reason. Persistent-connection follow-up no longer omits recognized application identities, and child-spawn analysis requires actual parentage rather than coincident process start times.

Game/anti-cheat memory-handle safety restrictions remain. Protected/PPL processes, missing/stripped ETW providers, inaccessible memory, event loss, and unobservable exploits limit userland coverage. A signed image or trusted install path does not establish runtime safety. This release does not claim detection of every exploit or a patch for application/OS vulnerabilities.

## Offline operation and privilege boundary (3.2.3)

Sentinel no longer performs online reputation queries, DNS reputation lookups, live threat/KEV feed downloads, public-IP lookups, cloud connectivity probes, or automatic outbound threat/evidence reporting. Local behavioral telemetry, static/ML analysis, cached/local KEV catalogs, bundled ThreatFox indicators, and local evidence packs remain available. Missing external reputation is Unknown with a neutral score; old online reputation caches are not used. Bundled/cached intelligence becomes stale until supplied through a trusted local update. Legacy encrypted settings cannot re-enable online transports, and the embedded proxy credential has been removed.

The SYSTEM service installs and reconciles six fixed, executable-scoped Windows Firewall block rules: inbound and outbound for Sentinel.Service.exe, Sentinel.Agent.exe, and SentinelAutoRotate.exe, on Domain/Private/Public profiles, for non-loopback IPv4/IPv6 traffic including LAN/link-local destinations. Loopback is excluded from the blocks because an allow rule cannot override a matching block. Rule identifiers remain stable across upgrades, and uninstall removes only these identifiers. Firewall failures or disabled profiles are logged as errors and retried every minute; local detection continues without falsely claiming network enforcement. The service must run with installation/admin privileges to manage these rules. Authenticode verification uses cached URL data only.

The Agent uses an explicit asInvoker manifest and refuses SYSTEM/elevated-administrator execution. The service watchdog checks the session token and selects its limited linked token where necessary; if no suitable token exists it refuses an elevated launch. The Agent applies only its own process mitigations, writes logs/restart state to user-owned storage by default, and delegates privileged operations to the service. Module UI requests schedule service inspection rather than directly quarantining a browser-supplied file path. Certificate requests retain the service's explicit distrust-list authorization. If the service is unavailable these operations fail without an elevated fallback. No generic command execution, arbitrary privileged file-write/delete, or response-disable operation is exposed.

The privileged service still contains system sensors and the response engine: this is not yet a minimal standalone privilege broker. Splitting ETW/native sensors and response execution from the rest of analysis is future work and requires its own protocol and authorization review. Agent-only operation has reduced visibility and response capability. The existing service IPC now denies network-logon access, bounds input to 16 Ki characters before JSON/auth parsing, and disconnects stalled request readers after five seconds; HMAC, freshness, replay checks, and the operation allowlist remain in place.

These controls reduce exposure; they do not confine an already-compromised SYSTEM process. Such a process can potentially alter firewall rules or use other processes/OS services. Malicious local files, telemetry, dependencies, and IPC remain attack surfaces. The localhost dashboard is still active and authenticated. There is no longer an off-host evidence mirror; administrators can destroy local evidence. No kernel/PPL boundary is claimed.


**Version: 3.0.4**

This document assumes the attacker has read the source code.

## Historical implementation notes

Versioned subsections below record earlier behavior, not additional current response authority. In 3.2.2, certificate trust-marker absence became Tier2 review-only; only explicit thumbprint distrust authorizes certificate mutation. In 3.2.3, online transports and automatic off-host mirroring were removed. The current controls above and [requirements](requirements.md) take precedence.

### Certificate-store observations and mutation authority (current)

A trusted-store certificate can affect TLS and signed-code trust, but its presence, Subject/Issuer strings or absent OS trust markers do not establish hostile installation or malicious use. `RootStoreGuard` inventories existing certificates as well as later changes. Missing AuthRoot/OS trust markers yield Tier2 LogOnly review findings.

Autonomous removal, Disallowed insertion and associated file quarantine require an exact thumbprint in the explicit `CertDistrustList`, with the existing mutation policy and file protections. The remediator refuses heuristic-only requests. Historical list entries for three legitimate Microsoft roots were removed; old logs are not authorization to distrust them again. Local administrative rights and incomplete telemetry remain limits, and recorded action labels alone do not prove final store state.

### v2.8.2 - a new network adapter appearing ("attacker adds his network to mine")

Answers a direct user question: can an attacker just add their network to yours? The layer-2/3
variants (rogue DHCP, evil-twin, ARP, rogue PAC) were already covered by `ArpSpoofMonitor`,
`WifiSecurityMonitor`, `WpadProxyMonitor`, the DNS validators, and `RouteTableMonitor`. But the
*on-host* first step - a new network adapter appearing (USB Ethernet, a second Wi-Fi NIC, or an
overlay/VPN virtual adapter like WireGuard/Tailscale/OpenVPN) - was a silent gap: `NetworkInterfaceGuard`
baselined physical adapters only to re-enable one that went *down*, never diffed for **additions**,
and `RouteTableMonitor` deliberately excludes virtual adapters. Windows itself surfaces no
user-visible event for a new adapter, so nothing recorded it. Now `NetworkInterfaceGuard` baselines
the full adapter set (physical + virtual) at startup and emits **`Network: New Adapter Appeared`**
(Tier2 / `LogOnly` observe-fuel, confidence 0.45 physical / 0.55 overlay-VPN, overlay/VPN flagged not
excluded) for any adapter added afterwards. It is **never auto-removed** - a new dongle is a
legitimate admin action. Its value is composition: the new-adapter signal and the pre-existing
`Network: Default Gateway Changed` signal are now `IsNetworkTamperFuel` with distinct vector labels
(`NewAdapter`, `Gateway`), so either one alongside an independent ARP/DNS/route tamper reaches the
`Network Tamper: Local MitM Chain` VPN-shield composite. **Honest ceiling:** a local admin can always
add an adapter (a legitimate OS operation needing exactly the privilege they'd already have, per B1);
Sentinel does not and cannot prevent it - it makes the addition visible, durably recorded, and able
to corroborate a MitM chain. Prevention for the LAN-side variants lives on the network (WPA3, 802.1X,
DHCP snooping), not in a userland host agent.

**v2.8.3 route/gateway follow-up.** Two `RouteTableMonitor` blind spots from the 2.8.2 audit are now
closed, both Tier2/observe-fuel: a new **non-default route** (previously only the `0.0.0.0/0` default
and `/32`-netmgmt host routes were recorded - a more-specific `/24` that shadows a subnet's path was
silently baselined) emits `Network: New Route Added`; and a gateway on a **secondary adapter**
(gateway detection formerly inspected only the first adapter, missing a rogue second-NIC gateway or
DHCP lease) emits `Network: Additional Gateway Appeared`. Both feed the MitM composite as independent
`Route` / `Gateway` vectors. Same ceiling: routes and gateways are added legitimately by DHCP / VPN /
multi-homing, so these observe and corroborate - they do not prevent or revert.

### v2.6.8 - silent / user-directed harm, and state-baseline reconciliation

Addresses a threat class that every prior Sentinel defense structurally misses. Every terminal
family (credential theft, C2, ransomware, injection-then-exfil) is defined around harm to the
**system or its secrets**, and kill authority requires qualifying terminal behavior. Consider instead a module whose only purpose is to harm the **user**: it
emits an audio / hypnotic stream, flickers the screen, or otherwise degrades sleep and wellbeing.
It makes no network connection, touches no credentials, destroys no files, and may be signed with
a **stolen but validly-chaining** certificate. It produces *zero* terminal telemetry and it never
escalates - the steady state *is* the attack. behavioral terminal classification cannot establish malicious intent from that alone, and signature-based trust is defeated by the stolen cert. Neither of Sentinel's existing
axes - behavior, or provenance - is sufficient alone against an attacker who deliberately closes
both doors.

The one thing such a payload cannot avoid is **persisting somewhere** - it must be a module mapped
into some process. So v2.6.8 adds a third, **state-driven** axis: `StateReconciliationMonitor`
(SystemIntegrity group, 5-min cadence). It keeps a **reboot-durable** baseline
(`ModuleBaselineStore`, plain `System.Text.Json` under `%ProgramData%\Sentinel\baseline`, SYSTEM+
Admins ACL - deliberately NOT the boot-bound `SecureCacheStore`, which would re-flag every module
each reboot) of the loaded-module set of a fixed list of **long-lived, low-churn** processes
(`explorer`, `winlogon`, `services`, `lsass`, `csrss`, `dwm`, `sihost`, `taskhostw`,
`runtimebroker`). On each pass it diffs the live module set against the baseline and runs every new
module through **attribution** - the diff is cheap; attribution is the whole product. A delta is
suppressed if it has a trusted load position (`ModuleIdentity.Evaluate` - OS-servicing, keep-tree,
signed Program Files, Roslyn analyzer shadow-copy, GPU ICD, app-directory), if a Windows servicing
actor is/was recently active (`ServicingWindow`), or if its Authenticode signer CN was **already
accepted on this host** (a per-machine first-seen-publisher ledger - the one signal a *stolen* cert
cannot fully launder, because even a valid cert is "new to this host" the first time). Only a delta
that survives all of these is surfaced.

Attacker-relevant honesty (this is the honest ceiling, not a claim of coverage):

- Everything surfaced is **Tier2 / `ResponseAction.LogOnly`, `Family = null`** - observe-only,
  never auto-killed. Reconciliation introduces no new response action and no host mutation. `pid`
  inspection honors the `CanInspect` gate (PPL / anti-cheat skipped, never clobbering
  `MappedModuleCache`).
- The signal is worded for **review, not attribution of intent**. It says "an unexplained module
  appeared in a normally low-churn process; review it." It explicitly does **not** identify who
  placed the module, and it does **not** assert that anyone is monitoring or targeting the user - a
  userland tool sees a module, not an operator, and cannot confirm surveillance. Over-claiming here
  would be worse than silence.
- Reconciliation **raises the attacker's cost and shrinks the blind spot** - an unexplained module
  injected into a low-churn system/shell host is surfaced regardless of what harm it delivers - but
  it does **not** deterministically stop user-directed harm. A payload loaded into a **high-churn**
  host (a browser, a game, an Electron app that legitimately loads many third-party modules) can
  blend into that churn and is out of scope for surface #1. And a validly-signed module that never
  behaves terminally is surfaced for **human review**, not killed - because auto-killing on
  provenance alone is exactly the identity-based response the constraints forbid, and because a
  destructive false positive is a real cost. If the surfaced module later *does* something terminal,
  the durable "unexplained since X" observation is re-emitted on cadence so the correlation layer
  can chain it - it never self-confirms a kill on its own.

Also in v2.6.8: the local-network-tamper (VPN-shield) composite now counts **independent** tamper
vectors, not just distinct rule-name labels - a single root observation (e.g. one gateway MAC
change stamped with a shared `ObservationKey`) can no longer masquerade as two independent vectors
and self-confirm a MitM chain; the network monitors stamp `ObservationKey` so co-derived signals
collapse to one leg. And the Roslyn build-server analyzer shadow-copy path
(`VBCSCompiler\AnalyzerAssemblyLoader`) is recognized in `ModuleIdentity` - gated on the loading
host being a genuine Microsoft SDK binary - so ordinary .NET builds no longer trip foreign-path DLL
quarantine (a real false positive that was quarantining Microsoft/xUnit source-generator DLLs).

### v2.6.3 - update/servicing-surface abuse observation

Addresses a user question that generalizes to a real threat class: "can something malicious ride in through the Windows update / CAB servicing path?" Sentinel deliberately does **not** try to validate whether an update is genuine - that is impossible from userland and, for a truly Microsoft-signed CDN-delivered payload (Flame-tier certificate forgery), invisible to any userland tool. Instead `UpdateServicingMonitor` (CoreDetection group, 12s poll) watches what the servicing surface *does*, honoring "behavioral signals only for kill authority": it flags a servicing actor (`TrustedInstaller`/`tiworker`/`wusa`/`dism`/`dismhost`/`expand`/`extrac32`/`pkgmgr`) spawning a shell / LOLBin / credential tool, CAB/MSU extraction to a path outside the legitimate WinSxS/servicing/Temp staging (the CVE-2021-40444 `..\` path-traversal class), a binary named as a servicing actor that is unsigned or not Microsoft-signed (`SignerTrustService.GetSignerName`, folded through `AdjustConfidence`), and plain-HTTP or non-Microsoft WSUS / `AutoConfigURL`-style update sources (the WSUSpect on-path class). Every one of these is emitted **Tier2 / `ResponseAction.LogOnly`** (`KillAuthorized` stays false, `Family` left null so `ResponsePolicy.ClassifyTerminalOutcome` never treats it as kill-grade); the monitor never self-authorizes a destructive action. Its value is composition: it does not re-observe file writes or service registration (that would duplicate `FileActivityMonitor` and `RegistryMonitor`, which already emit those and are servicing-path-aware via `IsServicingProcessActive()`), it contributes the servicing-context observe leg that the correlation layer chains with a `RegistryMonitor` driver/service drop or a subsequent beacon/credential-access leg to reach a confirmed composite. Attacker-relevant honesty: this catches malware *behaving* like post-exploitation once a servicing actor is involved (rogue WSUS, LOLBin extraction, a "signed" package that misbehaves, a BYOVD driver dropped around a servicing event - `TerminalFamily.Byovd`, terminal but never solo kill-grade). It does **not** and cannot catch a genuinely Microsoft-signed backdoor delivered over the real Windows Update CDN; that is out of scope for any userland IDS and would require Microsoft's own signing infrastructure to fail. Legitimate servicing - a clean cumulative update installing via `TrustedInstaller`, NTLite/DISM offline image work, a UUP dump conversion - produces no anomalous child, no abnormal extraction path, and Microsoft-signed binaries, so it emits nothing.

### v2.6.0 - protective VPN shield for confirmed local-network MitM

Closes the *exposure window* during a local man-in-the-middle attack. Sentinel already detected and cleaned the individual tampers (ARP poisoning via `ArpSpoofMonitor`, DNS hijack via the DNS validators, route injection via `RouteTableMonitor`, adapter bridging + DNS lock via `NetworkInterfaceGuard`, rogue WPAD/PAC via `WpadProxyMonitor`, Wi-Fi deauth / evil-twin via `WifiSecurityMonitor`), but the user's traffic still rode the hostile path between detection and cleanup. `BehavioralCorrelationEngine` now correlates these PID-0 SYSTEM signals in a dedicated host-wide buffer and emits `Network Tamper: Local MitM Chain` when **>= 2 distinct tamper vectors** (`ARP`, `DNS`, `Route`, `Bridge`, `AdapterDown`, `WPAD`, `WiFiDeauth`, `WiFiEvilTwin`) land within the correlation window - a single vector never self-confirms, and WPAD (a `WeakObserveSeed`) still also feeds the existing `WPAD Proxy Hijack Chain`. The composite authorizes the new **`ResponseAction.VpnShieldUp`** (non-kill; ordered below `KillProcess` so `KillAuthorized` stays false). `VpnShieldEngine` raises a userland RAS VPN tunnel (`rasapi32` - `RasDial`/`RasEnumConnections`/`RasHangUp`; a visible Windows VPN connection, no kernel driver, no self-hiding, honoring the transparency constraint), asks `NetworkInterfaceGuard` to clean the path, verifies clean for `CleanSweepsRequired` consecutive sweeps, then drops the tunnel. **Fail-safe:** if the path cannot be *verified* clean the tunnel STAYS UP; on `MaxShieldSeconds` expiry the incident is escalated and the tunnel is held - never silently dropped. Attacker-relevant properties: the whole path is gated on explicit `VpnShield.Enabled` (`ProductPosture.AllowsVpnShield`, default off) and a confirmed multi-vector chain, so it is not a speculative trigger an attacker can weaponize into forced tunneling; chain confirmation never rewrites `VpnShieldUp` into a process nuke (`ApplyTierLaw` / `PromoteChainConfirmedFields` preserve it), so a spoofed PID-0 network signal cannot escalate into killing a process. A trusted `ProviderProfile` is preferred; VPN Gate public relays are a caveated last-resort fallback only when `UseVpnGateFallback` is set and no trusted profile exists - the incident log records that a volunteer relay replaces a local attacker with a remote unknown one and is not equivalent to a trusted tunnel. Process-level threats (C2 beaconing, DoH exfil, covert mesh/webhook) are deliberately NOT routed here - a tunnel would merely carry the malicious traffic; those remain kill/isolate.

### v2.3.5 - script-dropper MOTW + WPAD/PAC proxy hijack (DHCP Option 252)

Two delivery-vector gaps closed. **(1) Script-class droppers.** `MotwBypassMonitor` previously only checked PE files in delivery folders for a missing `Zone.Identifier`. A drive-by or XSS-forced download that drops a `.hta`/`.js`/`.vbs`/`.wsf`/`.ps1`/`.lnk`/`.chm` detonates via WSH/mshta/batch without ever being a PE, so it slipped the PE-only check. The scan now also flags script-class droppers missing MOTW (`CveCoverageHeuristics.IsScriptDropperExtension`) as `CVE Class: Script Dropper Missing Mark-of-the-Web` (Tier2/LogOnly weak observe). Because the correlation engine keys `hasMotwDelivery` on `Contains("Mark-of-the-Web")`, the new signal feeds the existing `MOTW Bypass Execution Chain` automatically when it correlates with a LOLBin, script, or C2. **(2) WPAD/PAC.** DHCP does not deliver JavaScript, but DHCP **Option 252** delivers a *PAC URL*, and a PAC file is JavaScript (`FindProxyForURL`) that the WinHTTP/WinINET auto-proxy resolver executes to route traffic. A rogue DHCP server or malware that sets `AutoConfigURL` can MITM every browser and leak visited hosts even for HTTPS. `WpadProxyMonitor` baselines the current PAC config (a pre-existing corporate PAC does not fire), then emits on a post-startup PAC change, a remote/IP-literal PAC, or WPAD auto-detect + remote PAC - all Tier2/LogOnly. Correlated with C2/exfil it promotes to the `WPAD Proxy Hijack Chain` composite (0.9). Neither monitor reverts the proxy setting or kills - corporate PAC and game ISOs are legitimate; these are observe fuel that only escalate on a corroborating execution or callback leg. This is a userland delivery/observe sensor: it does not patch the DHCP client (CVE-2026-62755 class) and does not stop a PAC-engine memory-corruption RCE - patch the OS for that.

### v2.3.4 - module identity spans all loadable extensions

`DllUnloadEngine` enumerates every mapped PE via `EnumProcessModules` (`NativeProcessMemory.EnumModules`) **regardless of file extension**, then runs each through `ModuleIdentity.Evaluate`. Identity is path + Microsoft-family signature, never extension. So a foreign / user-writable-drop / non-keep-tree module is unloaded whether it is a `.dll`, a managed `.winmd` (WinRT metadata that carries MSIL), an `.ocx`, `.cpl`, `.ax`, `.node`, `.drv`, `.acm`, `.tsp`, `.mui`, or `.efi`. System-provided `.winmd` is pure metadata and stays keep-tree. `ModuleIdentity.ModuleExtensions` / `IsModuleFileName` and `DllUnloadEngine.IsLoadableModuleFileName` make the filename-keyed helpers extension-aware so a non-`.dll` module is never silently treated as "not a module". Search-order hijack names (`dbghelp`/`version`/`winmm`/...) remain the classic `.dll` set (`SideloadTargets`); those specific names are only sideloaded as `.dll`. Ceprkac's in-process/child `InjectedModuleCleaner` mirrors this: `IsBundledFileName` now keeps bundled `Microsoft.*.winmd` / `System.*.winmd` (WinUI/WinRT), and `IsSideloadFileName` matches the hijack base name against any loadable-module extension. No change to the unload primitive (FreeLibrary-APC) or the protected-host / OS-servicing / game skips.

### v2.2.8 - WMI triple + policy rewrite

Permanent WMI persistence is `__EventFilter` + EventConsumer + `__FilterToConsumerBinding`, not a consumer name. `WmiPersistenceMonitor` snapshots that triple in `root\subscription` and `root\default`. Hostile CommandLine/ActiveScript consumers are a `WmiPersistence` terminal. `WmiPolicyRewriteMonitor` attributes `SOFTWARE\Policies` hive changes to WmiPrvSE / wmiadap / scrcons (StdRegProv). WMI-Activity ETW 5859-5861 is the fast path. `wmiadap.exe` is module-scanned like WmiPrvSE. Name-only new consumers stay observe fuel.

### v2.2.5 - module identity, not count

A remote inject is a mapped PE that does not belong. `ModuleIdentity` allow/deny and `DllUnloadEngine` FreeLibrary-APC immediately (permanent Tier1). Hijack-name plants (`dbghelp.dll` next to Chrome **or** a Steam game) are quarantined **on drop** so search order cannot bind them. Module *count* is not a signal. Games are not VM_READ (Denuvo) - in-memory inject into a live game is a residual gap. Never FreeLibrary lsass/csrss/wininit/DISM/NTLite.

### v2.1.2 - battle hackers, keep play/browse working

Work-first defaults: HID auto-disable is kiosk-only; Steam/Xbox/Store/DirectX/OBS are work surface; Hell's Gate and unmapped-thread scanners require a real stub table / compact shellcode page. Weak browse/play heuristics cannot complete a chain nuke. MitMDefense does not unlock arbitrary host mutation.

### v2.2.4 - generic CVE-class (userland)

Named campaigns lag. New sensors hunt exploit-host / MOTW / MSI / winget / VS Code / isolation-FS *shape* so the next AFD sibling does not require a new Dream Job pack. Local/cached CISA KEV entries produce asset-match candidates, without verified affected-version applicability. Missing or stale catalogs are not proof of patch compliance. Kernel races still need the OS CU.

### v2.8.6 - CLFS + token-integrity-jump LPE, kill-on-success

Adds two userland-observable local-privilege-escalation surfaces, wired to fire **only when the
escalation succeeds** - never on touching an interface or matching a signature (that would kill the
legitimate software an attacker hides behind, and an attacker controls the signature). Userland
cannot patch these kernel primitives; apply OS updates.

| Capability | Role | Not a substitute for |
|------------|------|----------------------|
| TokenIntegrityMonitor (integrity jump) | User-session process from a user-writable image now holding a **SYSTEM-integrity token** - the footprint of a completed LPE. Kill-grade `TokenTheft` (Tier1). | The kernel/driver LPE patch itself |
| ClfsExploitationMonitor | CLFS Base Log File (`.blf`) dropped in a staging path outside the legit CLFS/TxR trees (CVE-2025-29824-class). **Observe-only** (Tier2/WeakObserveSeed) - a drop is not proof. | The `clfs.sys` patch |

Composite: `CLFS Privilege Escalation Chain` / `CVE Exploit + Privilege Gain Chain` - a CLFS `.blf`
leg (or a confirmed integrity jump) correlated with a same-actor privilege gain / CVE-exploit leg
becomes an instant Tier1 `QuarantineAndKill`. Scoped so it does not intercept the pre-existing
`Kernel Exploit Loader Chain` / `Installer / Package Manager EoP Chain`. The token integrity level
is a fact the process cannot fake without actually holding the token - behavioral, not name/path.

### v2.2.3 - August 2026 CVEs (userland, honest about the kernel)

Does **not** patch `afd.sys` (CVE-2026-68820). Coverage is the Lazarus Operation Dream Job chain around that bug, KEV patch toast, LegacyHive hive-load, and Cloud Files / ShieldBreak hydration.

| Capability | Role | Not a substitute for |
|------------|------|----------------------|
| DreamJobCampaignMonitor | SecurityPDF, libmupdf sideload, FudModule names, Troy C2 IOCs | KB5121003 / UBR 9168 |
| KEV posture toast | Win11 26100/26200 UBR below 9168 (LogOnly + toast) | Installing the cumulative update + reboot |
| LegacyHiveMonitor | Another user's hive loaded / custom HKU (CVE-2026-62832) | The User Profile Service patch |
| CloudFilesHydrationMonitor | Unknown CfApi sync roots; placeholders in staging (CVE-2026-62713 / ShieldBreak) | Cloud Files Mini Filter patch; does not disable OneDrive |

Composites: `Lazarus Dream Job Chain`, `LegacyHive Privilege Escalation Chain`, `Cloud Files Hydration Tamper Chain`.

### v2.2.9 - Embedded web dashboard in native window

Tray Settings opens `AgentDashboardForm` containing an embedded `WebBrowser` control pointed at `WebDashboardService` (`http://localhost:19845`). Bearer token auth prevents other local processes from accessing the API. The HTTP listener binds only to localhost. No external browser is launched.

### v2.2.2 - Settings was native WinForms (reverted in v2.2.9)

Tray Settings opened `AgentDashboardForm` (WinForms panels). No browser, no `http://localhost`. The web dashboard listener was not started.

### v2.2.1 - tray opens a real browser

Windows 11 with a broken `http` protocol association showed "We can't open this 'http' link" when Settings was clicked. The tray launched Edge/Chrome/Firefox instead of ShellExecute on the URL. Superseded by v2.2.2 native Settings.

### v2.2.0 - advertised controls actually run

Dashboard bearer is no longer bypassed by a spoofed Referer. V217 monitors (AMSI integrity, honeypot DLLs in a dedicated folder, decoy pipes, kernel module audit, token privilege audit, EDR-killer **name observe**) are registered. Game-path reputation skip refuses user-profile trees. ChainTracer does not treat `Windows\Temp` as OS-critical. Hardened-mode LGPO no longer turns audit and password quality off.

### v2.1.8 - red team audit hardening + dirty tricks

Security fixes: binary integrity verification before agent launch (Authenticode + SHA-256 baseline); AntiTamperGuard detects binary replacement (not just deletion); Worker nonce consumed after HMAC verification; WebDashboard bearer token auth (**completed in 2.2.0** - 2.1.8 Referer shortcut was not auth); Worker input validation; chain-confirmed detections bypass kill rate limit.

New detection capabilities (code existed in 2.1.8; **wired in 2.2.0**):

| Capability | Role | Bypass requires |
|------------|------|-----------------|
| AmsiIntegrityCheck | Detects AMSI/ETW function prologue patching | Kernel-level memory modification (BYOVD) |
| EdrKillerDetectionMonitor | **Name-only observe fuel** (LogOnly, not President's Law). Catches default tool names. | Rename the binary (always) |
| HoneypotDllMonitor | Decoy DLLs in `{install}\honeypot\` (never next to Sentinel.exe) | Not touching that folder |
| DecoyPipeMonitor | C2 honeypot named pipes (default CobaltStrike/Metasploit names) | Using non-standard pipe names for C2 |
| KernelModuleAuditMonitor | NtQuerySystemInformation detects stealth BYOVD loads; logs pre-existing RTCore64/WinRing0 | Already having kernel control to hide from NtQSI |
| TokenPrivilegeAuditMonitor | SeDebugPrivilege/SeImpersonate from user-writable paths | Running from a non-user-writable path (Program Files) |

### Phase A coverage expansion (v2.1.0)

Additional **userland** sensors for campaigns that use local privilege escalation after foothold:

| Capability | Role | Not a substitute for |
|------------|------|----------------------|
| LpeScaffoldMonitor | Potato-class tools, elevated staging PEs | Kernel LPE patches (e.g. afd.sys CVE) |
| InitialAccessMonitor | Browser/Office -> LOLBin, staging LOLBins | Email/web content filtering |
| PersistenceSurfaceMonitor | IFEO, accessibility, Winlogon, COM hijack | Full registry integrity product |
| WU posture | Disabled AU / stale updates / **KEV UBR** (LogOnly + toast) | Installing the cumulative update |

Composites: `LPE Campaign Scaffold`, `Initial Access Execution Chain`, `Persistence + Abuse Channel` (chain-confirmed with corroboration).

### Audience (v2.0.8+)

- **Gamers / creators:** Always-on hardening; game and anti-cheat paths are not reputation-kill fuel; memory handles skipped on known game trees. Real terminal chains (C2/exfil/token/cred-dump/BYOVD) still authorize response.
- **High-profile targets:** Dual audit trail + sealed incident packs. Userland limits still apply: local admin / novel kernel implants can win. Pair with Defender, Secure Boot, HVCI and operator-controlled independent/offline evidence copies; no endpoint proxy connection remains.
- **Honest battle stance:** Sentinel is meant to fight real operators on real desktops - not to market "unhackable."

---

## Digital coercion / surveillance toolkit (v1.9.4)

**Mission:** Protect users from **endpoint tools** commonly used to control, watch, or take over a PC in online harassment, sexual coercion, stalkerware, account takeover, and remote blackmail.

**In scope (host behaviour):**

| Toolkit | Examples of signals | Composite / response |
|---------|---------------------|----------------------|
| Covert surveillance | Screen capture, webcam, keystroke-class monitors | + remote/C2 -> `Covert Surveillance + Remote Channel` |
| Remote control | Reverse shell, RDP abuse, AnyDesk/TeamViewer-class from staging | + network -> `Remote Control Abuse Toolkit` |
| Session / account theft | Browser/OS credential stores, token theft, CDP/extension abuse | + network/exfil -> `Session Theft + Abuse Channel` |
| Stalkerware | Surveillance + autorun/persistence | `Stalkerware Persistence Chain` |
| Classic malware | C2, ransomware, BYOVD, injection | Existing composites (unchanged) |

**Out of scope (explicit):**

- Reading Discord / social / email message content  
- Identifying a person as a "rapist" or sexual offender  
- Moderating speech or ban-list scraping  
- Proving offline sexual assault  
- Stopping abuse that never touches the victim's Windows host  

**Platforms:** Platform-agnostic. Messaging, social, email, browsers, games, voice/video, remote-support - anything that leaves process, file, registry, or network traces on Windows.

**Evidence:** Coercion-tagged packs include a technical section stating what Sentinel asserts vs does not assert, plus optional affidavit checkboxes the **victim** completes (remote control, recording, session theft, threats/coercion). Sentinel never auto-files with police.

**Honesty for users:** Settings -> **Safety** page. Product language must not overclaim.

---

## Windows Event Log + barebone Windows (v1.9.5)

| Capability | Full Windows | Stripped / custom image |
|------------|--------------|-------------------------|
| JSONL `events.jsonl` | Primary trail | Primary trail (required) |
| Windows Event Log Application/Sentinel | Secondary trail (critical IDs) | **Auto-disabled** if create/write fails |
| Unified ETW | ~50 ms sensors | Falls back to WMI/poll |
| User alerts | Local dashboard/tray state; no Win32 toast calls | Local JSONL/dashboard where available |
| Online TI proxy / feeds | Removed in 3.2.3 | Removed; local/cached data only, potentially stale |

Attacker wiping only Event Log does not erase JSONL packs. Attacker wiping JSONL may still leave Event Log IDs 1100/1200 if the service was up. Neither is a substitute for offline backups of packs.

---

## Trust Boundaries

```

 KERNEL (ring 0)                                         
   - Sentinel has NO kernel component                    
   - Active driver can suppress userland (but Sentinel   
     detects the ENTIRE chain leading to driver load:    
     priv esc -> cert plant -> .sys drop -> service create) 
   - v1.7.0: Planted signing certs are auto-revoked     

                          

 SYSTEM (ring 3, highest userland privilege)              
   - Sentinel service runs here                          
   - ETW providers, full process access                  
   - SecureCacheStore, quarantine, firewall rules        

                          

 ADMINISTRATOR (ring 3, elevated)                        
   - Can stop/delete services via SCM                    
   - Can take ownership of SYSTEM files                  
   - Can load drivers (BYOVD)                            

                          

 STANDARD USER (ring 3)                                  
   - Cannot touch Sentinel service or files              
   - Sentinel agent (watchdog) runs here                 
   - Limited telemetry (WMI fallback, no ThreatIntel)    

```

---

## Monitor Coverage Summary (v2.2.0)

See [design.md](design.md) for the full component inventory (all MonitorGroups + Agent). Key additions since v1.4.5:

- **DriverLoadMonitor** (v1.5.0) - BYOVD detection + cert-tracing (v1.7.0)
- **BrowserC2Guard** (v1.6.8) - Headless Chrome proxy, CDP hijacking, extension integrity
- **NativeMessagingHostGuard + LocalControlChannelMonitor + DangerousBrowserFlagRule** (v2.7.1) - Site-to-local-app hijack/pairing: native-messaging bridge planting, loopback control-channel driving of browser-like apps, dangerous launch flags on any process
- **EtwThreatIntelMonitor expanded** (v1.6.8) - Unbacked RWX region detection
- **EtwThreatIntelMonitor call-stack analysis** (v2.9.0) - ETW-TI STACKWALK capture on the Threat-Intelligence provider; flags return frames in committed, executable, non-image (unbacked) memory at a sensitive syscall (T1055). Catches in-memory / living-off-the-land execution that leaves no file artifact, even when every loaded module is signed. Off-thread classification (no callback-thread cost); emits Tier1/LogOnly evidence into the correlation chain.
- **SyscallStubMonitor expanded** (v1.6.8) - Hell's Gate / indirect syscall detection
- **PrintSpoolerMonitor expanded** (v1.6.8) - PrintNightmare-class exploitation
- **WslMonitor expanded** (v1.6.8) - Container-to-host lateral movement
- **WfpIntegrityMonitor** (v1.6.8) - WFP filter tamper detection
- **WmiProviderIntegrityMonitor** (v1.6.6) - Malicious WMI provider DLLs
- **ConnectivityCanaryMonitor** - EDRSilencer detection
- **EtwSessionGuard** (v1.6.1) - Self-healing ETW session
- **EtwProviderTamperMonitor** - EtwEventWrite patch detection
- **ThreatIntelFeedBlocker** (v1.7.4) - Spamhaus/Feodo/ET IP blocklists
- **LnkShortcutMonitor** (v1.7.4) - Real-time malicious shortcut guard
- **AgenticProcessMonitor** (v1.8.2) - AI coding agent / MCP toolchain abuse
- **PackageRuntimeMonitor** (v1.8.2) - Package-manager runtime + AI config poison
- **AsrPolicyGuard** (v1.7.5) - Self-healing Defender ASR Block rules
- **RemoteSessionGuard** (v1.7.5) - Force-logoff unauthorized RDP/remote sessions
- **HostsFileGuard forum.hr block** (v2.6.9) - forum.hr + subdomains blackholed at hosts-file level plus a wildcard NRPT rule (`.forum.hr` -> 0.0.0.0) covering all subdomains (reinfection vector); `ForumHrWatchMonitor` removed
- **Observe-first posture (v1.8.3)** - Weak path/port/shell heuristics LogOnly; IPSec attack-only by default; `RestrictivePortHardening` for full lockdown
- **MitmDefense suite (v2.0.1)** - Opt-in post-incident: planted root cert remove, FCM Send-Tab-to-Self block, ghost process -> fake Chromecast kill, rogue Cast FW (subject to MITM-specific response authorization)
- **GpuProcessMonitor** (v2.1.5) - GPU sandbox escape + crypto-mining detection
- **WebDashboardService** (v2.1.3) - Local web-based settings UI replacing WinForms
- **ScanEngine** (v2.1.3) - On-demand comprehensive system security scan
- **AmsiIntegrityCheck** (v2.1.8 code / **registered v2.2.0**) - AMSI/ETW function prologue integrity monitoring
- **EdrKillerDetectionMonitor** (v2.2.0) - Known EDR-killer **process-name observe** (LogOnly; rename bypasses)
- **HoneypotDllMonitor** (v2.2.0) - Decoy DLL tripwires in `{install}\honeypot\` (not the exe directory)
- **DecoyPipeMonitor** (v2.2.0) - C2 honeypot named pipes (default CobaltStrike/Metasploit names)
- **KernelModuleAuditMonitor** (v2.2.0) - NtQuerySystemInformation stealth driver detection; logs pre-existing BYOVD-capable modules
- **TokenPrivilegeAuditMonitor** (v2.2.0) - Dangerous token privilege enumeration
- **WebDashboardService** (v2.2.0) - Bearer from tray `?token=` only; Referer is not auth; `/ws/events` requires the token

### Group 1: Critical (Self-Protection)
| Monitor | Purpose |
|---------|---------|
| SyscallStubMonitor | Detects ntdll unhooking/tampering |
| IPSecIntegrityGuard | Detects IPSec policy tampering |
| AsrPolicyGuard | Detects/re-applies demoted ASR Block rules |

### Group 2: Core Detection
| Monitor | Purpose |
|---------|---------|
| DiskWideDllScanner | Finds DLLs planted outside trusted directories |
| DllEntropyAnalyzer | Detects packed/encrypted DLLs |
| DllLoadFailureMonitor | Watches event log for suspicious load failures |
| ModuleValidationMonitor | Checks loaded DLL integrity via hash |
| RuntimeModuleIntegrityMonitor | Verifies loaded module paths |
| ScriptExecutionMonitor | PowerShell/WMI/AMSI bypass/SAM extraction/script drops |

### Group 3: Network Integrity
| Monitor | Purpose |
|---------|---------|
| ArpSpoofMonitor | Detects ARP cache poisoning |
| DnsResponseValidationMonitor | Retired in 3.2.3; no active DNS validation |
| PublicIpMonitor | Retired in 3.2.3; no public-IP queries |
| WifiSecurityMonitor | Detects open/WEP networks |
| RemoteAccessMonitor | Detects RAT indicators (RDP, VNC, etc.) |
| PhantomDeviceMonitor | Detects unauthorized network devices |

### Group 4: System Integrity
| Monitor | Purpose |
|---------|---------|
| FirewallIntegrityMonitor | Detects firewall rule tampering |
| SecureBootIntegrityMonitor | Checks Secure Boot state |
| ScheduledTaskMonitor | Detects new/modified scheduled tasks |
| TlsCertificateMonitor | Detects unauthorized root CA installations |
| RootStoreGuard | Reviews missing trust markers as Tier2 LogOnly; only explicit thumbprint distrust policy authorizes certificate mutations and associated file actions |
| UacBypassSurfaceMonitor | Detects autoelevate binary abuse |

### Group 5: Credential Protection
| Monitor | Purpose |
|---------|---------|
| CanaryFileMonitor | Honeypot files in sensitive directories |
| BrowserCredentialGuard | Chrome/Edge/Firefox credential theft detection |
| MicrosoftAccountGuardMonitor | Watches for MS account token access |
| NullSessionGuard | Detects null session enumeration |
| BuiltinAdminGuard | Detects enabled/exploited built-in Administrator |
| RemoteLogonHardeningGuard | Denies network/RDP logon for local admin accounts; clears auto-logon leak (v2.7.6) |

### Group 6: Peripheral & Environmental
| Monitor | Purpose |
|---------|---------|
| BluetoothMonitor | Detects new unknown Bluetooth devices |
| PhantomDeviceMonitor | Detects unauthorized network peripherals |
| DeviceInstallMonitor | New device driver installations |
| MtpTransferGuard | Blocks non-media writes to portable devices |
| VolumeMountMonitor | RAM disks, SUBST, VHD, VeraCrypt mounts |
| CastDeviceGuard | Blocks unauthorized Cast/screen-share devices |
| WslMonitor | WSL execution evasion detection |
| RawDiskAccessMonitor | Direct disk I/O bypass detection |
| PrintSpoolerMonitor | Print spooler exfiltration detection |
| SandboxEscapeMonitor | Container/sandbox escape detection |
| HardwareSecurityGuard | TPM, Secure Boot, BitLocker, Credential Guard |
| UsbHidWhitelist | BadUSB/Rubber Ducky defense |
| PhysicalAccessMonitor | Post-idle hardware change correlation |

### Standalone Monitors (not grouped)
| Monitor | Purpose |
|---------|---------|
| FileActivityMonitor | Real-time file system change tracking |
| EtwProcessMonitor | Process creation/termination via ETW |
| EtwThreatIntelMonitor | Kernel-level API observation |
| GhostProcessMonitor | Detects orphan/invisible processes |
| NetworkMonitor | TCP connection tracking and C2 detection |
| RegistryMonitor | Registry change monitoring |
| BeaconingDetector | Statistical C2 beacon detection |
| RansomwareIoMonitor | Shadow copy + bulk encryption detection |
| TokenIntegrityMonitor | Privilege escalation detection |
| MemoryBehaviorAnalyzer | RWX/shellcode pattern detection |
| DataExfiltrationMonitor | Large outbound data transfer detection |
| NetworkInterfaceGuard | Bridge/adapter tampering detection |
| AcousticThreatMonitor | Microphone access monitoring |
| WebcamHijackMonitor | Camera access monitoring |

---

## Bypass Scenarios (Known)

### B1: Attacker has local admin

**Attack:** `sc stop "Sentinel"` or `taskkill /f /im SentinelService.exe`

**Mitigation:**
- Agent watchdog detects stale heartbeat and attempts restart
- Service registry key ACL'd to deny Administrators delete (partial)
- ServiceProtectionMonitor detects SCM tampering

**Durable-evidence-survival additions (v2.5.8):**
- **Stop classification (alert-before-suppression).** `ShutdownContext` records whether the
  process is stopping for a legitimate reason (cooperative SCM stop via `StopAsync`, OS shutdown
  via `IHostApplicationLifetime.ApplicationStopping`, upgrade, uninstall). The `AntiTamperGuard`
  exit hook (`WriteLastGasp`) reads it: an **expected** stop is recorded as a normal lifecycle
  event; an **unexpected** exit (e.g. `taskkill`, or an SCM stop that never routed through the
  cooperative path) is recorded as `SERVICE_STOP_SUSPECTED` in the append-only audit trail plus a
  Tier1 `AntiTamper` **LogOnly** detection when the engine is still reachable. The coverage gap
  becomes evidence instead of silence.
- **Offline evidence only (3.2.3).** Automatic off-host mirroring has been removed. Local evidence packs and the audit chain remain, but no off-host survival is claimed.

**Residual risk:** HIGH. A local administrator can suppress the service and delete local evidence. Firewall self-blocks do not prevent an already-compromised SYSTEM process from changing host policy.

**Honest assessment:** If the attacker has admin and knows Sentinel is running, they can kill it.
The watchdog adds seconds of delay, not a security boundary. Unexpected stops can leave local tamper evidence, but 3.2.3 does not mirror it off-box. An administrator can erase every local copy.

---

### B2: BYOVD (Bring Your Own Vulnerable Driver)

**Attack:** Load a signed vulnerable driver, use it to kill Sentinel from kernel.

**Mitigation:**
- `DriverLoadMonitor` detects Event 7045 (service install), registry service creation, and .sys drops in user-writable paths every 15s
- Embedded blocklist of 35+ known vulnerable driver hashes (Microsoft WDBL + LOLDrivers)
- Known vulnerable driver filenames flagged even without hash match
- High-confidence matches (hash or name+non-standard-path) -> `KillProcessTree` + service disable/delete via native SCM
- **v1.7.0 cert-tracing:** Extracts Authenticode cert from detected driver -> checks if cert was planted in TrustedPublisher/Root stores -> if NOT a public CA, fires `RemoveCertAndKillAdder` (revokes cert, kills installer chain, scans for other drivers signed by same cert)
- Prerequisite monitoring: privilege escalation, UAC bypass, token manipulation all detected before attacker reaches the point of driver installation
- `SecureBootIntegrityMonitor` detects test signing mode / kernel debug enabled
- `WfpIntegrityMonitor` detects WFP filters blocking Sentinel/EDR processes
- Memory Integrity (HVCI) monitoring - alerts if disabled

**Residual risk:** MEDIUM. Sentinel wins the race in most scenarios because it monitors the prerequisites (priv esc, file drop, service creation, cert planting). If an attacker has admin, bypasses all prerequisite detections silently, uses an unknown driver not on the blocklist signed by a legitimate public CA (not a planted cert), AND loads it faster than the 15s poll - then the driver can suppress Sentinel. Remote alerting fires before suppression in most cases.

**v2.2.0 additions:**
- `KernelModuleAuditMonitor` is **registered** and detects driver loads via `NtQuerySystemInformation` every 30s (LogOnly). Pre-existing RTCore64/WinRing0 at start is logged, not silently trusted.
- `EdrKillerDetectionMonitor` is **registered** as name-only **observe fuel** (LogOnly). A rename still bypasses it; DriverLoadMonitor / kernel audit cover the load.
- `DriverLoadMonitor` scans **interactive user profiles**, not SYSTEM's LocalAppData. Event 7045 PID is used when `> 4`.
- Chain-confirmed detections bypass kill rate limit - budget exhaustion no longer shields the attacker.

---

### B3: ETW blinding

**Attack:** Patch `ntdll!EtwEventWrite` or `ntdll!NtTraceEvent` in Sentinel's process to suppress telemetry.

**Mitigation:**
- EtwTamperingRule detects known patching patterns
- Self-protection monitors for DLL injection into own process
- CIG (Code Integrity Guard) audit prevents unsigned DLL load
- **v2.1.8:** `AmsiIntegrityCheck` captures EtwEventWrite prologue at startup and compares every 30s - detects memory patching at 0.97 confidence

**Residual risk:** MEDIUM. Direct syscall patching bypasses userland hooks. Sentinel now detects the patch AFTER it happens (prologue comparison), but cannot prevent it if attacker is already in-process with write access to ntdll pages.

---

### B4: Reputation cache poisoning (FIXED in v1.1.0)

**Attack (pre-1.1.0):** Attacker running as SYSTEM writes a "safe" verdict for their payload into the SecureCacheStore.

**Mitigation (v1.1.0+):**
- HMAC key incorporates installation entropy - requires SYSTEM access to forge
- DPAPI machine-scope encryption - file is unreadable on another machine
- ACL restricts to SYSTEM + Administrators only
- Unknown verdicts are not cached (re-checked next scan cycle)

**Residual risk:** LOW. An attacker with SYSTEM access can do far more damage than forging cache entries.

---

### B5: Process name/path spoofing

**Attack:** Rename malware to match allowlisted process names.

**Mitigation:**
- Detection rules use behavioral signals, not process names
- Allowlist uses full path verification (binary must reside under legitimate directory)
- Self-exclusion checks normalize paths with `Path.GetFullPath()`
- **v2.8.0:** `FullPathParentChildRule` (SENT-003) - the parent-spoof variant of this attack
  (malware named `winword.exe` spawning a shell) is now verified against the parent's **real
  image path** from the ancestry cache (the path the OS recorded at process creation, not
  attacker-controllable), and **fails closed**: a parent whose real path is not in a legitimate
  install location, or cannot be verified, is reported rather than skipped. Prior to v2.8.0 this
  rule checked the *child command line* for the install-path fragment and failed open, so a
  spoofed parent escaped. Still Tier2/LogOnly - it feeds correlation; auto-kill needs chain confirm.
- **v2.8.1:** two remaining name/path-only allow-lists now require an Authenticode-signature anchor.
  `UnsignedBinaryRule` (Tier2) only clears a "trusted" AppData install dir / Temp installer prefix
  when the binary is signed - an unsigned drop into a folder that merely contains the trusted
  substring stays observe-fuel. `DllSideloadingDetectionRule` (Tier1) no longer lets the developer-
  build path exclusion (`\bin\debug`, `\bin\release`, `.nuget`) blanket-bypass its kill: the skip
  applies only to signed binaries, so an unsigned system-tool-named impostor dropped in a dev path
  is caught.

**Residual risk:** LOW. Path-based verification prevents simple rename attacks; parent-path
verification and the AppData/dev-path allow-lists now combine with a non-attacker-controllable
signature anchor and fail closed.

---

### B6: Command-line obfuscation

**Attack:** Encode/obfuscate command-line arguments to bypass token matching.

**Mitigation:**
- Encoded PowerShell detection (base64 patterns)
- Multi-signal correlation (cmdline + network + memory = composite)
- ETW ThreatIntel provides kernel-level API observation regardless of cmdline

**Residual risk:** MEDIUM. Sophisticated tooling can avoid command-line exposure entirely. MemoryBehaviorAnalyzer and ETW ThreatIntel cover this gap.

---

### B7: DLL sideloading into Sentinel process

**Attack:** Place a malicious DLL in Sentinel's search path.

**Mitigation:**
- ProcessHardening.ApplyOrFail() at startup: restricts DLL search to System32 only
- NTFS ACL lockdown on installation directory
- Directory watcher deletes unauthorized files and kills writing processes
- CIG audit mode prevents unsigned DLL loads
- **v2.2.0:** `HoneypotDllMonitor` plants decoy `version.dll`, `winmm.dll`, `dbghelp.dll`, `WINHTTP.dll` in `{install}\honeypot\` only. Planting those names next to `Sentinel.Service.exe` would be a self-sideload / self-DoS. Access or deletion of the decoy folder is LogOnly anti-tamper fuel.

**Residual risk:** LOW if CIG is enforced. MEDIUM if CIG is audit-only. The honeypot folder is an early tripwire for directory scanners; it is not a kill trigger.

---

### B8: Time-of-check-to-time-of-use (TOCTOU) on file hashes

**Attack:** Swap a file between when Sentinel hashes it and when it executes.

**Mitigation:**
- Hash checks happen at process-start time (ETW event)
- File is already mapped into memory by the time we hash it
- Quarantine reads, encrypts, then deletes atomically

**Residual risk:** LOW. Race window is milliseconds.

---

### B8b: Installer / shell false kills (FIXED in v1.6.2)

**Attack surface (pre-1.6.2, operator self-DoS):** Legitimate software installs and Windows shell behavior were classified as high-severity threats and chain-quarantined:

1. **PPID spoof on Inno Setup** - Git for Windows / Chrome extractors (`innosetup-*.tmp`) race ETW vs kernel parent PID -> Kill + ChainTracer quarantine of the signed installer.
2. **Raw disk on explorer / taskhostw** - Shell holds `\Device\HarddiskVolume*` / disk handles; catalog-sign verify could fail -> KillProcessTree on system binaries.
3. **ChainTracer empty path** - Critical process names with unresolved image path were treated as non-system -> kill/quarantine.
4. **Signed quarantine** - Any chain path could wipe Authenticode-valid installers (Git, ChromeSetup, even SentinelSetup).

**Mitigation (v1.6.2+):**
- `InstallerHeuristics` + PPID skip for Inno/NSIS extractors and signed installer parents
- `RawDiskAccessMonitor` never kills critical hosts under `%SystemRoot%`; volume-root LogOnly; PhysicalDrive kill only for unsigned non-Windows paths
- `ChainTracer` preserves critical names when path empty; preserves signed installer ancestors
- `QuarantineManager` refuses signed files unless force (cuckoo/sideload)
- Ephemeral prefetch noise suppressed for GIT/INNOSETUP/DOTNET/setup patterns

**Residual risk:** LOW for official signed installers. Unsigned portable tools in Temp may still draw LogOnly or, if also holding PhysicalDrive, kill. True PPID spoof malware that is unsigned remains kill-authorized.

---

### B8c: Parallel quarantine path / OS binary wipe (FIXED in v1.6.3)

**Attack surface (pre-1.6.3, operator self-DoS):** ChainTracer skipped System32/SysWOW64 quarantine, but `AdvancedResponseEngine` always called `IncidentResponseService.CollectEvidenceAsync` *before* ChainTracer. That path quarantined `MainModule` with no OS-path gate. Combined with AMSI "no amsi.dll" -> KillProcessTree on stock PowerShell (catalog-signed verify fail-open), production deleted `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

**Mitigation (v1.6.3+):**
- `QuarantineManager` hard-refuses OS-critical paths (`IsOsCriticalPath`); force flag cannot override
- Signature-check exceptions fail closed under Windows / Program Files
- `IncidentResponseService` skips OS-critical paths before quarantine
- System PowerShell hosts missing amsi.dll -> LogOnly only (not kill)
- USB failed-enumeration Tier1 + auto-disable; trusted VID:PID allowlist

**Residual risk:** LOW for System32 hosts. Impostor `powershell.exe` outside system paths can still be killed. Catalog verify failures on non-Windows paths may still quarantine unsigned drops (intended).

---

### B9: Behavioral baseline poisoning (FIXED in v1.5.9)

**Attack:** Malware achieves persistence (e.g., scheduled task) and runs 10+ times over days to earn "established" status in `BehavioralBaselineService`. Once established, all future detections receive a -10 to -20 score reduction, potentially dropping below the kill threshold.

**Mitigation (v1.5.9+):**
- `IsEstablishedProcess()` requires ZERO detection events for the process name within a 7-day window
- `ScoringEngine.Score()` records every detection via `RecordDetectionForProcess()`, permanently revoking established status
- Detection records age out after 7 days with no new detections (allows recovery from one-time false positives)
- Total baseline/trust reduction is capped at -20 regardless (v1.3.0)

**Residual risk:** LOW. A process that has EVER fired a detection cannot earn baseline trust.

---

### B10: ActiveResponse config tampering (FIXED in v1.5.9 / v1.6.0)

**Attack:** Attacker injects config to set `ActiveResponse=false`, neutering all kill/quarantine/isolate responses while Sentinel continues running (appearing functional but inert).

**Mitigation (v1.5.9+ / v1.6.0):**
- `AntiTamperGuard` monitors `ActiveResponse` flag every ~10s
- Transition from true->false fires Tier1 anti-tamper detection (confidence 0.99)
- **v1.6.0:** Boot-time `ActiveResponse=false` is force-enabled in `StartAsync` and alerted on first integrity tick
- Disk JSON is not a config source (compiled defaults + `config.enc` only)
- **v1.6.0:** `EnforceActiveResponse` (default true) policy; set false only for intentional observation mode
- ActiveResponse is forcibly re-enabled immediately upon detection
- The alert is immune to the ActiveResponse flag (uses LogOnly response type)

**Residual risk:** LOW. Requires `EnforceActiveResponse=false` (operator choice) or kernel/SYSTEM ability to patch the process image.

---

### B11: Supply-chain C2 via signed binary (FIXED in v1.5.9)

**Attack:** Compromise a legitimate software update (SolarWinds-style). The signed binary is installed in Program Files, passes all trust checks (Authenticode + protected path + baseline + diversity). Its C2 beaconing gets demoted to LogOnly, maintaining an unblocked communication channel.

**Mitigation (v1.5.9+):**
- `BeaconingDetector` never demotes confirmed statistical beaconing below `NetworkIsolate`
- Even maximum trust score (signed + protected path + diversity + baseline) only achieves `NetworkIsolate` - C2 IP is always firewall-blocked
- C2Beaconing added to President's Law - cannot be suppressed by user allowlisting
- DLL sideloading check invalidates Authenticode trust for compromised processes

**Residual risk:** MEDIUM. The C2 channel is blocked, but if the attacker uses a legitimate CDN/cloud endpoint as C2 (domain fronting), the NetworkIsolate may block legitimate traffic to that IP too. The detection still fires and is logged regardless.

---

### B12: Dynamic rule injection (FIXED in v1.5.9 / v1.6.0)

**Attack:** Attacker deletes the `.install_entropy` file (used for HMAC key derivation), then drops a malicious JSON rule file into the `rules/` directory. Previously, missing entropy caused HMAC verification to be skipped (fail-open), allowing arbitrary unsigned rules to load. Local admins could also read entropy and forge valid HMACs.

**Mitigation (v1.5.9+ / v1.6.0):**
- `DynamicRulesEvaluator` now fails CLOSED - missing HMAC key rejects all rules
- **v1.6.0:** `.install_entropy` ACL is SYSTEM-only (Administrators cannot read signing material)
- **v1.6.0:** Rules directory write is SYSTEM-only; Admins/Users are read-only
- Entropy file deletion itself would require SYSTEM access

**Residual risk:** LOW. Requires SYSTEM (or taking ownership of the entropy file) to forge signed rules.

---

### B13: Legacy standalone proxy forgery

The historical Worker used shared-secret HMAC, timestamp/nonce checks and rate limiting. Current endpoint transports, client credentials and automatic evidence mirroring were removed in 3.2.3, so the endpoint does not expose this connection.

The retained `worker/` server is deployed independently. Its evidence route stores minimal manifest/checkpoint anchors, not raw incident summaries or host/process details; it returns a storage receipt, not an independently trusted origin signature. Local Worker tests do not establish a live deployment. A separately deployed server and its account administrator remain outside the endpoint's trust boundary. See [Worker documentation](../worker/README.md).

### B14: Kill-storm / response weaponization (FIXED in v1.6.0)

**Attack:** Induce many false positives to make Sentinel kill large numbers of processes.

**Mitigation (v1.6.0+):**
- `MaxKillsPerMinute` (default 15) rate-limits kill and quarantine-kill actions
- Expanded protected process list (Defender / Sense / smartscreen) with path verification
- Excess kills demoted to LogOnly with a rate-limit response event
- **v2.1.8:** Chain-confirmed multi-signal detections bypass the per-minute rate limit entirely. An attacker who floods false positives to exhaust the budget can no longer prevent Sentinel from killing chain-confirmed threats.

**Residual risk:** LOW. NetworkIsolate has its own separate budget. Chain-confirmed kills are unlimited. Only single-signal kills are rate-limited.

---

### B15: Evading honeypots and decoy detections (v2.2.0)

**Attack:** Attacker reads the source, identifies decoy pipe names and `{install}\honeypot\` filenames, and avoids them.

**Mitigation:**
- Honeypot DLLs catch untargeted sideload scanners that probe every subdirectory
- Decoy pipe names catch default C2 configs
- These are defense-in-depth - NOT the primary detection mechanism

**Residual risk:** LOW for targeted attackers (they'll just avoid). Useful against automated tools.

**Honest assessment:** Honeypots detect lazy attackers. Skilled operators who read the source skip the known pipes and the `honeypot\` folder. EDR-killer **process names** are the same class of control (rename bypasses).

---

## What Sentinel CANNOT Protect Against

Fundamental limitations, not bugs:

1. **Kernel-level attacks with novel implants** - No visibility below ring 3. Default (v1.8.3) IPSec is **attack-only** (Telnet/rsh/classic RAT ports; Remote Registry/Telnet services off) so users keep SSH/RDP/SMB. Full port/service lockdown is opt-in (`RestrictivePortHardening: true`). DEP/SEHOP/Spectre mitigations and ASR still apply.
2. **Hardware implants** - No firmware/UEFI visibility (but detects Secure Boot disabled)
3. **Pre-boot attacks** - Sentinel starts after Windows boots (detects boot config tampering)
4. **Attacker with physical access + offline disk** - Can boot from USB, modify disk (but detects post-idle hardware changes)
5. **Attacker already running as SYSTEM** - Can kill Sentinel (watchdog adds delay only)
6. **Encrypted C2 over legitimate ports** - Looks like normal HTTPS (but TLS cert monitor detects rogue CA installations; beaconing detector catches statistical patterns)
7. **Direct syscalls from custom code** - Bypasses ntdll hooks (SyscallStubMonitor detects unhooking attempts; v1.6.8 Hell's Gate in-memory pattern detection scans for syscall stubs in non-image regions)
8. **GPU memory-resident malware** - Code in GPU VRAM/compute shaders has no CPU-side memory to scan
9. **Physical-layer Wi-Fi attacks** - Cannot see deauth frames directly (detects rapid disconnects)

---

## What Sentinel CAN Detect Even Against Skilled Attackers

Hard-to-bypass detections (require kernel access to evade):

1. **Parent PID spoofing** - ETW reports kernel truth; can't be faked from userland
2. **Credential harvesting** - Canary credential is a zero-FP tripwire
3. **Ransomware** - Shadow copy deletion + bulk encryption is behaviorally unavoidable
4. **ntdll unhooking** - Stub integrity check detects the modification itself
5. **Privilege escalation** - Token integrity transitions are observable regardless of method
6. **Process injection (kernel ETW)** - API calls observed at kernel level
7. **Phantom keystrokes (SendInput)** - Blocked globally via WH_KEYBOARD_LL
8. **Credential Guard disablement** - LsaIso.exe absence + registry state change
9. **Hardware security downgrade** - TPM/SecureBoot/BitLocker state monitored every 5 minutes

---

## Detection Confidence Levels

| Detection | vs Commodity Malware | vs Targeted Attacker |
|-----------|---------------------|---------------------|
| Ransomware (shadow copy + bulk rename) | HIGH | HIGH |
| Credential canary (honeypot) | HIGH | HIGH |
| Parent PID spoofing | HIGH | HIGH |
| Phantom keystrokes (SendInput) | HIGH | HIGH |
| Parent-child anomaly (Office->shell) | HIGH | HIGH |
| SAM hive extraction (reg save) | HIGH | HIGH |
| EDR-killer tool detection (name-based) | HIGH | MEDIUM |
| AMSI bypass (amsi.dll patched) | HIGH | HIGH |
| LSASS dump (dbghelp.dll load) | HIGH | MEDIUM |
| Syscall stub integrity | HIGH | MEDIUM |
| Token integrity escalation | HIGH | MEDIUM |
| Process injection (ETW ThreatIntel) | HIGH | MEDIUM |
| Credential Guard disablement | HIGH | MEDIUM |
| Hardware security downgrade | HIGH | MEDIUM |
| Decoy pipe connection (C2 honeypot) | HIGH | LOW |
| Honeypot DLL access (sideload probe) | HIGH | LOW |
| PowerShell Script Block patterns | HIGH | MEDIUM |
| Kernel module load (NtQSI baseline) | HIGH | MEDIUM |
| Token privilege from user-writable path | HIGH | MEDIUM |
| Memory behavior (RWX/shellcode) | MEDIUM | MEDIUM |
| DNS DGA detection | MEDIUM | MEDIUM |
| BadUSB/unauthorized HID | HIGH | MEDIUM |
| Suspicious script file drops | MEDIUM | LOW |
| C2 beaconing (statistical) | HIGH | MEDIUM |
| DNS tunneling | MEDIUM | LOW |
| File entropy | LOW | LOW |
| Campaign IOCs | MEDIUM | LOW |

---

## Design Principles

1. **Behavioral over static** - Detect what processes DO, not what they ARE
2. **No security theater** - If it doesn't work against a competent attacker, document limitations
3. **Assume the attacker reads the code** - No security-by-obscurity
4. **Layered defense** - Sentinel is ONE layer alongside Defender, not a replacement
5. **Kill only on corroboration** - Multiple Tier2 signals correlating produce composite kills. Single signals never kill independently (except self-protection)
6. **Honest documentation** - State what works and what doesn't

---

## Closed Vulnerabilities

See CHANGELOG.md for full history. Key fixes:

- **v2.2.0:** Dashboard bearer is actually required (Referer ignored; token not in GET /; WS authenticated). V217 monitors **registered**. Game-path reputation skip refuses user-profile trees. ChainTracer System32/SysWOW64 only. Watchdog publisher pin + install-path liveness. DriverLoadMonitor user-profile scan. Kiosk LGPO no longer disables audit/passwords/FIPS. Worker RATE_LIMITER after HMAC. Encrypted config HMAC envelope. President's Law no longer includes DnsAnomaly/NetworkAnomaly.
- **v2.1.8:** Binary integrity before agent launch (RT-2026-H1/H3); AntiTamperGuard SHA-256 replacement detection; Worker nonce-after-HMAC (RT-2026-M1); Worker input validation (RT-2026-M4); chain-confirmed budget bypass (RT-2026-M2). Six monitors were **written** here and **wired in 2.2.0**. Dashboard "bearer auth" in 2.1.8 was a Referer shortcut (closed in 2.2.0).
- **v2.6.9:** Restored the forum.hr hosts-file block (reinfection vector); removed the useless `ForumHrWatchMonitor` and its DNS-feed wiring.
- **v1.7.6:** Removed opinionated forum.hr hosts block; added `ForumHrWatchMonitor` for non-browser C2/relay abuse of that site alone. **(reverted in v2.6.9)**
- **v1.7.5:** ASR Block self-heal (`AsrPolicyGuard`), remote session force-logoff (`RemoteSessionGuard`), install-time credential/browser residual hardening. Documentation inventory parity with runtime registration.
- **v1.7.4:** ThreatIntelFeedBlocker (Spamhaus/Feodo/ET), real-time `LnkShortcutMonitor`, Agent scareware/cursor/cookie ports.
- **v2.7.1:** Site-to-local-app hijack/pairing protection: `NativeMessagingHostGuard` (native-messaging bridge planting), `LocalControlChannelMonitor` (loopback control-channel driving of any browser-like app), `DangerousBrowserFlagRule` (dangerous launch flags on any process). Covers browser-like apps outside the mainstream-browser name set.
- **v1.7.0:** BYOVD cert-tracing: `DriverLoadMonitor` now extracts Authenticode cert from detected drivers, checks TrustedPublisher/Root stores, revokes planted non-public certs via `RemoveCertAndKillAdder`, scans System32\drivers for other drivers signed by same identity. Closes the fake-Chromecast-CA / planted-cert BYOVD attack chain.
- **v1.6.9:** IDE false-positive kill prevention: V8 JIT code matching syscall-stub patterns no longer kills Electron IDEs; ChainTracer preserves IDE host ancestors; AdvancedResponseEngine IDE host protection demotes to LogOnly for non-President's-Law rules.
- **v1.6.8:** BrowserC2Guard (headless Chrome proxy + CDP hijack + extension integrity), EtwThreatIntelMonitor RWX detection, SyscallStubMonitor Hell's Gate patterns, PrintSpoolerMonitor PrintNightmare exploitation, WslMonitor container-to-host lateral movement, Named Pipe + Beaconing and Token + Lateral composite detections.
- **v1.6.3:** OS self-DoS closed: `QuarantineManager` + `IncidentResponseService` hard-refuse OS-critical paths (production FP deleted System32 `powershell.exe` after AMSI false positive). System PowerShell AMSI demotion to LogOnly. Failed USB enumeration Tier1 + auto-disable; `TrustedUsbDevices` allowlist.
- **v1.6.2:** Installer/shell false-positive remediation (ProgramData evidence): PPID spoof no longer kills Inno Setup extractors; Raw Disk Access never kills explorer/taskhostw under Windows; ChainTracer preserves critical hosts with empty path and signed installer ancestors; QuarantineManager refuses Authenticode-signed files by default; EphemeralProcessMonitor ignores installer prefetch noise; shared InstallerHeuristics
- **v1.6.1:** EtwSessionGuard (heal stopped ETW session), NetworkIsolate rate limit + budget Tier1 alerts, ClickFix/FakeCAPTCHA rule expansion, NpmSupplyChainRule
- **v1.6.0:** Audit remediation: threat-proxy server-side HMAC (no client key), ActiveResponse boot-time force, SYSTEM-only entropy, rules dir write SYSTEM-only, kill rate limit, protected AV processes, native SCM driver disable, Cast IP validation, tray LOLBin removal
- **v1.5.9:** 7 false-positive/false-negative fixes: supply-chain beaconing gap (C2 never LogOnly), signed injector quarantine prevention, C2 back in President's Law, ActiveResponse tamper detection, baseline poisoning prevention, dynamic rules fail-closed, svchost correlation bypass
- **v1.4.5:** LSA secret storage for auto-logon, Credential Guard monitoring, ScriptExecutionMonitor (PowerShell/AMSI/SAM/script drops), Tier1+Tier2 correlation fix, Agent code placement cleanup
- **v1.4.4:** 15 red-team findings fixed (command injection, handle leaks, HMAC weakness, socket exhaustion, installer race conditions)
- **v1.1.0:** Cache poisoning, process name spoofing, self-exclusion bypass
- **v1.0.1:** RAM disk staging, WSL evasion, raw disk bypass, print spooler exfil, sandbox escape


## Reliability and investigation changes (pending release)

Sensor progress is separate from supervisor task liveness. A running task is not proof
that a provider is available or a collection cycle succeeded. Uninstrumented monitors
remain Unknown. Native ETW query results, provider enable status, loss counters, exact
queue evictions, queue age and processing waits are observable. Zero ETW events alone
is not proof of tampering. Missing providers on custom/debloated Windows degrade
coverage; they do not authorize response or certify a clean endpoint.

Read-only root-certificate/network inventories retain the previous snapshot when a
collection fails. Context identifiers group observations; they never authorize trust,
exclusions, automatic baseline acceptance or changed hardening. Root observations record
presence/fingerprint and observation time, not a proven installer or actor. CurrentUser
stores refer to the account running the service, not all interactive users. Hashing
network configuration reduces plaintext exposure but is not a promise of anonymity.

A companion daily audit hash chain can expose changed/reordered records. Trusted
checkpoints retained independently are necessary to expose truncated suffixes or rewritten
history. A machine administrator controlling every copy can still replace evidence.
Incident-summary anchoring is optional and requires configured off-host KV storage;
local tests do not establish remote durability. A shared-key receipt proves neither
incident truth nor integrity against the remote account owner. Audit integrity degrades
explicitly if the chain cannot be written/verified or reaches its daily size cap.

Replay is offline weighted-correlation evaluation. It cannot issue host actions, run
plugins or reproduce telemetry that was never captured. Restores use a write-ahead
journal, non-overwriting staging and read-back verification, and retain the encrypted
vault. Recovery inspection is read-only; it never trusts a journal to authorize replay,
delete evidence or run restored files. Process termination remains irreversible.

Redacted bundles are derived evidence. Their manifest checks content consistency,
not original origin/custody. Timestamps and behavioral categories remain sensitive;
preview exports before sharing them.


## Limits demonstrated by operational logs

Certificate metadata and absent OS trust markers do not establish hostile installation or authorize removal. A named pipe scanner can itself connect to a honeypot; client/server PID attribution must distinguish that observer effect. Shared-vendor or substring software matches do not establish CVE applicability. Exclusive event writer ownership and separate agent/service chains prevent accidental interleaving, but neither authenticates a user-writable agent log nor proves collection completeness. Unavailable ETW providers and uninstrumented monitor progress remain visibility limits; these corrections do not claim to repair that coverage.

## DNS coverage limits

In the published 3.2.2 build, the cross-validator probes cloudflare.com against 1.1.1.1 over ordinary UDP and compares IPv4 /16 subnets. This is heuristic evidence, not an authenticated independent view; interception of both paths, same-subnet manipulation, IPv6-only behavior and domains outside the probe can evade it. Critical-domain resolution shifts can also reflect legitimate infrastructure changes.

In the 3.2.3 offline implementation, DnsCrossValidator and DnsResponseValidationMonitor are no-op compatibility types and are not active DNS-answer validation. Local adapter DNS-change monitoring and baseline restoration remain. A startup baseline is not proof that the resolver was trustworthy, and the static NameServer check is not complete DHCP or router-state validation. Browser DNS policy enforcement does not independently authenticate the OS resolver. Sentinel does not repair router firmware, authenticate DHCP or verify Wi-Fi password strength.
