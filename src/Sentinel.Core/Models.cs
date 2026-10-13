using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    public enum DetectionTier
    {
        Tier1Behavioral,
        Tier2Indicator
    }

    public enum ResponseAction
    {
        LogOnly,
        NetworkIsolate,
        RemoveCert,
        /// <summary>
        /// v2.6.0: Raise a protective userland VPN tunnel as a temporary shield during a
        /// confirmed local network-tamper incident (ARP/DNS/route/bridge MitM), then clean
        /// the network and drop the tunnel once the path is verified clean. Non-kill,
        /// non-destructive to processes - a network-integrity remediation. Ordered BELOW
        /// KillProcess so <see cref="DetectionEvent.KillAuthorized"/> stays false for it.
        /// </summary>
        VpnShieldUp,
        KillProcess,
        KillProcessTree,
        Quarantine,
        QuarantineAndKill,
        RemoveCertAndKillAdder,
        RemoveRegistryEntry,
        DismountVolume
    }

    public enum SignalType
    {
        Generic,
        LsassAccess,
        AmsiTampering,
        EtwTampering,
        Ransomware,
        ReverseShell,
        NetworkC2,
        CredentialTheft,
        ProcessInjection,
        SuspiciousProcess,
        AntiTamper,
        SecurityEvasion,
        PhantomKeystroke
    }

    public class CveShieldConfig
    {
        public bool Enabled { get; set; } = true;
        public string FeedUrl { get; set; } = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        public int PollIntervalHours { get; set; } = 4;
        public string? CustomFeedPath { get; set; } // Local fallback JSON for offline testing
    }

    /// <summary>
    /// Post-incident MITM hardening - cert plant + FCM tab injection + fake Chromecast C2 relay.
    /// Observed chain (2026-06-13/14):
    ///   1. Plant self-signed root (CN=WINDOWS-PC / long validity) -> TLS intercept
    ///   2. Steal Chrome sync tokens during intercept window
    ///   3. "Send Tab to Self" via FCM push (TCP 5228) opens attacker URLs in open Chrome
    ///   4. Rogue LAN device (e.g. 192.168.1.100, OUI B0-B3-69) on Cast :8009 as C2 relay
    ///      through the browser's open Cast/tab channel
    /// </summary>
    public class MitmDefenseConfig
    {
        /// <summary>
        /// Master switch for the suite. v2.9.4: ALWAYS TRUE - no off switch. Setter is a no-op
        /// (retained for deserialization compatibility) so a planted config or a caller cannot
        /// disable MitM defense. This machine sustained the 2026-06 MitM chain (planted root ->
        /// TLS intercept -> Chrome token theft -> FCM "Send Tab to Self" -> rogue Cast :8009 C2
        /// at 192.168.1.100 / OUI B0-B3-69) and a device at that IP is still live on the LAN.
        /// </summary>
        public bool Enabled { get => true; set { } }

        /// <summary>
        /// Remove high-confidence planted MitM roots. v2.9.4: ALWAYS TRUE - no off switch.
        /// </summary>
        public bool RemovePlantedCerts { get => true; set { } }

        /// <summary>
        /// Block Google FCM TCP 5228 - severs "Send Tab to Self" after token theft.
        /// v2.9.4: ALWAYS TRUE - no off switch.
        /// </summary>
        public bool BlockFcmPushChannel { get => true; set { } }

        /// <summary>
        /// Auto firewall-block rogue Cast / fake Chromecast devices when detected.
        /// v2.9.4: ALWAYS TRUE - no off switch.
        /// </summary>
        public bool AutoBlockRogueCast { get => true; set { } }

        /// <summary>
        /// MAC OUI prefixes treated as cast-spoof / known hostile (normalized XX-XX-XX).
        /// B0-B3-69 is Shenzhen SDMC, historically spoofed as "Google Chromecast" in-incident.
        /// </summary>
        public string[] RogueCastMacPrefixes { get; set; } = { "B0-B3-69" };

        /// <summary>
        /// Explicit rogue Cast / MITM relay IPs. v2.9.4: seeded with 192.168.1.100 - the
        /// confirmed attacker relay from the 2026-06 incident on this host, still answering on
        /// Cast :8009 (SDMC OUI B0-B3-69). Re-added after CHANGELOG 2857 cleared it for clean
        /// installs; this machine is not a clean install.
        /// </summary>
        public string[] KnownRogueCastIps { get; set; } = { "192.168.1.100" };
    }

    /// <summary>
    /// v2.6.0: Protective VPN-shield remediation for confirmed local network tampering.
    ///
    /// When a network-tamper incident is chain-confirmed (rogue gateway / ARP poisoning,
    /// DNS hijack, route injection, adapter bridging), Sentinel can raise a userland VPN
    /// tunnel as a TEMPORARY shield so the user's traffic is encrypted and routed off the
    /// hostile local path while the network is cleaned (unbridge, restore DNS, drop rogue
    /// routes). Once the path is verified clean, the tunnel is dropped.
    ///
    /// Design invariants:
    /// - Userland only. The tunnel is a standard RAS/VPN dial (visible in Task Manager,
    ///   the network list, and event logs). No kernel driver, no self-hiding. Honors the
    ///   product's transparency constraint.
    /// - Fail-safe: if the network cannot be VERIFIED clean, the tunnel STAYS UP. The whole
    ///   point is to protect the user until the path is trustworthy.
    /// - Opt-in: <see cref="Enabled"/> defaults false. Clean installs do nothing here.
    /// - Never speculative: only fires on a confirmed network-tamper chain (routed through
    ///   the same observe-until-chain / MitmDefense gate as the rest of the MITM suite).
    /// </summary>
    public class VpnShieldConfig
    {
        /// <summary>
        /// Master switch. v2.9.4: ALWAYS TRUE - no off switch. Setter is a no-op. On a
        /// confirmed network-tamper chain the protective VPN shield engages and cannot be
        /// disabled from config. NOTE: to actually shield, configure a trusted
        /// <see cref="ProviderProfile"/>; without one there is no tunnel to raise (fail-safe:
        /// the incident is still reported, traffic is not silently routed through an unknown
        /// relay unless <see cref="UseVpnGateFallback"/> is explicitly set).
        /// </summary>
        public bool Enabled { get => true; set { } }

        /// <summary>
        /// Name of a pre-configured Windows RAS/VPN phonebook entry (a trusted provider such
        /// as a paid Proton/Mullvad profile, or a corporate VPN). This is the RECOMMENDED
        /// path: the operator configures a trusted tunnel once, and Sentinel raises it on
        /// demand. Empty = no trusted profile configured.
        /// </summary>
        public string ProviderProfile { get; set; } = string.Empty;

        /// <summary>
        /// Last-resort fallback ONLY when <see cref="ProviderProfile"/> is empty. When true,
        /// Sentinel may dial a VPN Gate public volunteer relay to get the user off the hostile
        /// local path. This is a TRADEOFF, not a clean win: a VPN Gate exit is operated by an
        /// unknown volunteer and replaces a local attacker with a remote unknown one. It
        /// defends against the LAN MitM but is NOT equivalent to a trusted paid tunnel, and
        /// the incident report says so. Default false - the operator must opt in explicitly.
        /// </summary>
        public bool UseVpnGateFallback { get; set; } = false;

        /// <summary>
        /// Transient RAS entry name Sentinel creates/uses for the VPN Gate fallback dial.
        /// Only used when <see cref="UseVpnGateFallback"/> is true and no trusted profile
        /// exists. VPN Gate's well-known shared credentials are vpn/vpn (public relays).
        /// </summary>
        public string VpnGateEntryName { get; set; } = "Sentinel-Shield-Fallback";

        /// <summary>
        /// Seconds between clean-and-verify sweeps while the shield is up. Each sweep asks the
        /// network to be cleaned and re-checks integrity (gateway MAC, DNS, no bridge, DNS
        /// cross-validation). The tunnel drops only after a clean sweep.
        /// </summary>
        public int VerifyIntervalSeconds { get; set; } = 20;

        /// <summary>
        /// Consecutive clean sweeps required before the tunnel is dropped (hysteresis so a
        /// single lucky poll doesn't tear down the shield prematurely).
        /// </summary>
        public int CleanSweepsRequired { get; set; } = 3;

        /// <summary>
        /// Hard ceiling on how long the shield may stay up for a single incident (seconds).
        /// On expiry Sentinel keeps the tunnel but escalates the incident report - it never
        /// silently drops an unverified-clean shield.
        /// </summary>
        public int MaxShieldSeconds { get; set; } = 1800;
    }

    public class SentinelConfig
    {
        /// <summary>
        /// v2.0.4: ActiveResponse is always true. The setter is retained for deserialization
        /// compatibility but silently ignores attempts to set it to false.
        /// There is no way to disable response actions from configuration.
        /// </summary>
        public bool ActiveResponse
        {
            get => true; // Always armed - no off switch
            set { } // No-op: cannot be disabled
        }
        public string? LogPath { get; set; }
        public string? WatchPath { get; set; }
        /// <summary>
        /// Explicit allowlist of Cast device IPs on the LAN.
        /// v1.8.3: Empty = observe-only (log Cast traffic, do not firewall-block) unless
        /// <see cref="MitmDefense"/> is enabled (then rogue Cast IOCs are blocked).
        /// Non-empty = enforce allowlist (block LAN Cast IPs not listed).
        /// </summary>
        public string[] TrustedCastDevices { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v1.9.10: Post-incident MITM defense suite (June 13-14 chain).
        /// When Enabled: plant MitM certs are removed, FCM "Send Tab to Self" is blocked,
        /// and fake Chromecast / rogue Cast LAN relays are firewall-blocked.
        /// Does not require RestrictivePortHardening (narrow exception for this threat class).
        /// Default off for clean installs; enable after confirmed MitM / fake Cast.
        /// </summary>
        public MitmDefenseConfig MitmDefense { get; set; } = new();

        /// <summary>
        /// v2.6.0: Protective VPN-shield remediation for confirmed local network tampering.
        /// When Enabled: a chain-confirmed network-tamper incident raises a temporary userland
        /// VPN tunnel, the network is cleaned (unbridge / DNS restore / rogue-route drop), and
        /// the tunnel is dropped only after the path is verified clean (fail-safe: stays up if
        /// it cannot be verified). Default off for clean installs.
        /// </summary>
        public VpnShieldConfig VpnShield { get; set; } = new();
        // Optional modern detection extensions
        // NOTE: EnableIntelThreatIntel stays FALSE by default on purpose - IntelFeedUrl below is
        // a PLACEHOLDER (example.com). Enabling it without a real feed URL just polls a dead
        // host. Set a real IntelFeedUrl via config and flip this to true to use it.
        public bool EnableIntelThreatIntel { get; set; } = false;
        public string IntelFeedUrl { get; set; } = "https://intel-ti-feed.example.com/iocs.json";
        // NOTE: these two flags are currently NOT read by any consumer (no wired monitor/engine
        // references them). Left FALSE so the config does not advertise behavior that does not
        // exist. If/when a PMU monitor or AI-scoring engine is wired up, flip the relevant flag.
        public bool EnableHardwarePmuMonitor { get; set; } = false;
        public bool EnableAiBehaviorScoring { get; set; } = false; // AI model based scoring
        // NOTE: EnableDynamicSandboxing stays FALSE by default - it executes suspicious binaries
        // in Windows Sandbox, which requires the optional Windows Sandbox feature installed and
        // carries real performance/compat cost. Enable only on hosts that have it.
        public bool EnableDynamicSandboxing { get; set; } = false; // Run suspicious binaries in Windows Sandbox

        /// <summary>
        /// AGGRESSIVE mode: walks ready drive roots for unsigned loadable modules
        /// (.dll/.winmd/.ocx/.cpl/.ax/.node/.drv/...) and quarantines them with hardened removal
        /// (kill holders + takeown/icacls so locked modules leave disk immediately). Default TRUE
        /// on this repeat-target host - the sweep mirrors the PS Antivirus.ps1 DLL remover.
        /// Still compiled-only: disk JSON does NOT enable it (EncryptedConfigStore has no case for
        /// this key and all JSON sources are stripped), so a planted file can neither arm NOR
        /// disarm it. To disarm, change this initializer and rebuild.
        /// </summary>
        public bool EnableAggressiveUnsignedDllSweep { get; set; } = true;

        /// <summary>
        /// v2.7.6: Operator-defined DOMAIN blocks, enforced by the proven forum.hr-style path -
        /// a hosts-file line (exact host) PLUS a wildcard NRPT rule (apex + all subdomains ->
        /// 0.0.0.0) under the GP-managed policy hive, self-healed on startup and every scan.
        /// Because BrowserDnsPolicyGuard disables DoH, these blocks are authoritative for
        /// browsers too. EMPTY BY DEFAULT - nothing is blocked unless the operator populates
        /// it. Each entry is a bare domain (e.g. "example.com"); the leading-dot NRPT suffix
        /// covers every subdomain. No domain is hardcoded.
        /// </summary>
        public string[] EnforcedDomainBlocks { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v2.7.6: Operator-defined IP blocks, enforced with inbound + outbound Windows Firewall
        /// block rules (Sentinel-owned rule names), re-asserted on startup and every scan.
        /// EMPTY BY DEFAULT. Each entry is an IPv4/IPv6 address; loopback / broadcast / invalid
        /// values are refused. NRPT is a name-resolution policy and cannot match a raw IP, so IP
        /// blocking is a separate firewall mechanism from EnforcedDomainBlocks.
        /// </summary>
        public string[] EnforcedIpBlocks { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v2.7.6: Known-risky pairing origins (domain suffixes) used ONLY as an aggravator
        /// for the site-to-local-app pairing guards (LocalControlChannelMonitor,
        /// NativeMessagingHostGuard, DangerousBrowserFlagRule). A match here NEVER triggers
        /// action or a detection on its own - it only raises confidence / lowers the chain
        /// threshold when a *behavioral* pairing signal has already fired. This deliberately
        /// avoids domain-identity trust as a verdict (an attacker controls the domain and can
        /// move it), keeping behavior authoritative. Matched as a case-insensitive suffix so
        /// "forum.hr" covers the apex and all subdomains. Seeded with the historical
        /// forum.hr spy-pairing origin as an example; empty is a valid (behavior-only) config.
        /// </summary>
        public string[] RiskyPairingOrigins { get; set; } = new[] { "forum.hr" };

        // Dynamic polling intervals (configurable)
        public int DnsPollIntervalSeconds { get; set; } = 15;
        public int RouteTableScanIntervalSeconds { get; set; } = 15;
        public int RawDiskScanIntervalSeconds { get; set; } = 20;
        public int AntiTamperTimingTickMs { get; set; } = 2000;
        public int AntiTamperIntegrityTickMs { get; set; } = 10000;

        /// <summary>
        /// v1.6.0: Maximum process kill/quarantine-kill actions per rolling 60 seconds.
        /// Prevents weaponized false-positive storms. NetworkIsolate is not counted.
        /// 0 = unlimited (not recommended).
        /// </summary>
        public int MaxKillsPerMinute { get; set; } = 15;

        /// <summary>
        /// v1.6.1: Maximum new NetworkIsolate firewall targets per rolling 60 seconds.
        /// Prevents isolate-storm DoS / CDN collateral from decoy beacons.
        /// 0 = unlimited (not recommended).
        /// </summary>
        public int MaxNetworkIsolatesPerMinute { get; set; } = 10;

        /// <summary>
        /// When true, ActiveResponse=false at startup is treated as tampering and force re-enabled.
        /// <summary>
        /// v2.0.4: Removed. ActiveResponse is now always true (no off switch).
        /// This property is retained as a no-op for deserialization compatibility only.
        /// </summary>
        [System.Obsolete("v2.0.4: ActiveResponse cannot be disabled. This property is a no-op.")]
        public bool EnforceActiveResponse { get; set; } = true;

        /// <summary>
        /// v2.9.4: ALWAYS FALSE - no off switch. Setter is a no-op. Sentinel acts on single
        /// high-confidence Tier1 signals; it does not wait for a multi-signal chain, and this
        /// cannot be re-enabled from config or a planted file. Tier2 remains LogOnly
        /// unconditionally (that invariant is unchanged). Chosen for a repeat-target host;
        /// accepts higher false-positive-action risk so a lone strong indicator is never
        /// left un-actioned.
        /// </summary>
        public bool ObserveUntilChain { get => false; set { } }

        /// <summary>
        /// Minimum confidence (0-1) for a kill-grade family to remain Tier1.
        /// Below this, signals demote to Tier2 observe (still feed correlation).
        /// </summary>
        public double MinTier1Confidence { get; set; } = 0.85;

        /// <summary>
        /// Distinct rule names on the same PID required (within ChainConfirmWindowSeconds)
        /// plus at least one terminal-outcome signal before destructive response.
        /// </summary>
        public int ChainConfirmMinSignals { get; set; } = 2;

        /// <summary>
        /// Rolling window for multi-signal chain confirmation (seconds).
        /// </summary>
        public int ChainConfirmWindowSeconds { get; set; } = 300;

        /// <summary>
        /// When true (default): no toasts and no auto evidence packs unless chain-confirmed nuke.
        /// Detection still writes to events.jsonl for correlation.
        /// </summary>
        public bool SilentObserve { get; set; } = true;

        /// <summary>
        /// v1.9.5: Optional Windows Event Log trail (Application / source Sentinel).
        /// Disabled automatically on barebone/custom images where Event Log is stripped.
        /// </summary>
        public WindowsEventLogConfig WindowsEventLog { get; set; } = new();

        /// <summary>
        /// v1.8.3: When true, ThreatIntelFeedBlocker pre-creates Windows Firewall block rules
        /// for every feed IP/CIDR. Default <c>false</c> - observe connections to listed IPs
        /// and only act reactively (NetworkIsolate on live hit when ActiveResponse is on).
        /// Pre-blocking thousands of ranges breaks legitimate TLS/OCSP/CDN traffic.
        /// v2.9.4: ALWAYS TRUE - no off switch. Setter is a no-op. Known-bad feed IOCs are
        /// proactively firewalled and this cannot be disabled from config.
        /// </summary>
        public bool ThreatIntelProactiveFirewall { get => true; set { } }

        /// <summary>
        /// v1.8.3: When true, permanently block Google FCM (TCP 5228 + mtalk hosts).
        /// v2.9.4: ALWAYS TRUE - no off switch. Setter is a no-op. This machine had confirmed
        /// Chrome sync token theft in the June 13-14 chain; severing FCM "Send Tab to Self"
        /// (TCP 5228) closes the attacker's remaining push vector and cannot be re-enabled.
        /// </summary>
        public bool BlockFcmPushChannel { get => true; set { } }

        /// <summary>
        /// v2.5.5: Hardening is now unconditional - always active. The setter is retained
        /// for deserialization compatibility but is a no-op. IPSec port lockdown, ASR Block
        /// rules, RPC/DCOM firewall, remote session guard, registry hardening, credential
        /// hardening, browser hardening, and LGPO security policy always run.
        /// </summary>
        [System.Obsolete("v2.5.5: RestrictivePortHardening is always true. This property is a no-op.")]
        public bool RestrictivePortHardening
        {
            get => true;
            set { } // No-op: hardening is always-on as of v2.5.5
        }

        /// <summary>
        /// v1.6.3: Trusted USB devices as VID:PID (hex, e.g. "0951:1666" for Kingston DataTraveler).
        /// New mass-storage/composite devices matching these IDs are baselined at low severity
        /// and never auto-disabled. HID BadUSB rules still apply to unknown keyboards.
        /// </summary>
        public string[] TrustedUsbDevices { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v1.9.7: When true, auto-disable USB nodes that fail descriptor requests
        /// (VID_0000 / "Device Descriptor Request Failed") via registry ConfigFlags.
        /// Default TRUE (v3.0.3): the "work-first" restraint is dropped on this hardened host -
        /// a device that fails descriptor enumeration is treated as a BadUSB / rogue-HID tell and
        /// disabled on sight. Trade-off accepted: a genuinely flaky-but-legitimate USB device may
        /// be disabled; re-enable it in Device Manager if that happens. HID BadUSB rules continue
        /// to apply to unknown keyboards regardless of this flag.
        /// </summary>
        public bool AutoDisableFailedUsbEnumeration { get; set; } = true;

        public CveShieldConfig CveShield { get; set; } = new();

        /// <summary>
        /// v1.9.9: Observe optional vendor/OS services that phone home (DiagTrack, whesvc, ...).
        /// Default Mode=Observe - log only; never stop services or firewall-block for privacy noise.
        /// Destructive host mutation remains reserved for chain-confirmed malice
        /// (cred dump, C2, ransomware, reverse shell, token theft, proven exfil chains).
        /// </summary>
        public ServiceExfilPostureConfig ServiceExfilPosture { get; set; } = new();

        /// <summary>
        /// v2.0: Explainable weighted multi-signal correlation (complements hand-authored composites).
        /// Compiled default; optional DPAPI override via EncryptedConfigStore.
        /// </summary>
        public WeightedCorrelationConfig WeightedCorrelation { get; set; } = new();
    }

    /// <summary>
    /// How Sentinel treats optional OS/vendor services that perform outbound telemetry.
    /// MVP ships Observe only; Soft/Hard are reserved for future opt-in (not default).
    /// </summary>
    public enum ServiceExfilPostureMode
    {
        /// <summary>Log inventory + outbound remotes only. No host mutation.</summary>
        Observe = 0,
        /// <summary>Future: NetworkIsolate public remotes for inventory services (opt-in).</summary>
        SoftReact = 1,
        /// <summary>Future: stop inventory services via SCM (opt-in; never kill svchost).</summary>
        HardReact = 2
    }

    /// <summary>
    /// v1.9.9 - Awareness of optional services that may phone home while remaining legitimate.
    /// Product law: 99% of software is observe-only; act only on kill-grade malice chains.
    /// </summary>
    public sealed class ServiceExfilPostureConfig
    {
        /// <summary>Master switch for PrivacyServiceOutboundMonitor. Default true (observe).</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Always Observe in shipped defaults. Soft/Hard must stay off unless operator opts in later.</summary>
        public ServiceExfilPostureMode Mode { get; set; } = ServiceExfilPostureMode.Observe;

        public int ScanIntervalSeconds { get; set; } = 15;

        /// <summary>
        /// Extra service short names to treat as privacy/phone-home inventory.
        /// Merged with built-in defaults (DiagTrack, whesvc, ...).
        /// </summary>
        public string[] Inventory { get; set; } = Array.Empty<string>();

        /// <summary>Service names the operator chooses to ignore (no privacy events).</summary>
        public string[] Allowlist { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Services that must never be stopped/disabled even if HardReact is added later.
        /// Empty uses built-in NeverTouch set (EventLog, BFE, Defender, ...).
        /// </summary>
        public string[] NeverTouch { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// v1.9.5 - Durable secondary audit trail via Windows Event Log.
    /// Primary product log remains JSONL. All writes fail-soft on stripped Windows.
    /// </summary>
    public class WindowsEventLogConfig
    {
        /// <summary>Master switch. Default on; writer self-disables if Event Log is unusable.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Event source name (registered under LogName on first successful create).</summary>
        public string SourceName { get; set; } = "Sentinel";

        /// <summary>
        /// Target log. Default Application - most available on custom/stripped images.
        /// Custom logs require extra ACLs and fail more often; avoid for barebone hosts.
        /// </summary>
        public string LogName { get; set; } = "Application";

        /// <summary>
        /// When true (default): only service lifecycle, chain response, evidence pack,
        /// quarantine, anti-tamper, heartbeat - never Tier2 observe spam.
        /// </summary>
        public bool CriticalOnly { get; set; } = true;

        /// <summary>Rolling write budget (0 = unlimited). Protects broken log stacks.</summary>
        public int MaxWritesPerMinute { get; set; } = 30;

        /// <summary>Low-frequency "still alive" events for SIEM gap detection.</summary>
        public bool HeartbeatEnabled { get; set; } = true;

        /// <summary>Heartbeat interval in minutes (minimum 15 enforced at runtime).</summary>
        public int HeartbeatMinutes { get; set; } = 60;
    }

    public class ThreatReportingConfig
    {
        public bool Enabled { get; set; } = true;
        public string? AbuseIpDbApiKey { get; set; }
        public string? UrlhausAuthToken { get; set; }
        public string? MalwareBazaarApiKey { get; set; }
        public bool ReportToMalwareBazaar { get; set; } = true;
        public bool ReportToUrlhaus { get; set; } = true;

        /// <summary>
        /// URL of the Cloudflare Worker proxy that holds API keys server-side.
        /// When set, reports go to this endpoint instead of directly to abuse.ch.
        /// This allows open-source distribution without leaking API keys.
        /// Default endpoint compiled into the binary.
        /// </summary>
        public string? ProxyEndpoint { get; set; } = "https://sentinel-threat-proxy.znastidobrostoje-6ee.workers.dev";

        /// <summary>
        /// HMAC key for the threat-proxy Worker. Compiled into the binary.
        /// Must match Worker env SENTINEL_SHARED_SECRET. Split concat so a PE
        /// dump is not one line. Admin --set-config can rotate via DPAPI
        /// config.enc (length >= 16). Short plants are ignored.
        /// </summary>
        public string? ProxySharedSecret { get; set; } = CompiledProxySharedSecret;

        /// <summary>Built-in Worker HMAC. Not disk config.</summary>
        public static string CompiledProxySharedSecret =>
            string.Concat("SntlHmac/", "CroatiaSecurity/", "v254/", "e7a91c4b2f6d80e3", "15c8a0d47b9e2f63");
    }

    /// <summary>
    /// v1.7.7+ - Automatic local evidence packs + optional TI indicator share
    /// for high-confidence hacking / attack detections.
    /// Does not file police reports (no public LE API); prepares packs and portal links.
    /// v1.7.8: reportable-grade policy, integrity manifest/HMAC, victim affidavit.
    /// </summary>
    public class AutoIncidentReportingConfig
    {
        /// <summary>Master switch. Default on.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Write police-ready packs under ProgramData\Sentinel\IncidentReports.</summary>
        public bool GenerateLocalEvidencePack { get; set; } = true;

        /// <summary>
        /// B1 (durable evidence survival): when true, a signed <b>summary</b> of each
        /// chain-confirmed evidence pack is mirrored off-host via the existing HMAC-signed
        /// ThreatReporting proxy so a local admin who suppresses Sentinel cannot also erase the
        /// proof. Default <b>false</b> (opt-in) - matches the honest, no-covert-exfil posture.
        /// Requires a configured ThreatReporting ProxyEndpoint + shared secret; fails closed
        /// (skips silently) when the secret is missing. Never uploads file contents or secrets.
        /// </summary>
        public bool MirrorEvidenceOffHost { get; set; } = false;

        /// <summary>
        /// Submit hashes/URLs/IPs via ThreatReportService (MalwareBazaar/URLhaus/AbuseIPDB).
        /// Requires ThreatReporting proxy secret. Community intel - not law enforcement.
        /// </summary>
        public bool ReportThreatIntel { get; set; } = true;

        /// <summary>Show a critical toast when a pack is written.</summary>
        public bool NotifyUser { get; set; } = true;

        /// <summary>
        /// v1.7.8: When true (default), only reportable-grade events produce packs:
        /// kill-authorized at high confidence, NetworkIsolate for C2-class signals,
        /// or Tier1 attack signals at MinConfidence - no low-signal noise.
        /// </summary>
        public bool ReportableGradeOnly { get; set; } = true;

        /// <summary>Minimum confidence for reportable-grade Tier1 / isolate paths (default 0.85).</summary>
        public double MinConfidence { get; set; } = 0.85;

        /// <summary>
        /// Floor confidence for kill-authorized packs when ReportableGradeOnly is true (default 0.80).
        /// When ReportableGradeOnly is false, uses min(MinConfidence, 0.70) for broader capture.
        /// </summary>
        public double KillAuthorizedMinConfidence { get; set; } = 0.80;

        /// <summary>Report kill-authorized detections (above KillAuthorizedMinConfidence).</summary>
        public bool IncludeKillAuthorized { get; set; } = true;

        /// <summary>Include NetworkIsolate when signal looks like C2 / attack (not every isolate).</summary>
        public bool IncludeNetworkIsolate { get; set; } = true;

        /// <summary>
        /// v1.7.8: Write MANIFEST.sha256, evidence_manifest.json, MANIFEST.hmac, chain_of_custody.txt.
        /// </summary>
        public bool IncludeIntegrityManifest { get; set; } = true;

        /// <summary>v1.7.8: Write victim_affidavit.txt fill-in template for the complainant.</summary>
        public bool IncludeVictimAffidavit { get; set; } = true;

        /// <summary>v1.7.8: Also create a .zip of the pack after integrity sealing.</summary>
        public bool CreateZipExport { get; set; } = true;

        /// <summary>Optional pre-fill for affidavit (user may complete remaining fields by hand).</summary>
        public string? VictimFullName { get; set; }
        public string? VictimEmail { get; set; }
        public string? VictimPhone { get; set; }
        public string? VictimAddress { get; set; }

        /// <summary>
        /// ISO 3166-1 alpha-2 override for filing portal (e.g. "HR", "US").
        /// Null = detect from Windows region.
        /// </summary>
        public string? CountryCode { get; set; }

        /// <summary>Override pack output directory. Null = ProgramData\Sentinel\IncidentReports.</summary>
        public string? ReportDirectory { get; set; }

        /// <summary>Per rule+pid cooldown in seconds (default 5 minutes).</summary>
        public int CooldownSeconds { get; set; } = 300;

        /// <summary>Hard cap on packs written per rolling hour (default 20).</summary>
        public int MaxPacksPerHour { get; set; } = 20;
    }

    public class TelemetryEvent
    {
        public string Type { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
    }

    public class ProcessTelemetry : TelemetryEvent
    {
        public string ImagePath { get; set; } = string.Empty;
        public int ParentProcessId { get; set; }
        public string ParentProcessName { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
    }

    public class NetworkTelemetry : TelemetryEvent
    {
        public string LocalAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string State { get; set; } = "ESTABLISHED";
    }

    public class FileActivityTelemetry : TelemetryEvent
    {
        public string FilePath { get; set; } = string.Empty;
        public string OperationType { get; set; } = string.Empty; // WRITE, RENAME, DELETE, etc.
        public string? TargetPath { get; set; }
    }

    public class ThreatIntelTelemetry : TelemetryEvent
    {
        public int TargetProcessId { get; set; }
        public string ApiName { get; set; } = string.Empty; // observed API name when known
        public string Protection { get; set; } = string.Empty;
    }

    public class DetectionEvent
    {
        public string RuleName { get; set; } = string.Empty;
        /// <summary>
        /// Stable rule identifier (e.g. "SENT-001") used for central action mapping,
        /// deduplication, and audit correlation. Optional - legacy rules leave this null.
        /// Ported from GorstaksProtection (GRS-00X scheme).
        /// </summary>
        public string? RuleId { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public string Reasoning { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public DetectionTier Tier { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public SignalType SignalType { get; set; } = SignalType.Generic;
        /// <summary>
        /// v2.6: Optional TYPED terminal-outcome family. When a monitor sets this explicitly,
        /// <see cref="ResponsePolicy.ClassifyTerminalOutcome"/> trusts it directly instead of
        /// inferring the family from rule-name substrings - removing the "renamed a rule,
        /// silently lost its kill-grade classification" bug class. Null for legacy detections,
        /// which continue to flow through the proven substring classifier unchanged.
        /// </summary>
        public TerminalFamily? Family { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public ResponseAction AuthorizedResponse { get; set; } = ResponseAction.LogOnly;
        public bool KillAuthorized => AuthorizedResponse >= ResponseAction.KillProcess;
    }

    public class ResponseEvent
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ActionTaken { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public double ExecutionTimeMs { get; set; }
    }
}
