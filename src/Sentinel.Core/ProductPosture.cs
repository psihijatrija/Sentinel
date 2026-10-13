using System;

namespace Sentinel.Core
{
    /// <summary>
    /// Standing product law (v2.5.5+). Hardening is unconditional - always active.
    ///
    /// <para><b>ALL HARDENING IS ALWAYS-ON.</b> IPSec port lockdown, ASR Block rules,
    /// RPC/DCOM firewall, remote session guard, registry hardening, credential hardening
    /// (LSASS PPL, WDigest off), browser hardening, and LGPO security policy run on every
    /// Sentinel startup with no config gate. The work-first observe-only default is retired.</para>
    ///
    /// <para>Allowed without any flag:</para>
    /// <list type="bullet">
    /// <item>Self-protect Sentinel (DLL path, install ACLs, Safe Mode registration)</item>
    /// <item>Detect + log to events.jsonl</item>
    /// <item>Destructive response only after multi-signal chain confirmation
    ///       (<see cref="ResponsePolicy"/> / ObserveUntilChain)</item>
    /// <item>Module identity unload is always on. Foreign mapped PEs are FreeLibrary'd.
    ///       Hijack-name plants are quarantined on drop (file only, never kill the host).
    ///       Games are not VM_READ. Never OS servicing. No config flag may disable this.</item>
    /// <item>Full proactive OS hardening - IPSec, ASR Block, RPC firewall, remote session
    ///       kill, registry hardening, credential hardening, browser hardening.</item>
    /// </list>
    /// </summary>
    public static class ProductPosture
    {
        /// <summary>
        /// Standing law: <c>MemoryBehaviorAnalyzer</c> + <c>ModuleIdentity</c> +
        /// <c>DllUnloadEngine</c> scan every process and unload foreign mapped PEs
        /// immediately. There is no config switch. Games/anti-cheat are skipped only
        /// for handle safety (Denuvo). OS servicing / lsass / csrss are never FreeLibrary'd.
        /// </summary>
        public const bool ModuleIdentityUnloadAlwaysOn = true;

        /// <summary>
        /// v2.5.5: Always returns true - hardening is unconditional.
        /// The config parameter is ignored; retained for call-site compatibility.
        /// </summary>
        public static bool AllowsProactiveHostLockdown(SentinelConfig? config) => true;

        /// <summary>
        /// v2.5.5: Always succeeds - hardening is unconditional.
        /// The denyReason is always empty.
        /// </summary>
        public static bool TryProactiveHostLockdown(SentinelConfig? config, out string denyReason)
        {
            denyReason = "";
            return true;
        }

        /// <summary>
        /// Destructive response after detection pipeline - separate from proactive lockdown.
        /// Still gated by ActiveResponse + ObserveUntilChain / chain confirm.
        /// </summary>
        public static bool AllowsChainConfirmedResponse(SentinelConfig? config, DetectionEvent? detection)
        {
            if (config == null || !config.ActiveResponse || detection == null)
                return false;
            return ResponsePolicy.MayPerformDestructiveResponse(detection, config);
        }

        /// <summary>
        /// v1.9.10: Narrow post-incident MITM suite (cert remove, FCM Send-Tab-to-Self block,
        /// rogue Cast / fake Chromecast firewall). Explicit operator opt-in via
        /// <see cref="MitmDefenseConfig.Enabled"/> - does not enable full kiosk lockdown.
        /// </summary>
        public static bool AllowsMitmDefenseMutations(SentinelConfig? config)
        {
            return config != null
                   && config.ActiveResponse
                   && config.MitmDefense != null
                   && config.MitmDefense.Enabled;
        }

        /// <summary>
        /// v2.6.0: Protective VPN-shield remediation for confirmed local network tampering.
        /// Explicit operator opt-in via <see cref="VpnShieldConfig.Enabled"/>. Raises a
        /// temporary userland VPN tunnel while the network is cleaned, then drops it once the
        /// path is verified clean. Non-kill, non-destructive to processes; does not enable
        /// full kiosk lockdown.
        /// </summary>
        public static bool AllowsVpnShield(SentinelConfig? config)
        {
            return config != null
                   && config.ActiveResponse
                   && config.VpnShield != null
                   && config.VpnShield.Enabled;
        }
    }
}
