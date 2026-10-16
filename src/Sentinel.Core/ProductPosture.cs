using System;

namespace Sentinel.Core
{
    /// <summary>Always-on host-hardening policy and action-specific response checks.
    /// Authorized Tier1 response can act immediately; Tier2 never authorizes mutation.</summary>
    public static class ProductPosture
    {
        /// <summary>
        /// Standing law: <c>MemoryBehaviorAnalyzer</c> + <c>ModuleIdentity</c> +
        /// <c>DllUnloadEngine</c> check mapped-module identity and contain eligible hosts.
        /// Disk quarantine and verified process-tree outcomes are reported separately.
        /// Games/anti-cheat, OS servicing and critical hosts retain their protections.
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
