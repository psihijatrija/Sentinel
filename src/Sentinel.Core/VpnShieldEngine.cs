using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.6.0: Protective VPN-shield remediation for confirmed local network tampering.
    ///
    /// Chain: a network-tamper incident (rogue gateway / ARP poisoning, DNS hijack, route
    /// injection, adapter bridging) is chain-confirmed by the response engine, which invokes
    /// <see cref="RaiseShieldAsync"/>. This engine then:
    ///   1. raises a userland VPN tunnel (a standard RAS dial - visible, no kernel driver),
    ///      so the user's traffic is encrypted and routed off the hostile local path;
    ///   2. repeatedly asks <see cref="NetworkInterfaceGuard"/> to clean the network
    ///      (unbridge, re-enable adapters, restore DNS) and re-checks integrity;
    ///   3. drops the tunnel only after the path is VERIFIED clean for
    ///      <see cref="VpnShieldConfig.CleanSweepsRequired"/> consecutive sweeps.
    ///
    /// Hard invariants honored:
    /// - Userland only. RAS dial via <c>rasapi32</c> - the connection is visible in Task
    ///   Manager, the network list, and event logs. No kernel/PPL component, no self-hiding.
    /// - Fail-safe: if the network cannot be verified clean (or verification errors), the
    ///   tunnel STAYS UP. The engine never silently tears down an unverified-clean shield;
    ///   on <see cref="VpnShieldConfig.MaxShieldSeconds"/> expiry it escalates the report
    ///   and keeps the tunnel.
    /// - Opt-in and never speculative: only reached when <see cref="ProductPosture.AllowsVpnShield"/>
    ///   is true AND the incident is chain-confirmed (the response engine enforces both).
    /// - CancellationToken threaded through the remediation loop; no static mutable state;
    ///   graceful degradation (all faults logged, never thrown to the caller).
    ///
    /// Trusted-provider preference: a pre-configured <see cref="VpnShieldConfig.ProviderProfile"/>
    /// (e.g. a paid Proton/Mullvad or corporate RAS entry) is always preferred. VPN Gate public
    /// relays are a last-resort fallback only when <see cref="VpnShieldConfig.UseVpnGateFallback"/>
    /// is set and no trusted profile exists - and that tradeoff is recorded in the incident log.
    /// </summary>
    public sealed class VpnShieldEngine
    {
        private readonly SentinelConfig _config;
        private readonly NetworkInterfaceGuard _netGuard;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<VpnShieldEngine> _logger;

        // Single-flight guard so overlapping detections don't raise multiple shields.
        private readonly SemaphoreSlim _gate = new(1, 1);
        private volatile bool _shieldActive;

        // Injected tunnel transport (RAS by default). Swappable for tests so the
        // remediation/verify orchestration can be exercised without touching real network
        // state. Never null after construction.
        private readonly IVpnTunnel _tunnel;

        public VpnShieldEngine(
            SentinelConfig config,
            NetworkInterfaceGuard netGuard,
            JsonlEventLogger eventLogger,
            ILogger<VpnShieldEngine> logger,
            IVpnTunnel? tunnel = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _netGuard = netGuard ?? throw new ArgumentNullException(nameof(netGuard));
            _eventLogger = eventLogger ?? throw new ArgumentNullException(nameof(eventLogger));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _tunnel = tunnel ?? new RasVpnTunnel(logger);
        }

        /// <summary>True while a protective tunnel is currently raised.</summary>
        public bool IsShieldActive => _shieldActive;

        /// <summary>
        /// Raise the protective tunnel for a confirmed network-tamper incident, run the
        /// clean-and-verify loop, and drop the tunnel once the path is verified clean.
        /// Fire-and-forget safe: never throws, single-flight, honors cancellation.
        /// </summary>
        public async Task RaiseShieldAsync(DetectionEvent detection, CancellationToken ct)
        {
            // Posture gate (defence in depth - the response engine also checks this).
            if (!ProductPosture.AllowsVpnShield(_config))
            {
                await LogAsync("VPN_SHIELD_SKIP", detection,
                    "VpnShield disabled (VpnShield.Enabled=false) - no tunnel raised.");
                return;
            }

            // Single-flight: if a shield is already up, this incident just extends coverage.
            if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
            {
                await LogAsync("VPN_SHIELD_COALESCE", detection,
                    "Protective tunnel already active - coalescing this incident under the existing shield.");
                return;
            }

            try
            {
                var (entryName, provenance, isFallback) = SelectProfile();
                if (entryName == null)
                {
                    await LogAsync("VPN_SHIELD_NO_PROFILE", detection,
                        "No trusted VPN ProviderProfile configured and VPN Gate fallback disabled - " +
                        "cannot raise a protective tunnel. Network cleaning proceeds without a shield.");
                    // Still clean the network even if we cannot shield.
                    await _netGuard.ForceCleanAsync(ct).ConfigureAwait(false);
                    return;
                }

                if (!_tunnel.Connect(entryName, out var connectError))
                {
                    await LogAsync("VPN_SHIELD_DIAL_FAILED", detection,
                        $"Failed to raise protective tunnel via {provenance} ('{entryName}'): {connectError}. " +
                        "Proceeding to clean the network without a shield (fail-open on connectivity, not on cleaning).");
                    await _netGuard.ForceCleanAsync(ct).ConfigureAwait(false);
                    return;
                }

                _shieldActive = true;
                await LogAsync("VPN_SHIELD_UP", detection,
                    $"Protective VPN tunnel raised via {provenance} ('{entryName}')." +
                    (isFallback
                        ? " NOTE: this is a VPN Gate public volunteer relay used as a last-resort fallback - " +
                          "it defends against the local MitM but is operated by an unknown third party and is " +
                          "NOT equivalent to a trusted paid tunnel. Configure VpnShield.ProviderProfile."
                        : " Trusted provider profile."));

                await CleanAndVerifyLoopAsync(detection, entryName, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Shutdown: leave the tunnel as-is (fail-safe). It is a visible RAS connection
                // the user/operator can drop manually; we never tear down on cancellation.
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VpnShieldEngine] Unexpected error during shield remediation");
                await LogAsync("VPN_SHIELD_ERROR", detection, $"Shield remediation error: {ex.Message}");
            }
            finally
            {
                _gate.Release();
            }
        }

        private async Task CleanAndVerifyLoopAsync(DetectionEvent detection, string entryName, CancellationToken ct)
        {
            int verifyInterval = Math.Max(5, _config.VpnShield.VerifyIntervalSeconds);
            int cleanSweepsRequired = Math.Max(1, _config.VpnShield.CleanSweepsRequired);
            int maxShieldSeconds = Math.Max(verifyInterval * cleanSweepsRequired, _config.VpnShield.MaxShieldSeconds);

            var deadline = DateTime.UtcNow.AddSeconds(maxShieldSeconds);
            int consecutiveClean = 0;

            while (!ct.IsCancellationRequested)
            {
                // Ask the interface guard to clean (unbridge / re-enable adapters / restore DNS).
                await _netGuard.ForceCleanAsync(ct).ConfigureAwait(false);

                // Give the OS a moment to settle the interface state before re-checking.
                await Task.Delay(TimeSpan.FromSeconds(verifyInterval), ct).ConfigureAwait(false);

                bool clean = _netGuard.IsNetworkClean();
                if (clean)
                {
                    consecutiveClean++;
                    await LogAsync("VPN_SHIELD_VERIFY", detection,
                        $"Network verified clean ({consecutiveClean}/{cleanSweepsRequired} consecutive sweeps).");

                    if (consecutiveClean >= cleanSweepsRequired)
                    {
                        // Path is trustworthy again - safe to drop the shield.
                        if (_tunnel.Disconnect(entryName, out var hangupError))
                        {
                            _shieldActive = false;
                            await LogAsync("VPN_SHIELD_DOWN", detection,
                                "Network path verified clean - protective tunnel dropped, user restored to the direct path.");
                        }
                        else
                        {
                            await LogAsync("VPN_SHIELD_DOWN_FAILED", detection,
                                $"Network verified clean but tunnel hang-up failed: {hangupError}. " +
                                "Tunnel remains up (fail-safe); operator can drop it manually.");
                        }
                        return;
                    }
                }
                else
                {
                    // Regression - reset the hysteresis counter. Keep shielding.
                    consecutiveClean = 0;
                }

                if (DateTime.UtcNow >= deadline)
                {
                    // Fail-safe: never silently drop an unverified-clean shield. Escalate and hold.
                    await LogAsync("VPN_SHIELD_HOLD", detection,
                        $"Network still not verified clean after MaxShieldSeconds ({maxShieldSeconds}s). " +
                        "Protective tunnel is HELD UP (fail-safe) and the incident is escalated for operator review.");
                    return;
                }
            }
        }

        /// <summary>
        /// Choose which RAS entry to dial. Prefers a trusted operator-configured profile;
        /// falls back to a transient VPN Gate relay only when explicitly opted in and no
        /// trusted profile exists. Returns (entryName, provenance, isFallback) or null entry.
        /// </summary>
        private (string? entryName, string provenance, bool isFallback) SelectProfile()
        {
            var cfg = _config.VpnShield;
            if (!string.IsNullOrWhiteSpace(cfg.ProviderProfile))
                return (cfg.ProviderProfile.Trim(), "trusted provider profile", false);

            if (cfg.UseVpnGateFallback && !string.IsNullOrWhiteSpace(cfg.VpnGateEntryName))
                return (cfg.VpnGateEntryName.Trim(), "VPN Gate fallback", true);

            return (null, "none", false);
        }

        private async Task LogAsync(string action, DetectionEvent detection, string message)
        {
            try
            {
                await _eventLogger.LogEventAsync("vpn_shield", new
                {
                    Action = action,
                    Rule = detection?.RuleName,
                    Message = message,
                    Timestamp = DateTime.UtcNow
                }).ConfigureAwait(false);
            }
            catch { /* logging must never break remediation */ }
            _logger.LogInformation("[VpnShieldEngine] {Action}: {Message}", action, message);
        }
    }

    /// <summary>
    /// Abstraction over the userland VPN tunnel transport so the clean-and-verify orchestration
    /// in <see cref="VpnShieldEngine"/> is testable without dialing a real connection.
    /// </summary>
    public interface IVpnTunnel
    {
        /// <summary>Raise the tunnel for the named RAS phonebook entry. Returns success.</summary>
        bool Connect(string entryName, out string error);

        /// <summary>Drop the tunnel for the named RAS phonebook entry. Returns success.</summary>
        bool Disconnect(string entryName, out string error);
    }

    /// <summary>
    /// RAS-based userland tunnel transport. Uses documented <c>rasapi32</c> APIs (RasDial /
    /// RasEnumConnections / RasHangUp) rather than shelling out to <c>rasdial.exe</c> - the
    /// connection remains a standard, visible Windows VPN connection (transparency invariant).
    /// The named entry must already exist in a RAS phonebook (operator-provisioned trusted
    /// profile, or the VPN Gate fallback entry).
    /// </summary>
    internal sealed class RasVpnTunnel : IVpnTunnel
    {
        private readonly ILogger _logger;
        public RasVpnTunnel(ILogger logger) { _logger = logger; }

        private const int RAS_MaxEntryName = 256;
        private const int RAS_MaxDeviceName = 128;
        private const int RAS_MaxDeviceType = 16;
        private const int UNLEN = 256;
        private const int PWLEN = 256;
        private const int DNLEN = 15;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RASDIALPARAMS
        {
            public int dwSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RAS_MaxEntryName + 1)] public string szEntryName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RAS_MaxPhoneNumber + 1)] public string szPhoneNumber;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RAS_MaxCallbackNumber + 1)] public string szCallbackNumber;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = UNLEN + 1)] public string szUserName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PWLEN + 1)] public string szPassword;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DNLEN + 1)] public string szDomain;
        }

        private const int RAS_MaxPhoneNumber = 128;
        private const int RAS_MaxCallbackNumber = 128;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RASCONN
        {
            public int dwSize;
            public IntPtr hrasconn;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RAS_MaxEntryName + 1)] public string szEntryName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RAS_MaxDeviceType + 1)] public string szDeviceType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = RAS_MaxDeviceName + 1)] public string szDeviceName;
        }

        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint RasDial(
            IntPtr lpRasDialExtensions,
            string? lpszPhonebook,
            ref RASDIALPARAMS lpRasDialParams,
            uint dwNotifierType,
            IntPtr lpvNotifier,
            out IntPtr lphRasConn);

        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint RasEnumConnections(
            [In, Out] RASCONN[]? lprasconn,
            ref int lpcb,
            ref int lpcConnections);

        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint RasHangUp(IntPtr hrasconn);

        public bool Connect(string entryName, out string error)
        {
            error = string.Empty;
            try
            {
                var p = new RASDIALPARAMS
                {
                    szEntryName = entryName,
                    szPhoneNumber = string.Empty,
                    szCallbackNumber = string.Empty,
                    // VPN Gate public relays use the well-known vpn/vpn credentials; trusted
                    // provider entries typically store their own credentials in the phonebook,
                    // in which case these are ignored. We never hard-code secret credentials.
                    szUserName = "vpn",
                    szPassword = "vpn",
                    szDomain = string.Empty
                };
                p.dwSize = Marshal.SizeOf(typeof(RASDIALPARAMS));

                uint ret = RasDial(IntPtr.Zero, null, ref p, 0, IntPtr.Zero, out _);
                if (ret != 0)
                {
                    error = $"RasDial returned {ret}";
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                _logger.LogDebug(ex, "[RasVpnTunnel] Connect error for '{Entry}'", entryName);
                return false;
            }
        }

        public bool Disconnect(string entryName, out string error)
        {
            error = string.Empty;
            try
            {
                IntPtr handle = FindConnection(entryName);
                if (handle == IntPtr.Zero)
                {
                    // Nothing to hang up - treat as already down.
                    return true;
                }
                uint ret = RasHangUp(handle);
                if (ret != 0)
                {
                    error = $"RasHangUp returned {ret}";
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                _logger.LogDebug(ex, "[RasVpnTunnel] Disconnect error for '{Entry}'", entryName);
                return false;
            }
        }

        private static IntPtr FindConnection(string entryName)
        {
            int structSize = Marshal.SizeOf(typeof(RASCONN));
            int cb = structSize;
            int count = 0;

            // First call to size the buffer.
            var probe = new RASCONN[1];
            probe[0].dwSize = structSize;
            uint ret = RasEnumConnections(probe, ref cb, ref count);
            if (count == 0)
                return IntPtr.Zero;

            var conns = new RASCONN[count];
            for (int i = 0; i < count; i++) conns[i].dwSize = structSize;
            cb = structSize * count;
            ret = RasEnumConnections(conns, ref cb, ref count);
            if (ret != 0)
                return IntPtr.Zero;

            for (int i = 0; i < count; i++)
            {
                if (string.Equals(conns[i].szEntryName, entryName, StringComparison.OrdinalIgnoreCase))
                    return conns[i].hrasconn;
            }
            return IntPtr.Zero;
        }
    }
}
