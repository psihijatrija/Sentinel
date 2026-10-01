using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    // Host-wide (PID 0) signal correlation for BehavioralCorrelationEngine:
    // network-tamper vector independence + the protective VPN-shield composite, plus
    // host-wide delivery fuel buffering. Split out for reviewability; this is the SAME
    // type (partial class) - no behavior change. Shared mutable buffers (_networkTamper,
    // _hostWideDelivery) and their lock discipline are declared in the main file and
    // remain the only synchronization authority.
    public partial class BehavioralCorrelationEngine
    {
        internal static bool IsHostWideDeliveryFuel(DetectionEvent signal)
        {
            var n = signal?.RuleName ?? "";
            return n.IndexOf("Mark-of-the-Web", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Disk Image", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("AppInstaller Package", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Script Dropper", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("WPAD", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Auto-Proxy PAC", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void BufferHostWideDelivery(DetectionEvent signal)
        {
            lock (_hostWideDelivery)
            {
                _hostWideDelivery.Add(signal);
                PruneHostWideLocked();
            }
        }

        // v2.6.0: Host-wide local network-tamper correlation (PID-0 SYSTEM monitors).
        private readonly List<DetectionEvent> _networkTamper = new();
        private DateTime _lastVpnShieldEmit = DateTime.MinValue;
        private static readonly TimeSpan VpnShieldReEmitCooldown = TimeSpan.FromSeconds(120);

        /// <summary>
        /// v2.6.0: True for a local network-tamper signal that indicates active LAN MitM /
        /// redirection - the trigger family for the protective VPN-shield composite. These are
        /// emitted by SYSTEM monitors (ArpSpoofMonitor, NetworkInterfaceGuard, RouteTableMonitor,
        /// DNS validators) with PID 0. Matched by rule-name shape so a renamed rule that keeps
        /// its wording keeps its classification.
        /// </summary>
        internal static bool IsNetworkTamperFuel(DetectionEvent signal)
        {
            var n = signal?.RuleName ?? "";
            return n.IndexOf("ARP Spoof", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Network Bridge", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Unauthorized DNS Change", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("DNS Poison", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("DNS Hijack", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("DNS Spoof", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Route Injected", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Route Table", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Persistent Route", StringComparison.OrdinalIgnoreCase) >= 0
                // v2.8.3: any new non-default route is observe-fuel that corroborates a MitM chain.
                || n.IndexOf("New Route Added", StringComparison.OrdinalIgnoreCase) >= 0
                // v2.8.2/v2.8.3: a default-gateway change OR a gateway appearing on a secondary
                // adapter is a distinct MitM vector (rogue DHCP / route redirect / rogue 2nd NIC).
                || n.IndexOf("Gateway Changed", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Gateway Appeared", StringComparison.OrdinalIgnoreCase) >= 0
                // v2.8.2: a NEW network adapter appearing is the on-host start of adding a second
                // network path. On its own it is benign observe-fuel, but as an independent leg
                // alongside ARP/DNS/route tamper it corroborates a local MitM.
                || n.IndexOf("New Adapter Appeared", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Primary Adapter Disabled", StringComparison.OrdinalIgnoreCase) >= 0
                // v2.6.0: rogue WPAD/PAC proxy - JavaScript that reroutes browser traffic through
                // an attacker MITM proxy (DHCP Option 252 / CVE-2026-62755 class). A lone PAC
                // config is often legit corporate (WeakObserveSeed), so it never self-confirms -
                // it only counts as ONE independent tamper vector toward the >=2 shield composite.
                || n.IndexOf("WPAD", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Auto-Proxy PAC", StringComparison.OrdinalIgnoreCase) >= 0
                // v2.6.0: Wi-Fi path takeover - deauth flood (forced off AP, evil-twin precursor)
                // and BSSID change on the same SSID (evil twin AP impersonation). Both are active
                // attacks on the local path that a protective tunnel defends against.
                || n.IndexOf("Deauthentication Flood", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("Evil Twin", StringComparison.OrdinalIgnoreCase) >= 0
                || n.IndexOf("BSSID Changed", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Metadata key a network monitor may set to identify the SINGLE underlying observation
        /// (e.g. a gateway MAC change, one adapter, one route-table snapshot) that produced this
        /// signal. Two signals that share the same observation key are NOT independent evidence,
        /// even if they carry different <see cref="NetworkTamperVector"/> labels - they are two
        /// views of one root fact. Used by <see cref="CountIndependentTamperVectors"/> so a lone
        /// ARP/gateway event cannot masquerade as ARP + Route + DNS.
        /// </summary>
        internal const string ObservationKeyMeta = "ObservationKey";

        /// <summary>
        /// Counts DISTINCT tamper vectors that also rest on INDEPENDENT root observations.
        /// A vector counts once; if several signals of DIFFERENT vector labels all share the same
        /// <see cref="ObservationKeyMeta"/> value, they collapse to a single independent leg
        /// (one root fact cannot be its own corroboration). Signals with no observation key are
        /// treated as independent (each contributes its own vector) - legacy monitors that predate
        /// the key are unaffected, so this only ever REMOVES false independence, never adds it.
        /// </summary>
        private static int CountIndependentTamperVectors(List<DetectionEvent> snapshot)
        {
            // Group signals by their root observation. Signals without a key each get a unique
            // synthetic group so they remain independent.
            var byObservation = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            int synthetic = 0;
            foreach (var s in snapshot)
            {
                var vector = NetworkTamperVector(s);
                string obsKey;
                if (s.Metadata != null &&
                    s.Metadata.TryGetValue(ObservationKeyMeta, out var k) &&
                    !string.IsNullOrWhiteSpace(k))
                {
                    obsKey = k;
                }
                else
                {
                    // No provenance declared: this signal stands on its own root fact.
                    obsKey = "__nokey__" + (synthetic++);
                }

                if (!byObservation.TryGetValue(obsKey, out var vset))
                    byObservation[obsKey] = vset = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                vset.Add(vector);
            }

            // Each independent root observation contributes ONE leg regardless of how many
            // vector labels it tripped. Independence is the number of distinct root facts that
            // each carry at least one tamper vector.
            int independentLegs = 0;
            var seenVectors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in byObservation)
            {
                // Only count this observation if it introduces a tamper vector not already
                // proven by another independent observation - keeps two independent facts that
                // happen to share a vector label from double-counting either.
                bool introducesNew = false;
                foreach (var v in kv.Value)
                {
                    if (seenVectors.Add(v))
                        introducesNew = true;
                }
                if (introducesNew)
                    independentLegs++;
            }

            return independentLegs;
        }

        /// <summary>Distinct tamper-vector label so 2 hits of the SAME vector don't self-confirm.</summary>
        private static string NetworkTamperVector(DetectionEvent s)
        {
            var n = s.RuleName ?? "";
            if (n.IndexOf("ARP Spoof", StringComparison.OrdinalIgnoreCase) >= 0) return "ARP";
            if (n.IndexOf("Network Bridge", StringComparison.OrdinalIgnoreCase) >= 0) return "Bridge";
            if (n.IndexOf("DNS", StringComparison.OrdinalIgnoreCase) >= 0) return "DNS";
            // "Gateway" (changed or a rogue secondary-adapter gateway appearing) must be checked
            // before the generic "Route" catch so it gets its own vector (a gateway redirect is a
            // distinct MitM leg from a route-table injection).
            if (n.IndexOf("Gateway", StringComparison.OrdinalIgnoreCase) >= 0) return "Gateway";
            if (n.IndexOf("New Adapter Appeared", StringComparison.OrdinalIgnoreCase) >= 0) return "NewAdapter";
            if (n.IndexOf("Route", StringComparison.OrdinalIgnoreCase) >= 0) return "Route";
            if (n.IndexOf("Adapter Disabled", StringComparison.OrdinalIgnoreCase) >= 0) return "AdapterDown";
            if (n.IndexOf("WPAD", StringComparison.OrdinalIgnoreCase) >= 0 ||
                n.IndexOf("Auto-Proxy PAC", StringComparison.OrdinalIgnoreCase) >= 0) return "WPAD";
            // Deauth and evil-twin are DISTINCT vectors: deauth + evil-twin together is the classic
            // two-step evil-twin sequence and should reach the shield on its own.
            if (n.IndexOf("Deauthentication Flood", StringComparison.OrdinalIgnoreCase) >= 0) return "WiFiDeauth";
            if (n.IndexOf("Evil Twin", StringComparison.OrdinalIgnoreCase) >= 0 ||
                n.IndexOf("BSSID Changed", StringComparison.OrdinalIgnoreCase) >= 0) return "WiFiEvilTwin";
            return "Other";
        }

        private void BufferNetworkTamper(DetectionEvent signal)
        {
            lock (_networkTamper)
            {
                _networkTamper.Add(signal);
                var cutoff = DateTime.UtcNow - CorrelationWindow;
                _networkTamper.RemoveAll(s => s.Timestamp < cutoff);
                while (_networkTamper.Count > 40)
                    _networkTamper.RemoveAt(0);
            }
        }

        /// <summary>
        /// v2.6.0: Emit the protective VPN-shield composite when >= 2 DISTINCT local network-tamper
        /// vectors (e.g. ARP spoof + DNS change, or bridge + route injection) are seen within the
        /// correlation window - multi-signal proof of an active LAN MitM. The composite authorizes
        /// <see cref="ResponseAction.VpnShieldUp"/> (a non-kill network-integrity remediation), NOT
        /// a process nuke: these signals originate from SYSTEM/PID 0 and there is no malicious
        /// process to terminate. The response engine still Tier1-guards it and re-checks
        /// <see cref="ProductPosture.AllowsVpnShield"/> before raising a tunnel.
        /// </summary>
        private async Task EvaluateNetworkTamperCompositeAsync()
        {
            if (_emitCallback == null) return;

            List<DetectionEvent> snapshot;
            lock (_networkTamper)
            {
                var cutoff = DateTime.UtcNow - CorrelationWindow;
                _networkTamper.RemoveAll(s => s.Timestamp < cutoff);
                snapshot = new List<DetectionEvent>(_networkTamper);
            }

            var vectors = snapshot.Select(NetworkTamperVector).Distinct().ToList();
            // Evidence-independence gate: distinct vector LABELS are not enough. Require >= 2
            // vectors that rest on INDEPENDENT root observations, so a single gateway/ARP event
            // that trips several detectors cannot self-confirm a MitM chain. Legacy signals with
            // no ObservationKey are treated as independent, so this only tightens, never loosens.
            if (CountIndependentTamperVectors(snapshot) < 2) return;

            // Re-emit cooldown so a burst of tamper signals doesn't spam shield actions
            // (the shield engine is single-flight anyway, but keep the log clean).
            if (DateTime.UtcNow - _lastVpnShieldEmit < VpnShieldReEmitCooldown) return;
            _lastVpnShieldEmit = DateTime.UtcNow;

            var vectorList = string.Join(" + ", vectors);
            var composite = new DetectionEvent
            {
                RuleName = "Network Tamper: Local MitM Chain",
                ProcessId = 0,
                ProcessName = "SYSTEM",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.VpnShieldUp,
                SignalType = SignalType.SecurityEvasion,
                Evidence = $"[COMPOSITE] Multiple independent local network-tamper vectors within the correlation window: {vectorList}.",
                Reasoning = "Two or more independent local-network tamper indicators (ARP poisoning, DNS " +
                            "redirection, route injection, adapter bridging) occurred together - proof of an " +
                            "active man-in-the-middle on the local path. Sentinel raises a protective VPN " +
                            "tunnel to shield the user's traffic while it cleans the network, then drops the " +
                            "tunnel once the path is verified clean.",
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    [ResponsePolicy.ChainConfirmedKey] = "true",
                    [ResponsePolicy.TerminalOutcomeKey] = "NetworkTamper",
                    ["MitmDefense"] = "true",
                    ["TamperVectors"] = vectorList
                }
            };

            await _emitCallback(composite);
        }
    }
}
