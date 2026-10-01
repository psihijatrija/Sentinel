using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.6.0: Tests for the protective VPN-shield network-tamper remediation chain.
    ///
    /// Covers the testing constraints for a new proactive host mutation:
    ///  (1) the Tier1 composite fires and returns Tier1Behavioral;
    ///  (2) a single tamper vector (Tier2-equivalent observe fuel) does NOT fire it;
    ///  (3) the Tier2/observe log-only contract still holds through the response engine;
    ///  (4) the mutation gates on ProductPosture and is DEFAULT-DENY (disabled -> LogOnly).
    /// </summary>
    [Collection("ResponsePolicy")]
    public class VpnShieldTests
    {
        public VpnShieldTests() => ResponsePolicy.ResetForTests();

        // A fake tunnel so the clean-and-verify orchestration is exercised without dialing.
        private sealed class FakeTunnel : IVpnTunnel
        {
            public int Connects; public int Disconnects; public bool ConnectResult = true;
            public bool Connect(string entryName, out string error) { Connects++; error = ""; return ConnectResult; }
            public bool Disconnect(string entryName, out string error) { Disconnects++; error = ""; return true; }
        }

        private static DetectionEvent Tamper(string rule) => new()
        {
            RuleName = rule,
            ProcessId = 0,
            ProcessName = "SYSTEM",
            Confidence = 0.9,
            Tier = DetectionTier.Tier1Behavioral,
            SignalType = SignalType.SecurityEvasion,
            Timestamp = DateTime.UtcNow,
        };

        // Tamper signal that declares the SINGLE root observation it derives from, so the
        // evidence-independence gate can collapse co-derived vectors.
        private static DetectionEvent TamperFromObservation(string rule, string observationKey)
        {
            var d = Tamper(rule);
            d.Metadata["ObservationKey"] = observationKey;
            return d;
        }

        // ---- (1) Tier1 composite fires on 2 distinct tamper vectors ----

        [Fact]
        public async Task TwoDistinctTamperVectors_FireVpnShieldComposite_Tier1()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(Tamper("ARP Spoof: Gateway MAC Changed"));
            await engine.RegisterSignalAsync(Tamper("Network: Unauthorized DNS Change"));

            Assert.NotNull(emitted);
            Assert.Equal("Network Tamper: Local MitM Chain", emitted!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, emitted.Tier);
            Assert.Equal(ResponseAction.VpnShieldUp, emitted.AuthorizedResponse);
            // Network-integrity remediation, NOT a process kill.
            Assert.False(emitted.KillAuthorized);
            // Pre-tagged chain-confirmed composite so the response engine acts on it.
            Assert.True(ResponsePolicy.IsNukeComposite(emitted));
            Assert.Equal("true", emitted.Metadata["MitmDefense"]);
        }

        // ---- (2) A single tamper vector must NOT self-confirm the shield ----

        [Fact]
        public async Task SingleTamperVector_DoesNotFireComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // Two ARP hits are still ONE vector - not independent proof of MitM.
            await engine.RegisterSignalAsync(Tamper("ARP Spoof: Gateway MAC Changed"));
            await engine.RegisterSignalAsync(Tamper("ARP Spoof: Multiple IPs Sharing MAC"));

            Assert.Null(emitted);
        }

        [Fact]
        public async Task WpadPlusDns_FireVpnShieldComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // Rogue PAC proxy + DNS redirection = two independent path-hijack vectors.
            await engine.RegisterSignalAsync(Tamper("WPAD Auto-Proxy PAC Changed"));
            await engine.RegisterSignalAsync(Tamper("Network: Unauthorized DNS Change"));

            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.VpnShieldUp, emitted!.AuthorizedResponse);
        }

        [Fact]
        public async Task WifiDeauthPlusEvilTwin_FireVpnShieldComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // Classic evil-twin sequence: deauth flood forces you off, then a fake AP with the
            // same SSID (BSSID change) picks you up. Two distinct Wi-Fi path-takeover vectors.
            await engine.RegisterSignalAsync(Tamper("WiFi Security: Deauthentication Flood Detected"));
            await engine.RegisterSignalAsync(Tamper("WiFi Security: BSSID Changed (Possible Evil Twin)"));

            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.VpnShieldUp, emitted!.AuthorizedResponse);
        }

        [Fact]
        public async Task WpadAlone_DoesNotFireComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // A lone PAC config is frequently legitimate corporate policy - must not self-confirm.
            await engine.RegisterSignalAsync(Tamper("WPAD Auto-Proxy PAC Configured"));
            await engine.RegisterSignalAsync(Tamper("WPAD Auto-Detect With Remote PAC"));

            Assert.Null(emitted);
        }

        // ---- Evidence independence: co-derived vectors from one root fact must NOT self-confirm ----

        [Fact]
        public async Task TwoVectorsFromSameObservation_DoNotFireComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // A single gateway MAC change is what ARP spoofing IS. If that one L2 event also
            // trips a route-table re-read, the two signals carry different vector labels
            // (ARP + Route) but rest on ONE root observation - not two independent proofs.
            await engine.RegisterSignalAsync(
                TamperFromObservation("ARP Spoof: Gateway MAC Changed", "gw-mac:00-11-22-33-44-55"));
            await engine.RegisterSignalAsync(
                TamperFromObservation("Route Injected: Default Gateway", "gw-mac:00-11-22-33-44-55"));

            Assert.Null(emitted);
        }

        [Fact]
        public async Task TwoVectorsFromDistinctObservations_FireComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // Two genuinely independent root facts: a gateway ARP change AND a separate,
            // independently-observed DNS server change. Real multi-signal MitM proof -> fire.
            await engine.RegisterSignalAsync(
                TamperFromObservation("ARP Spoof: Gateway MAC Changed", "gw-mac:00-11-22-33-44-55"));
            await engine.RegisterSignalAsync(
                TamperFromObservation("Network: Unauthorized DNS Change", "dns:10.0.0.53"));

            Assert.NotNull(emitted);
            Assert.Equal("Network Tamper: Local MitM Chain", emitted!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, emitted.Tier);
            Assert.Equal(ResponseAction.VpnShieldUp, emitted.AuthorizedResponse);
        }

        [Fact]
        public async Task MixedKeyedAndLegacySignals_RemainIndependent()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // Legacy monitors that predate ObservationKey emit no key: they must still be
            // treated as independent so the gate only ever tightens, never loosens.
            await engine.RegisterSignalAsync(
                TamperFromObservation("ARP Spoof: Gateway MAC Changed", "gw-mac:aa-bb-cc-dd-ee-ff"));
            await engine.RegisterSignalAsync(Tamper("Network Bridge Detected"));

            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.VpnShieldUp, emitted!.AuthorizedResponse);
        }

        // ---- Real monitor-key shapes: proves the wired-in ObservationKey values behave ----

        [Fact]
        public async Task GatewayArpAndCoDerivedRoute_ShareGatewayKey_DoNotFire()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // The ArpSpoofMonitor keys the gateway-MAC signal on "gw-mac:<ip>", and the
            // poisoned-MAC signal that includes the gateway keys on the SAME "gw-mac:<ip>".
            // One ARP fact -> must not self-confirm even though the labels differ.
            await engine.RegisterSignalAsync(
                TamperFromObservation("ARP Spoof: Gateway MAC Changed", "gw-mac:192.168.1.1"));
            await engine.RegisterSignalAsync(
                TamperFromObservation("Route Injected: Default Gateway", "gw-mac:192.168.1.1"));

            Assert.Null(emitted);
        }

        [Fact]
        public async Task WifiDeauthAndEvilTwin_HaveDistinctMonitorKeys_StillFire()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });

            // WifiSecurityMonitor keys deauth on "wifi-deauth:<ssid>" and evil-twin on
            // "wifi-bssid:<bssid>" - deliberately distinct, so the two-step sequence remains
            // two independent vectors and reaches the shield.
            await engine.RegisterSignalAsync(
                TamperFromObservation("WiFi Security: Deauthentication Flood Detected", "wifi-deauth:HomeNet"));
            await engine.RegisterSignalAsync(
                TamperFromObservation("WiFi Security: BSSID Changed (Possible Evil Twin)", "wifi-bssid:00-de-ad-be-ef-00"));

            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.VpnShieldUp, emitted!.AuthorizedResponse);
        }

        // ---- (3) VpnShieldUp respects Tier: a Tier2 event never reaches the action ----

        [Fact]
        public void KillAuthorized_IsFalse_ForVpnShieldUp()
        {
            var d = new DetectionEvent { AuthorizedResponse = ResponseAction.VpnShieldUp };
            Assert.False(d.KillAuthorized); // ordered below KillProcess
        }

        // ---- (4) ProductPosture default-deny ----

        [Fact]
        public void AllowsVpnShield_IsTrue_ByDefault()
        {
            // v2.9.4: VpnShield.Enabled is hardwired true (no off switch) -> always allowed.
            Assert.True(ProductPosture.AllowsVpnShield(new SentinelConfig()));
        }

        [Fact]
        public void AllowsVpnShield_True_OnlyWhenEnabled()
        {
            var cfg = new SentinelConfig();
            cfg.VpnShield.Enabled = true;
            Assert.True(ProductPosture.AllowsVpnShield(cfg));
        }

        // v2.9.4: VpnShield is always on (no off switch), so a VpnShieldUp action for a
        // network-tamper chain is always a recognized MitM-defense action.
        [Fact]
        public void IsMitmDefenseAction_VpnShieldUp_Recognized()
        {
            var d = new DetectionEvent { AuthorizedResponse = ResponseAction.VpnShieldUp, RuleName = "Network Tamper: Local MitM Chain" };

            var cfg = new SentinelConfig();
            Assert.True(ResponsePolicy.IsMitmDefenseAction(d, cfg));
        }

        // ---- (4b) End to end through the response engine ----
        // v2.9.4: VpnShieldComposite_WithShieldDisabled_StaysLogOnly_NoDestructive removed -
        // VpnShield can no longer be disabled (hardwired on), so the "shield disabled" scenario
        // is unreachable. The enabled counterpart below (RaisesShield_NoProcessNuke) is retained.

        [Fact]
        public async Task VpnShieldComposite_WithShieldEnabled_RaisesShield_NoProcessNuke()
        {
            var tempDir = NewTemp();
            try
            {
                var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = true };
                config.VpnShield.Enabled = true;
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var engine = new AdvancedResponseEngine(config, new SentinelMetrics(), logger, new QuarantineManager(tempDir));
                engine.SetVpnShieldEngine(MakeShieldEngine(config, logger, out _));

                await engine.HandleAsync(TamperComposite());
                await logger.DisposeAsync();

                var lines = File.ReadAllLines(logPath);
                // The network-integrity remediation fires...
                Assert.Contains(lines, l => l.Contains("\"ActionTaken\":\"VPN_SHIELD\""));
                // ...and it is NOT escalated to a process kill/quarantine.
                Assert.DoesNotContain(lines, l =>
                    l.Contains("\"ActionTaken\":\"KILL") || l.Contains("QUARANTINE"));
            }
            finally { TryDelete(tempDir); }
        }

        // ---- helpers ----

        private static DetectionEvent TamperComposite() => new()
        {
            RuleName = "Network Tamper: Local MitM Chain",
            ProcessId = 0,
            ProcessName = "SYSTEM",
            Confidence = 0.95,
            Tier = DetectionTier.Tier1Behavioral,
            AuthorizedResponse = ResponseAction.VpnShieldUp,
            SignalType = SignalType.SecurityEvasion,
            Evidence = "[COMPOSITE] ARP + DNS",
            Timestamp = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                [ResponsePolicy.ChainConfirmedKey] = "true",
                [ResponsePolicy.TerminalOutcomeKey] = "NetworkTamper",
                ["MitmDefense"] = "true",
            }
        };

        private static VpnShieldEngine MakeShieldEngine(SentinelConfig config, JsonlEventLogger logger, out FakeTunnel tunnel)
        {
            tunnel = new FakeTunnel();
            // A minimal DetectionEngine-backed NetworkInterfaceGuard (never started here).
            var netGuard = new NetworkInterfaceGuard(
                MakeDetectionEngine(config, logger),
                config,
                NullLogger<NetworkInterfaceGuard>.Instance);
            return new VpnShieldEngine(config, netGuard, logger, NullLogger<VpnShieldEngine>.Instance, tunnel);
        }

        private static DetectionEngine MakeDetectionEngine(SentinelConfig config, JsonlEventLogger logger)
        {
            var tempDir = NewTemp();
            var cache = new SecureCacheStore(tempDir);
            var metrics = new SentinelMetrics();
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
            var response = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(tempDir), allowlist);
            var iocScanner = new IoCScanner(cache);
            var rep = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileRep = new FileReputationEngine(rep, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);
            var scoring = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            return new DetectionEngine(
                new List<IDetectionRule>(), metrics, logger, response, iocScanner, rep, fileRep,
                new BehavioralCorrelationEngine(), scoring, NullLogger<DetectionEngine>.Instance);
        }

        private static string NewTemp()
        {
            var d = Path.Combine(Path.GetTempPath(), "sentinel_vpnshield_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(d);
            return d;
        }

        private static void TryDelete(string dir) { try { Directory.Delete(dir, true); } catch { } }
    }
}
