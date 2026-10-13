using System;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.8.2 - "attacker adds his network to mine" coverage. Verifies that the two newly-wired
    /// network-tamper fuel signals - a NEW network adapter appearing (NetworkInterfaceGuard) and a
    /// default-gateway change (RouteTableMonitor) - now count as independent MitM legs that can
    /// raise the protective VPN-shield composite ("Network Tamper: Local MitM Chain"), while a lone
    /// signal still never self-confirms.
    ///
    /// These drive the correlation engine directly with PID-0 (SYSTEM) signals, matching how the
    /// real network monitors emit. The composite is captured via the Initialize emit callback.
    /// </summary>
    public class NetworkTamperFuelTests
    {
        private static DetectionEvent NewAdapterSignal(int index = 77) => new DetectionEvent
        {
            RuleName = "Network: New Adapter Appeared",
            ProcessId = 0,
            ProcessName = "SYSTEM",
            SignalType = SignalType.Generic,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            Timestamp = DateTime.UtcNow,
            Metadata = new System.Collections.Generic.Dictionary<string, string>
            {
                [BehavioralCorrelationEngine.ObservationKeyMeta] = $"new-adapter:{index}"
            }
        };

        private static DetectionEvent GatewayChangedSignal(string gw = "192.168.1.254") => new DetectionEvent
        {
            RuleName = "Network: Default Gateway Changed",
            ProcessId = 0,
            ProcessName = "SYSTEM",
            SignalType = SignalType.NetworkC2,
            Tier = DetectionTier.Tier1Behavioral,
            AuthorizedResponse = ResponseAction.NetworkIsolate,
            Timestamp = DateTime.UtcNow,
            Metadata = new System.Collections.Generic.Dictionary<string, string>
            {
                ["TargetIP"] = gw,
                [BehavioralCorrelationEngine.ObservationKeyMeta] = $"gw-change:{gw}"
            }
        };

        private static DetectionEvent ArpSpoofSignal(string gw = "192.168.1.1") => new DetectionEvent
        {
            RuleName = "ARP Spoof: Gateway MAC Changed",
            ProcessId = 0,
            ProcessName = "SYSTEM",
            SignalType = SignalType.NetworkC2,
            Tier = DetectionTier.Tier1Behavioral,
            AuthorizedResponse = ResponseAction.NetworkIsolate,
            Timestamp = DateTime.UtcNow,
            Metadata = new System.Collections.Generic.Dictionary<string, string>
            {
                [BehavioralCorrelationEngine.ObservationKeyMeta] = $"gw-mac:{gw}"
            }
        };

        [Fact]
        public async Task NewAdapter_PlusGatewayChange_RaisesMitmComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(NewAdapterSignal());
            Assert.Null(composite); // one vector - must not self-confirm

            await engine.RegisterSignalAsync(GatewayChangedSignal());

            Assert.NotNull(composite);
            Assert.Equal("Network Tamper: Local MitM Chain", composite!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
            Assert.Equal(ResponseAction.VpnShieldUp, composite.AuthorizedResponse);
        }

        [Fact]
        public async Task NewAdapter_PlusArpSpoof_RaisesMitmComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(NewAdapterSignal());
            await engine.RegisterSignalAsync(ArpSpoofSignal());

            Assert.NotNull(composite);
            Assert.Equal(ResponseAction.VpnShieldUp, composite!.AuthorizedResponse);
        }

        [Fact]
        public async Task NewAdapter_Alone_DoesNotRaiseComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Even two of the SAME vector (same observation) must not self-confirm.
            await engine.RegisterSignalAsync(NewAdapterSignal(index: 77));
            await engine.RegisterSignalAsync(NewAdapterSignal(index: 77));

            Assert.Null(composite);
        }

        [Fact]
        public async Task GatewayChange_Alone_DoesNotRaiseComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(GatewayChangedSignal());

            Assert.Null(composite);
        }

        // v2.8.3 - new non-default route and secondary-adapter gateway as tamper fuel.

        private static DetectionEvent NewRouteSignal(string key = "0A000000:FFFFFF00:C0A80101:5") => new DetectionEvent
        {
            RuleName = "Network: New Route Added",
            ProcessId = 0,
            ProcessName = "SYSTEM",
            SignalType = SignalType.Generic,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            Timestamp = DateTime.UtcNow,
            Metadata = new System.Collections.Generic.Dictionary<string, string>
            {
                [BehavioralCorrelationEngine.ObservationKeyMeta] = $"route:{key}"
            }
        };

        private static DetectionEvent AdditionalGatewaySignal(string ifId = "{IF-2}") => new DetectionEvent
        {
            RuleName = "Network: Additional Gateway Appeared",
            ProcessId = 0,
            ProcessName = "SYSTEM",
            SignalType = SignalType.Generic,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            Timestamp = DateTime.UtcNow,
            Metadata = new System.Collections.Generic.Dictionary<string, string>
            {
                [BehavioralCorrelationEngine.ObservationKeyMeta] = $"iface-gw:{ifId}"
            }
        };

        [Fact]
        public async Task NewRoute_PlusDnsChange_RaisesMitmComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(NewRouteSignal());
            Assert.Null(composite); // one vector alone

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Network: Unauthorized DNS Change",
                ProcessId = 0,
                ProcessName = "SYSTEM",
                SignalType = SignalType.NetworkC2,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                Timestamp = DateTime.UtcNow,
                Metadata = new System.Collections.Generic.Dictionary<string, string>
                {
                    [BehavioralCorrelationEngine.ObservationKeyMeta] = "dns-iface:{IF-1}"
                }
            });

            Assert.NotNull(composite);
            Assert.Equal(ResponseAction.VpnShieldUp, composite!.AuthorizedResponse);
        }

        [Fact]
        public async Task AdditionalGateway_PlusArpSpoof_RaisesMitmComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(AdditionalGatewaySignal());
            await engine.RegisterSignalAsync(ArpSpoofSignal());

            Assert.NotNull(composite);
            Assert.Equal(ResponseAction.VpnShieldUp, composite!.AuthorizedResponse);
        }

        [Fact]
        public async Task NewRoute_Alone_DoesNotRaiseComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(NewRouteSignal());

            Assert.Null(composite);
        }

        [Fact]
        public async Task AdditionalGateway_Alone_DoesNotRaiseComposite()
        {
            DetectionEvent? composite = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(AdditionalGatewaySignal());

            Assert.Null(composite);
        }
    }
}
