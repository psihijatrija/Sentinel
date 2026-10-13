using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    [Collection("ResponsePolicy")]
    public class ProtocolCoverageMonitorsTests
    {
        [Fact]
        public void MonitorTypes_LiveInSentinelCore()
        {
            Assert.Equal("Sentinel.Core", typeof(UdpFlowMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(IcmpAnomalyMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(WfpNetEventMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(VoipSessionMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(UserlandProtocolHeuristics).Namespace);
        }

        [Theory]
        [InlineData("powershell", true)]
        [InlineData("pwsh.exe", true)]
        [InlineData("cmd", true)]
        [InlineData("mshta", true)]
        [InlineData("chrome", false)]
        [InlineData("discord", false)]
        public void ScriptHost_Classification(string name, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.IsScriptHost(name));
        }

        [Theory]
        [InlineData("discord", true)]
        [InlineData("Discord.exe", true)]
        [InlineData("ms-teams", true)]
        [InlineData("zoom", true)]
        [InlineData("chrome", true)]
        [InlineData("steam", true)]
        [InlineData("obs64", true)]
        [InlineData("powershell", false)]
        [InlineData("malware", false)]
        public void KnownComms_NeverVoip(string name, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.IsKnownCommsProcess(name));
        }

        [Theory]
        [InlineData(5060, true)]
        [InlineData(5061, true)]
        [InlineData(3478, true)]
        [InlineData(19302, true)]
        [InlineData(1720, true)]
        [InlineData(4569, true)]
        [InlineData(443, false)]
        [InlineData(53, false)]
        public void VoipSignalingPorts(int port, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.IsVoipSignalingPort(port));
        }

        [Fact]
        public void Discord_SipBind_IsNotVoipVerdict()
        {
            var k = UserlandProtocolHeuristics.ClassifyVoip(
                "discord", @"C:\Users\x\AppData\Local\Discord\app.exe", 5060, 0, signalingPort: true);
            Assert.Equal(UserlandProtocolHeuristics.VoipVerdictKind.None, k);
        }

        [Fact]
        public void Powershell_SipBind_IsSipUnexpected()
        {
            var k = UserlandProtocolHeuristics.ClassifyVoip(
                "powershell", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 5060, 0, signalingPort: true);
            Assert.Equal(UserlandProtocolHeuristics.VoipVerdictKind.SipUnexpected, k);
            Assert.True(UserlandProtocolHeuristics.ConfidenceFor(k, scriptHost: true) >= 0.70);
        }

        [Fact]
        public void TempBinary_RtpBinds_IsHiddenRtp()
        {
            var k = UserlandProtocolHeuristics.ClassifyVoip(
                "payload", @"C:\Users\x\AppData\Local\Temp\payload.exe", 20000, rtpLikeBindCount: 4, signalingPort: false);
            Assert.Equal(UserlandProtocolHeuristics.VoipVerdictKind.HiddenRtpBinds, k);
        }

        [Fact]
        public void Chrome_Stun_IsSkipped()
        {
            var k = UserlandProtocolHeuristics.ClassifyVoip(
                "chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe", 3478, 0, signalingPort: true);
            Assert.Equal(UserlandProtocolHeuristics.VoipVerdictKind.None, k);
        }

        [Fact]
        public void Udp_LolbinNonDns_IsLolbinDatagram()
        {
            var k = UserlandProtocolHeuristics.ClassifyUdpBind(
                "powershell", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 5555, 1);
            Assert.Equal(UserlandProtocolHeuristics.UdpVerdictKind.LolbinDatagram, k);
        }

        [Fact]
        public void Udp_ClassicMalwarePort_FromUnknown()
        {
            var k = UserlandProtocolHeuristics.ClassifyUdpBind(
                "svc32", @"C:\Users\x\AppData\Roaming\svc32.exe", 69, 1);
            Assert.Equal(UserlandProtocolHeuristics.UdpVerdictKind.ClassicMalwarePort, k);
        }

        [Fact]
        public void Udp_SvchostDns_IsAmbient()
        {
            var k = UserlandProtocolHeuristics.ClassifyUdpBind(
                "svchost", @"C:\Windows\System32\svchost.exe", 53, 4);
            Assert.Equal(UserlandProtocolHeuristics.UdpVerdictKind.None, k);
        }

        [Fact]
        public void Udp_Discord_IsWorkSurface()
        {
            var k = UserlandProtocolHeuristics.ClassifyUdpBind(
                "discord", @"C:\Users\x\AppData\Local\Discord\app.exe", 50000, 12);
            Assert.Equal(UserlandProtocolHeuristics.UdpVerdictKind.None, k);
        }

        [Fact]
        public void Udp_SocketExplosion_FromUnknown()
        {
            var k = UserlandProtocolHeuristics.ClassifyUdpBind(
                "scanner", @"C:\Users\x\scanner.exe", 23456, 80);
            Assert.Equal(UserlandProtocolHeuristics.UdpVerdictKind.SocketExplosion, k);
        }

        [Fact]
        public void Icmp_Redirect_BeforeBaseline_IsNone()
        {
            var k = UserlandProtocolHeuristics.ClassifyIcmpDelta(0, inboundRedirects: 3, unreachPerSec: 0, baselineReady: false);
            Assert.Equal(UserlandProtocolHeuristics.IcmpVerdictKind.None, k);
        }

        [Fact]
        public void Icmp_Redirect_AfterBaseline_Wins()
        {
            var k = UserlandProtocolHeuristics.ClassifyIcmpDelta(80, inboundRedirects: 2, unreachPerSec: 90, baselineReady: true);
            Assert.Equal(UserlandProtocolHeuristics.IcmpVerdictKind.RedirectInbound, k);
        }

        [Fact]
        public void Icmp_EchoFlood()
        {
            var k = UserlandProtocolHeuristics.ClassifyIcmpDelta(50, 0, 0, baselineReady: true);
            Assert.Equal(UserlandProtocolHeuristics.IcmpVerdictKind.EchoFlood, k);
        }

        [Fact]
        public void Icmp_Quiet_IsNone()
        {
            var k = UserlandProtocolHeuristics.ClassifyIcmpDelta(1, 0, 2, baselineReady: true);
            Assert.Equal(UserlandProtocolHeuristics.IcmpVerdictKind.None, k);
        }

        [Theory]
        [InlineData(47, "GRE")]
        [InlineData(50, "ESP")]
        [InlineData(51, "AH")]
        [InlineData(132, "SCTP")]
        [InlineData(115, "L2TP")]
        [InlineData(41, "IPv6-encap")]
        public void UnusualIpProtocols_Named(byte proto, string name)
        {
            Assert.True(UserlandProtocolHeuristics.IsUnusualIpProtocol(proto));
            Assert.Equal(name, UserlandProtocolHeuristics.IpProtocolName(proto));
        }

        [Fact]
        public void TcpUdp_AreNotUnusual()
        {
            Assert.False(UserlandProtocolHeuristics.IsUnusualIpProtocol(6));
            Assert.False(UserlandProtocolHeuristics.IsUnusualIpProtocol(17));
        }

        [Fact]
        public void Wfp_EspFromPowershell_IsUnusual()
        {
            var k = UserlandProtocolHeuristics.ClassifyWfpEvent(
                50, UserlandProtocolHeuristics.WfpTypeClassifyAllow, "powershell",
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
            Assert.Equal(UserlandProtocolHeuristics.WfpVerdictKind.UnusualIpProtocol, k);
        }

        [Fact]
        public void Wfp_EspFromSvchost_IsVpnSkip()
        {
            var k = UserlandProtocolHeuristics.ClassifyWfpEvent(
                50, UserlandProtocolHeuristics.WfpTypeClassifyAllow, "svchost",
                @"C:\Windows\System32\svchost.exe");
            Assert.Equal(UserlandProtocolHeuristics.WfpVerdictKind.None, k);
        }

        [Fact]
        public void Wfp_IpsecKernelDrop()
        {
            var k = UserlandProtocolHeuristics.ClassifyWfpEvent(
                6, UserlandProtocolHeuristics.WfpTypeIpsecKernelDrop, "unknown", null);
            Assert.Equal(UserlandProtocolHeuristics.WfpVerdictKind.IPsecKernelDrop, k);
        }

        [Fact]
        public void Signals_AreTier2LogOnly_AndWeakChainOnly()
        {
            var events = new[]
            {
                new DetectionEvent
                {
                    RuleName = "Network UDP: LOLBin Datagram",
                    Confidence = 0.62,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessId = 4242,
                    ProcessName = "powershell",
                },
                new DetectionEvent
                {
                    RuleName = "Network ICMP: Redirect Inbound",
                    Confidence = 0.78,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessId = 0,
                    ProcessName = "SYSTEM",
                },
                new DetectionEvent
                {
                    RuleName = "Network WFP: Unusual IP Protocol",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessId = 4242,
                    ProcessName = "powershell",
                },
                new DetectionEvent
                {
                    RuleName = "Network VoIP: SIP from Unexpected Process",
                    Confidence = 0.78,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessId = 4242,
                    ProcessName = "powershell",
                },
            };

            foreach (var d in events)
            {
                Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
                Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
                Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
                Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
                Assert.False(ResponsePolicy.IsNukeComposite(d));
                Assert.Equal(DetectionCategory.NetworkAnomaly, ScoringEngine.CategorizeDetection(d.RuleName));
            }
        }

        [Fact]
        public void IcmpEchoFlood_WithWeakFlag_IsPureUx()
        {
            var d = new DetectionEvent
            {
                RuleName = "Network ICMP: Echo Flood",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessId = 0,
                Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" },
            };
            Assert.True(ResponsePolicy.IsPureUxObserveNoise(d));
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(d));
        }

        [Fact]
        public void AttackTechniqueMap_ProtocolRules()
        {
            var udp = AttackTechniqueMap.Resolve("Network UDP: LOLBin Datagram");
            Assert.Contains("T1071", udp);
            Assert.Contains("T1095", udp);

            var icmp = AttackTechniqueMap.Resolve("Network ICMP: Redirect Inbound");
            Assert.Contains("T1095", icmp);

            var voip = AttackTechniqueMap.Resolve("Network VoIP: SIP from Unexpected Process");
            Assert.Contains("T1123", voip);
            Assert.Contains("T1071", voip);

            var mesh = AttackTechniqueMap.Resolve("Covert Mesh: Userspace Overlay Tool");
            Assert.Contains("T1095", mesh);
            Assert.Contains("T1572", mesh);
        }

        [Theory]
        [InlineData("tailcat.dev", true)]
        [InlineData("https://tailcat.dev/derpmap.json", true)]
        [InlineData("derp1.tailscale.com", true)]
        [InlineData("derp.tailscale.com", true)]
        [InlineData("ny.derp.tailscale.com", true)]
        [InlineData("google.com", false)]
        [InlineData("discord.com", false)]
        public void CovertMeshDomains(string host, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.IsCovertMeshDomain(host));
        }

        [Theory]
        [InlineData("tailcat", true)]
        [InlineData("tailcat.exe", true)]
        [InlineData("wireproxy", true)]
        [InlineData("boringtun", true)]
        [InlineData("sliver-client", true)]
        [InlineData("tailscale", false)]
        [InlineData("chrome", false)]
        public void CovertMeshNames(string name, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.LooksLikeCovertMeshName(name));
        }

        [Fact]
        public void Tailcat_FromDownloads_IsNamedTool()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "tailcat",
                @"C:\Users\Admin\Downloads\tailcat-main\tailcat-main\tailcat.exe",
                nonAmbientUdpBinds: 1, hasStunPort: false, hasHttps: true, meshDnsRecently: true);
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.NamedTool, k);
        }

        [Fact]
        public void RenamedCopycat_Downloads_UdpHttps_IsUserWritableOverlay()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "svc32",
                @"C:\Users\Admin\Downloads\svc32.exe",
                nonAmbientUdpBinds: 2, hasStunPort: false, hasHttps: true, meshDnsRecently: false);
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.UserWritableOverlay, k);
        }

        [Fact]
        public void RenamedCopycat_StunAndHttps_IsHolePunch()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "payload",
                @"C:\Users\x\AppData\Roaming\payload.exe",
                nonAmbientUdpBinds: 1, hasStunPort: true, hasHttps: true, meshDnsRecently: false);
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.StunHolePunch, k);
        }

        [Fact]
        public void OfficialTailscale_IsSkipped()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "tailscale",
                @"C:\Program Files\Tailscale\tailscale.exe",
                nonAmbientUdpBinds: 4, hasStunPort: true, hasHttps: true, meshDnsRecently: true);
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.None, k);
        }

        [Fact]
        public void Discord_UdpHttps_IsSkipped()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "discord",
                @"C:\Users\x\AppData\Local\Discord\app.exe",
                nonAmbientUdpBinds: 8, hasStunPort: true, hasHttps: true, meshDnsRecently: false);
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.None, k);
        }

        [Fact]
        public void RandomProcess_UdpOnly_NoHttps_IsNone()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "notepad",
                @"C:\Windows\System32\notepad.exe",
                nonAmbientUdpBinds: 1, hasStunPort: false, hasHttps: false, meshDnsRecently: false);
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.None, k);
        }

        [Fact]
        public void CovertMesh_Signal_IsKillGradeC2()
        {
            ResponsePolicy.ResetForTests();
            var d = new DetectionEvent
            {
                RuleName = "Covert Mesh: Userspace Overlay Tool",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessId = 4242,
                ProcessName = "tailcat",
                SignalType = SignalType.NetworkC2,
            };
            Assert.False(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Equal("C2Beacon", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.True(ResponsePolicy.IsCovertChannelTerminal(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, new SentinelConfig
            {
                ActiveResponse = true,
                ObserveUntilChain = true,
                ChainConfirmMinSignals = 2,
                MinTier1Confidence = 0.85,
            }));
            Assert.Equal(DetectionCategory.NetworkAnomaly, ScoringEngine.CategorizeDetection(d.RuleName));
        }

        [Fact]
        public void CoercionPolicy_TreatsTailcatAsRemoteChannel()
        {
            Assert.True(CoercionAbusePolicy.IsRemoteAccessToolProcess("tailcat"));
            Assert.True(CoercionAbusePolicy.IsRemoteAccessToolProcess("tailcat.exe"));
        }

        [Fact]
        public void MonitorTypes_IncludeCovertMesh()
        {
            Assert.Equal("Sentinel.Core", typeof(CovertMeshMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(CovertWebhookMonitor).Namespace);
        }

        [Theory]
        [InlineData("webhook.site", true)]
        [InlineData("https://webhook.site/abc", true)]
        [InlineData("abc.interact.sh", true)]
        [InlineData("canarytokens.com", true)]
        [InlineData("discord.com", false)]
        [InlineData("google.com", false)]
        public void DedicatedWebhookSinks(string host, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.IsDedicatedWebhookSink(host));
        }

        [Theory]
        [InlineData("discord.com", true)]
        [InlineData("api.telegram.org", true)]
        [InlineData("hooks.slack.com", true)]
        [InlineData("cdn.discordapp.com", false)]
        public void CommsExfilHosts(string host, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.IsCommsExfilHost(host));
        }

        [Theory]
        [InlineData("curl https://discord.com/api/webhooks/1/token", true)]
        [InlineData("IWR https://api.telegram.org/bot123/sendMessage", true)]
        [InlineData("https://webhook.site/uuid", true)]
        [InlineData("notepad C:\\temp\\readme.txt", false)]
        public void WebhookUrlInContent(string text, bool expected)
        {
            Assert.Equal(expected, UserlandProtocolHeuristics.ContainsWebhookUrl(text));
        }

        [Fact]
        public void DiscordApp_IsSkippedForWebhook()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "discord", @"C:\Users\x\AppData\Local\Discord\app.exe",
                hasHttps: true, dedicatedDnsRecently: false, commsDnsRecently: true, urlInContent: false);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.None, k);
        }

        [Fact]
        public void Powershell_WebhookSite_IsDedicatedSink()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "powershell", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                hasHttps: true, dedicatedDnsRecently: true, commsDnsRecently: false, urlInContent: false);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.DedicatedSink, k);
        }

        [Fact]
        public void TempStealer_DiscordDnsAndHttps_IsCommsAbuse()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "payload", @"C:\Users\x\Downloads\payload.exe",
                hasHttps: true, dedicatedDnsRecently: false, commsDnsRecently: true, urlInContent: false);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.CommsPlatformAbuse, k);
        }

        [Fact]
        public void Chrome_DiscordHttps_IsSkipped()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                hasHttps: true, dedicatedDnsRecently: true, commsDnsRecently: true, urlInContent: true);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.None, k);
        }

        [Fact]
        public void Curl_WebhookUrl_IsUrlInContent()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "curl", @"C:\Users\x\Downloads\curl.exe",
                hasHttps: true, dedicatedDnsRecently: false, commsDnsRecently: false, urlInContent: true);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.UrlInContent, k);
        }

        [Fact]
        public void CovertWebhook_IsKillGradeC2()
        {
            ResponsePolicy.ResetForTests();
            var d = new DetectionEvent
            {
                RuleName = "Covert Webhook: Disposable Sink",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessId = 4242,
                ProcessName = "powershell",
                SignalType = SignalType.NetworkC2,
            };
            Assert.False(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Equal("C2Beacon", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.True(ResponsePolicy.IsCovertChannelTerminal(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, new SentinelConfig
            {
                ActiveResponse = true,
                ObserveUntilChain = true,
                ChainConfirmMinSignals = 2,
                MinTier1Confidence = 0.85,
            }));
            Assert.Equal(DetectionCategory.DataExfiltration, ScoringEngine.CategorizeDetection(d.RuleName));
            var techs = AttackTechniqueMap.Resolve(d.RuleName);
            Assert.Contains("T1041", techs);
        }

        [Fact]
        public void CovertChannel_PidZero_DoesNotNuke()
        {
            ResponsePolicy.ResetForTests();
            var d = new DetectionEvent
            {
                RuleName = "Covert Webhook: Disposable Sink Lookup",
                Confidence = 0.86,
                ProcessId = 0,
                ProcessName = "SYSTEM",
                SignalType = SignalType.NetworkC2,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            // v2.9.4: PID 0 no-nuke protection is observe-independent - enforced by
            // IsCovertChannelTerminal returning false (a SYSTEM/PID-0 origin is never a
            // covert-channel terminal). Observe-mode gating removed as a settable mode.
            Assert.False(ResponsePolicy.IsCovertChannelTerminal(d));
        }

        [Fact]
        public void Discord_StillSkipped_ForWebhookAndMesh()
        {
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.None,
                UserlandProtocolHeuristics.ClassifyWebhook(
                    "discord", @"C:\Users\x\AppData\Local\Discord\app.exe",
                    hasHttps: true, dedicatedDnsRecently: true, commsDnsRecently: true, urlInContent: true));
            Assert.Equal(UserlandProtocolHeuristics.CovertMeshKind.None,
                UserlandProtocolHeuristics.ClassifyCovertMesh(
                    "discord", @"C:\Users\x\AppData\Local\Discord\app.exe",
                    nonAmbientUdpBinds: 8, hasStunPort: true, hasHttps: true, meshDnsRecently: true));
        }
    }
}
