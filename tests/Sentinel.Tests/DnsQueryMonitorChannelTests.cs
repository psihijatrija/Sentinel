using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// docs/constraints.md testing contract, constraint (4): the DNS Client Operational
    /// channel enablement is a proactive host mutation (it changes OS event-log
    /// configuration). Its enforcement seam must gate on the always-on hardening posture
    /// (<see cref="ProductPosture.AllowsProactiveHostLockdown"/>), never on an independent
    /// flag, and the "deny" branch must exist as a single seam.
    ///
    /// DnsQueryMonitor itself performs NO detection-tier change in this changeset - it emits
    /// the same Tier1/Tier2 DNS rules as before - so constraints (1)-(3) are unaffected here.
    /// </summary>
    public class DnsQueryMonitorChannelTests
    {
        [Fact]
        public void EnableDnsChannel_IsAProactiveMutation_GatesOnProductPosture()
        {
            // Under the always-on hardening posture (v2.5.5+) the gate returns true for the
            // default config and even a null config - the deny branch exists as the single seam
            // a future posture change would honor.
            Assert.True(DnsQueryMonitor.MayEnableDnsChannel(new SentinelConfig()));
            Assert.True(DnsQueryMonitor.MayEnableDnsChannel(null));

            // The seam must be defined by ProductPosture, not an independent flag.
            Assert.Equal(
                ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()),
                DnsQueryMonitor.MayEnableDnsChannel(new SentinelConfig()));
        }
    }
}
