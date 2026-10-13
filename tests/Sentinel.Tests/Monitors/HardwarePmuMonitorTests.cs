using System;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Sentinel.Core.Monitors;
using Xunit;

namespace Sentinel.Tests.Monitors
{
    public class HardwarePmuMonitorTests
    {
        [Fact]
        public async Task StartAsync_DoesNotThrow()
        {
            var monitor = new HardwarePmuMonitor();
            var ct = CancellationToken.None;
            // Should complete without throwing even if capability is disabled
            await monitor.StartAsync(ct);
        }
    }

    public class FeatureFlagsTests
    {
        [Fact]
        public void DefaultValues_AreFalse()
        {
            var config = new SentinelConfig();
            Assert.False(config.EnableHardwarePmuMonitor, "Hardware PMU monitor should be disabled by default");
            Assert.False(config.EnableAiBehaviorScoring, "AI behavior scoring should be disabled by default");
            Assert.False(config.EnableDynamicSandboxing, "Dynamic sandboxing should be disabled by default");
        }
    }
}
