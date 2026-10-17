using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ProxyObservationTests
    {
        [Theory]
        [InlineData("ProxyEnable", "0", "1")]
        [InlineData("ProxyServer", "malicious-before-start.example:8080", "approved.example:8080")]
        [InlineData("AutoConfigURL", null, "https://enterprise.example/proxy.pac")]
        public void UnattributedProxyChangesCannotAuthorizeRestorationOrDeletion(string name, string? before, string? after)
        {
            var observation = RegistryMonitor.BuildProxyChangeObservation("HKLM", "Fixture", name, before, after);
            Assert.Equal(DetectionTier.Tier2Indicator, observation.Tier);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.Equal(0, observation.ProcessId);
            Assert.Equal("true", observation.Metadata["WeakObserveSeed"]);
            Assert.Equal(before ?? "", observation.Metadata["PreviousObservedValue"]);
            Assert.Equal(after ?? "", observation.Metadata["CurrentValue"]);
            Assert.DoesNotContain("BaselineValue", observation.Metadata.Keys);
        }
    }
}
