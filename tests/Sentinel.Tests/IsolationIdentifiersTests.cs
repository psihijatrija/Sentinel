using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class IsolationIdentifiersTests
    {
        [Theory]
        [InlineData("--all", false)]
        [InlineData("-f", false)]
        [InlineData("name --force", false)]
        [InlineData("name\nother", false)]
        [InlineData("", false)]
        [InlineData("container_1.test-name", true)]
        public void ContainerReferencesCannotBecomeCommandOptions(string value, bool expected)
            => Assert.Equal(expected, IsolationIdentifiers.IsContainerReference(value));

        [Theory]
        [InlineData("vmms.exe", false)]
        [InlineData("svchost.exe", false)]
        [InlineData("vmwp.exe", true)]
        [InlineData("vmware-vmx.exe", true)]
        [InlineData("VBoxHeadless.exe", true)]
        public void SharedVmManagementServicesAreNotDedicatedWorkers(string image, bool expected)
            => Assert.Equal(expected, IsolationIdentifiers.IsDedicatedVmHostImage(image));

        [Fact]
        public void MutationRequiresFullImmutableIds()
        {
            Assert.True(IsolationIdentifiers.IsContainerId(new string('a', 64)));
            Assert.False(IsolationIdentifiers.IsContainerId("short-name"));
            Assert.False(IsolationIdentifiers.IsContainerId(new string('g', 64)));
            Assert.True(IsolationIdentifiers.IsImageId("sha256:" + new string('b', 64)));
            Assert.False(IsolationIdentifiers.IsImageId("--force"));
            Assert.False(IsolationIdentifiers.IsImageId("sha256:" + new string('a', 63)));
        }
    }
}
