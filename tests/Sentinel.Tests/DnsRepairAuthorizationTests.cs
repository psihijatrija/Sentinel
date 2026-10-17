using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class DnsRepairAuthorizationTests
    {
        [WindowsContainmentFact]
        public async Task IdentificationTokenUsesTheRealClientAdministratorRole()
        {
            using var identity = WindowsIdentity.GetCurrent();
            bool expected = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            Assert.Equal(expected, await CheckClient(TokenImpersonationLevel.Identification));
        }

        [WindowsContainmentFact]
        public async Task AnonymousPipeClientCannotApproveDnsMutation()
            => Assert.False(await CheckClient(TokenImpersonationLevel.Anonymous));

        [WindowsContainmentFact]
        public void WindowsDnsApiBindingCanQueryALiveAdapterWithoutChangingIt()
        {
            var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            var adapter = System.Linq.Enumerable.FirstOrDefault(adapters, a =>
                a.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up &&
                a.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback && Guid.TryParse(a.Id, out _));
            Assert.NotNull(adapter);
            WindowsDnsConfigurationBackend.ProbeNativeApi(new Guid(adapter!.Id));
        }

        private static async Task<bool> CheckClient(TokenImpersonationLevel level)
        {
            string name = "SentinelDnsAuth_" + Guid.NewGuid().ToString("N");
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, level);
            var connecting = client.ConnectAsync(5000);
            await server.WaitForConnectionAsync(deadline.Token);
            await connecting;
            await client.WriteAsync(new byte[] { 1 }, 0, 1, deadline.Token);
            var buffer = new byte[1];
            Assert.Equal(1, await server.ReadAsync(buffer, 0, 1, deadline.Token));
            return ServiceAgentIpcHost.IsAdministratorClient(server);
        }
    }
}
