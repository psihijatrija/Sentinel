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
        [Fact]
        public void UnavailableRepairStorageDoesNotPreventServiceConstructionButRefusesAccess()
        {
            string path = Path.Combine(Path.GetTempPath(), "SentinelDnsStorage_" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(path, "A file blocks directory creation.");
            try
            {
                var journal = new DnsRepairJournal(path);
                Assert.Throws<IOException>(() => journal.ReadAll());
            }
            finally { File.Delete(path); }
        }

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
            // Isolate Windows token impersonation from xUnit's async execution context.
            // A stalled OS call must fail this test, not hold the entire test host open.
            var result = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            string stage = "starting dedicated pipe thread";
            var worker = new Thread(() =>
            {
                try
                {
                    bool approved;
                    string name = "SentinelDnsAuth_" + Guid.NewGuid().ToString("N");
                    using (var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                    using (var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, level))
                    {
                        Volatile.Write(ref stage, "connecting pipe");
                        var connecting = client.ConnectAsync(5000);
                        server.WaitForConnection();
                        connecting.GetAwaiter().GetResult();
                        Volatile.Write(ref stage, "starting identity read");
                        var buffer = new byte[1];
                        var reading = server.ReadAsync(buffer, 0, 1);
                        Volatile.Write(ref stage, "writing client identity byte");
                        client.WriteAsync(new byte[] { 1 }, 0, 1).GetAwaiter().GetResult();
                        Volatile.Write(ref stage, "finishing identity read");
                        Assert.Equal(1, reading.GetAwaiter().GetResult());
                        Assert.Equal(1, buffer[0]);
                        Volatile.Write(ref stage, "checking actual client administrator token");
                        approved = ServiceAgentIpcHost.IsAdministratorClient(server);
                        Volatile.Write(ref stage, "disposing connected pipes");
                    }
                    result.TrySetResult(approved);
                }
                catch (Exception ex) { result.TrySetException(ex); }
            }) { IsBackground = true, Name = "Sentinel DNS pipe authorization fixture" };
            worker.Start();
            if (await Task.WhenAny(result.Task, Task.Delay(TimeSpan.FromSeconds(15))).ConfigureAwait(false) != result.Task)
                throw new TimeoutException("DNS authorization fixture stalled while " + Volatile.Read(ref stage));
            return await result.Task.ConfigureAwait(false);
        }
    }
}
