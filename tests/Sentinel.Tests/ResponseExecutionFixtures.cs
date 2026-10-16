using System;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;

namespace Sentinel.Tests
{
    internal sealed class ResponseProcessFixture : IResponseProcessOperations
    {
        public bool IdentityMatches { get; set; } = true;
        public bool TerminationSucceeds { get; set; } = true;
        public int TerminationCalls { get; private set; }
        public Action? BeforeTerminate { get; set; }
        public bool EvidenceMatches(int pid, DateTime evidenceUtc) => IdentityMatches && pid > 4;
        public bool TryTerminate(int pid, DateTime evidenceUtc, out string reason)
        {
            BeforeTerminate?.Invoke();
            TerminationCalls++;
            reason = "Isolated fixture process outcome; no operating-system process was accessed";
            return TerminationSucceeds;
        }
    }
    internal sealed class IsolationContainmentFixture : IIsolationContainment
    {
        public int Calls { get; private set; }
        public Task<bool> HandleIsoThreatAsync(int pid, string path, DateTime? time = null, CancellationToken ct = default)
        { Calls++; return Task.FromResult(true); }
        public Task HandleDockerThreatAsync(string id, CancellationToken ct = default)
        { Calls++; return Task.CompletedTask; }
        public Task HandleVmThreatAsync(int pid, string name, DateTime? time = null, CancellationToken ct = default)
        { Calls++; return Task.CompletedTask; }
    }
}
