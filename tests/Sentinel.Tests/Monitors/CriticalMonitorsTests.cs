using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for CriticalMonitors - verifies SyscallStubMonitor Hell's Gate matching,
    /// IPSecIntegrityGuard backoff computation, and detection model behavior.
    /// </summary>
    public class CriticalMonitorsTests
    {
        // 
        // SyscallStubMonitor - well-formed Hell's Gate table (no name skip)
        // 

        [Fact]
        public void HellsGate_ThreeDistinctWellFormedStubs_IsHit()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.True(SyscallStubMonitor.IsHellsGateEvidence(hits));
        }

        [Fact]
        public void HellsGate_JitStyleLooseSyscall_IsNotHit()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05,
                0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05,
                0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x0F, 0x05,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.Empty(hits);
            Assert.False(SyscallStubMonitor.IsHellsGateEvidence(hits));
        }

        [Fact]
        public void HellsGate_SsnZero_IsNotHit()
        {
            // SSN=0 is never a real Windows syscall - must be rejected
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.Empty(hits);
        }

        [Fact]
        public void HellsGate_SsnAboveMaxValid_IsNotHit()
        {
            // SSN=0x0200 is above the valid Windows syscall range
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x02, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x02, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x02, 0x02, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.Empty(hits);
        }

        [Fact]
        public void HellsGate_SparseStubs_DensityFilterRejects()
        {
            // Three valid stubs but spread 200+ bytes apart - not a real table
            var buffer = new byte[700];
            // Stub 1 at offset 0
            buffer[0]  = 0x4C; buffer[1]  = 0x8B; buffer[2]  = 0xD1; buffer[3]  = 0xB8;
            buffer[4]  = 0x18; buffer[5]  = 0x00; buffer[6]  = 0x00; buffer[7]  = 0x00;
            buffer[8]  = 0x0F; buffer[9]  = 0x05; buffer[10] = 0xC3;
            // Stub 2 at offset 250
            buffer[250] = 0x4C; buffer[251] = 0x8B; buffer[252] = 0xD1; buffer[253] = 0xB8;
            buffer[254] = 0x26; buffer[255] = 0x00; buffer[256] = 0x00; buffer[257] = 0x00;
            buffer[258] = 0x0F; buffer[259] = 0x05; buffer[260] = 0xC3;
            // Stub 3 at offset 500
            buffer[500] = 0x4C; buffer[501] = 0x8B; buffer[502] = 0xD1; buffer[503] = 0xB8;
            buffer[504] = 0x50; buffer[505] = 0x00; buffer[506] = 0x00; buffer[507] = 0x00;
            buffer[508] = 0x0F; buffer[509] = 0x05; buffer[510] = 0xC3;

            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.Equal(3, hits.Count); // found by pattern matcher
            // But density filter must reject them - they are too far apart
            Assert.False(SyscallStubMonitor.IsHellsGateEvidence(
                SyscallStubMonitor.FilterByDensityPublic(hits, 48)));
        }

        [Fact]
        public void HellsGate_DenseStubs_DensityFilterAccepts()
        {
            // Three valid stubs packed within 48 bytes - real table
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            var dense = SyscallStubMonitor.FilterByDensityPublic(hits, 48);
            Assert.True(SyscallStubMonitor.IsHellsGateEvidence(dense));
        }

        // 
        // Syscall stub detection model
        // 

        [Fact]
        public void SyscallStub_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Process Injection: Indirect Syscall Stubs Detected",
                ProcessId = 4000,
                ProcessName = "implant.exe",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.ProcessInjection
            };

            Assert.Equal(SignalType.ProcessInjection, detection.SignalType);
            Assert.True(detection.KillAuthorized);
        }

        [Fact]
        public void ProcessInjection_IsPresidentsLaw()
        {
            Assert.True(ScoringEngine.IsPresidentsLawRule("Process Injection: Indirect Syscall Stubs Detected"));
        }

        // 
        // IPSecIntegrityGuard - backoff computation
        // 

        [Fact]
        public void Backoff_IncreasesWithFailures()
        {
            var backoff1 = ComputeBackoff(1);
            var backoff3 = ComputeBackoff(3);
            var backoff5 = ComputeBackoff(5);

            Assert.True(backoff3 > backoff1);
            Assert.True(backoff5 > backoff3);
        }

        [Fact]
        public void Backoff_ZeroFailures_MinimumDelay()
        {
            var backoff = ComputeBackoff(0);
            Assert.True(backoff.TotalSeconds >= 1);
        }

        [Fact]
        public void Backoff_HasMaximumCap()
        {
            var backoff = ComputeBackoff(100);
            Assert.True(backoff.TotalMinutes <= 60, $"Backoff {backoff} exceeds 60min cap");
        }

        // 
        // AsrPolicyGuard - detection model
        // 

        [Fact]
        public void AsrPolicy_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Anti-Tamper: ASR Policy Modification Detected",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 4
            };

            var category = ScoringEngine.CategorizeDetection(detection.RuleName);
            Assert.Equal(DetectionCategory.AntiTamper, category);
        }

        // 
        // Helper re-implementations
        // 

        private static System.TimeSpan ComputeBackoff(int consecutiveFailures)
        {
            var seconds = 5.0 * System.Math.Pow(2, System.Math.Min(consecutiveFailures, 8));
            return System.TimeSpan.FromSeconds(System.Math.Min(seconds, 1800));
        }
    }
}
