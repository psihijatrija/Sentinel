using System;
using System.Diagnostics;
using System.Linq;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ProcessModuleAuditorTests
    {
        [Fact]
        public void AuditProcess_CurrentProcess_ReturnsModulesAndValidCounts()
        {
            int currentPid = Process.GetCurrentProcess().Id;
            var result = ProcessModuleAuditor.AuditProcess(currentPid);

            Assert.NotNull(result);
            Assert.Equal(currentPid, result.ProcessId);
            Assert.NotEmpty(result.ProcessName);
            Assert.True(result.TotalModules > 0, "Current process must have mapped modules");
            Assert.Equal(result.Modules.Count, result.TotalModules);
            Assert.Equal(result.TotalModules, result.AllowedModules + result.SuspiciousModules);
            Assert.Equal(result.TotalModules, result.SignedModules + result.UnsignedModules);

            // Test runner / .NET framework modules should include core OS/keep-tree libraries
            var allowedModules = result.Modules.Where(m => m.Allowed).ToList();
            Assert.NotEmpty(allowedModules);

            // Check that every module has base address and formatted size
            foreach (var mod in result.Modules)
            {
                Assert.False(string.IsNullOrEmpty(mod.Name));
                Assert.False(string.IsNullOrEmpty(mod.BaseAddressHex));
                Assert.False(string.IsNullOrEmpty(mod.SizeFormatted));
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        public void AuditProcess_SystemPids_HandledGracefully(int pid)
        {
            var result = ProcessModuleAuditor.AuditProcess(pid);
            Assert.NotNull(result);
            Assert.Equal(pid, result.ProcessId);
            Assert.Empty(result.Modules);
        }

        [Fact]
        public void GetActiveProcesses_ReturnsNonEmptyList()
        {
            var procs = ProcessModuleAuditor.GetActiveProcesses();
            Assert.NotNull(procs);
            Assert.NotEmpty(procs);

            int currentPid = Process.GetCurrentProcess().Id;
            Assert.Contains(procs, p => p.ProcessId == currentPid);
        }
    }
}
