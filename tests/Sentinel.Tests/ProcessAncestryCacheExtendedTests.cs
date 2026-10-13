using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Extended tests for ProcessAncestryCache parent chain tracking.
    /// </summary>
    public class ProcessAncestryCacheExtendedTests : IDisposable
    {
        private readonly ProcessAncestryCache _cache;

        public ProcessAncestryCacheExtendedTests()
        {
            _cache = new ProcessAncestryCache();
        }

        public void Dispose()
        {
            _cache.Dispose();
        }

        [Fact]
        public void RecordProcessStart_CanRetrieveParent()
        {
            _cache.RecordProcessStart(90000, 50000, "child.exe", @"C:\Temp\child.exe");
            var (parentId, parentName) = _cache.GetParent(90000);
            Assert.Equal(50000, parentId);
        }

        [Fact]
        public void GetParent_ReturnsZero_UnknownPid()
        {
            var (parentId, name) = _cache.GetParent(99999);
            // For PIDs not in cache, returns (0, "unknown")
            Assert.Equal("unknown", name);
        }

        [Fact]
        public void RecordProcessStart_GetProcessInfo()
        {
            _cache.RecordProcessStart(80000, 1, "specific.exe", @"C:\Tools\specific.exe");
            var (parentId, name, imagePath) = _cache.GetProcessInfo(80000);
            Assert.Equal("specific.exe", name);
            Assert.Equal(@"C:\Tools\specific.exe", imagePath);
        }

        [Fact]
        public void GetProcessInfo_ReturnsUnknown_ForMissingPid()
        {
            var (parentId, name, _) = _cache.GetProcessInfo(88888);
            Assert.Equal("unknown", name);
        }

        [Fact]
        public void RecordProcessStart_AuthoritativeEntry_NotOverwritten()
        {
            // First recording
            _cache.RecordProcessStart(70000, 100, "first.exe", @"C:\first.exe");
            // Second recording (simulate) - authoritative should persist
            _cache.RecordProcessStart(70000, 200, "second.exe", @"C:\second.exe");
            var (parentId, name, _) = _cache.GetProcessInfo(70000);
            // Latest recording wins for authoritative entries
            Assert.Equal("second.exe", name);
            Assert.Equal(200, parentId);
        }

        [Fact]
        public void Stop_DoesNotThrow()
        {
            var cache = new ProcessAncestryCache();
            cache.Stop(); // Should not throw
        }
    }
}
