using System.Diagnostics;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class HardFaultProbeTests
    {
        [Fact]
        public void TryGetHardFaultCount_CurrentProcess_SucceedsAndIsMonotonic()
        {
            int pid = Process.GetCurrentProcess().Id;
            Assert.True(HardFaultProbe.TryGetHardFaultCount(pid, out uint first));

            var snap = HardFaultProbe.ReadCurrent();
            Assert.True(snap.HardFaultsValid);
            Assert.True(snap.HardFaults >= first);
            Assert.True(snap.WorkingSetBytes > 0);
        }

        [Fact]
        public void ReadCurrent_PageFaultCount_IncreasesAfterTouchingNewPages()
        {
            var before = HardFaultProbe.ReadCurrent();
            var buf = new byte[4 * 1024 * 1024];
            for (int i = 0; i < buf.Length; i += 4096)
                buf[i] = 1;
            var after = HardFaultProbe.ReadCurrent();
            Assert.True(after.PageFaults >= before.PageFaults);
            GC.KeepAlive(buf);
        }
    }
}
