using System;
using System.Diagnostics;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class MemoryAnomalyScannerTests
    {
        [Fact]
        public void IsReflectivePeHeader_ValidDosAndPeHeader_ReturnsTrue()
        {
            var buffer = new byte[128];
            // DOS MZ magic at 0x00
            buffer[0] = (byte)'M';
            buffer[1] = (byte)'Z';

            // e_lfanew at offset 0x3C pointing to offset 0x40
            int peOffset = 0x40;
            byte[] offsetBytes = BitConverter.GetBytes(peOffset);
            Array.Copy(offsetBytes, 0, buffer, 0x3C, 4);

            // PE\0\0 signature at offset 0x40
            buffer[peOffset] = (byte)'P';
            buffer[peOffset + 1] = (byte)'E';
            buffer[peOffset + 2] = 0;
            buffer[peOffset + 3] = 0;

            bool isPe = MemoryAnomalyScanner.IsReflectivePeHeader(buffer, buffer.Length);
            Assert.True(isPe, "Buffer containing valid MZ and PE signature must be identified as reflective PE header");
        }

        [Fact]
        public void IsReflectivePeHeader_RandomOrZeroBytes_ReturnsFalse()
        {
            var zeroBuf = new byte[128];
            Assert.False(MemoryAnomalyScanner.IsReflectivePeHeader(zeroBuf, zeroBuf.Length));

            var randomBuf = new byte[128];
            new Random(42).NextBytes(randomBuf);
            Assert.False(MemoryAnomalyScanner.IsReflectivePeHeader(randomBuf, randomBuf.Length));
        }

        [Fact]
        public void IsReflectivePeHeader_MzOnlyWithoutPe_ReturnsFalse()
        {
            var buffer = new byte[128];
            buffer[0] = (byte)'M';
            buffer[1] = (byte)'Z';
            // Point to an offset without PE\0\0
            int peOffset = 0x40;
            Array.Copy(BitConverter.GetBytes(peOffset), 0, buffer, 0x3C, 4);
            buffer[peOffset] = (byte)'X';

            Assert.False(MemoryAnomalyScanner.IsReflectivePeHeader(buffer, buffer.Length));
        }

        [Fact]
        public void ScanProcess_CurrentProcess_ExecutesSafely()
        {
            int currentPid = Process.GetCurrentProcess().Id;
            var anomalies = MemoryAnomalyScanner.ScanProcess(currentPid);

            Assert.NotNull(anomalies);
            // Current process in test runner should not contain reflective PE headers in private memory
            Assert.DoesNotContain(anomalies, a => a.AnomalyType == MemoryAnomalyType.ReflectivePeHeader);
        }

        [Fact]
        public void DetectJitHost_DotNetHost_ReturnsTrue()
        {
            int currentPid = Process.GetCurrentProcess().Id;
            bool isJit = MemoryAnomalyScanner.DetectJitHost(currentPid);
            // Test runner is a .NET process loading clr.dll
            Assert.True(isJit);
        }

        [Fact]
        public void FormatProtectionAndType_ReturnsExpectedStrings()
        {
            Assert.Equal("PAGE_EXECUTE_READWRITE", MemoryAnomalyScanner.FormatProtection(NativeProcessMemory.ProtRWX));
            Assert.Equal("PAGE_EXECUTE_READ", MemoryAnomalyScanner.FormatProtection(NativeProcessMemory.ProtRX));
            Assert.Equal("PAGE_EXECUTE", MemoryAnomalyScanner.FormatProtection(NativeProcessMemory.ProtX));

            Assert.Equal("MEM_IMAGE", MemoryAnomalyScanner.FormatType(MemoryAnomalyScanner.MEM_IMAGE));
            Assert.Equal("MEM_PRIVATE", MemoryAnomalyScanner.FormatType(MemoryAnomalyScanner.MEM_PRIVATE));
            Assert.Equal("MEM_MAPPED", MemoryAnomalyScanner.FormatType(MemoryAnomalyScanner.MEM_MAPPED));
        }
    }
}
