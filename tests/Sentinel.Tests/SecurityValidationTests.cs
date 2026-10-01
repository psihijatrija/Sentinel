using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class SecurityValidationTests
    {
        //  IsSafeFilename 

        [Theory]
        [InlineData("report.pdf")]
        [InlineData("my-file_v2.0.exe")]
        [InlineData("data123.csv")]
        public void IsSafeFilename_AcceptsSafeFilenames(string filename)
        {
            Assert.True(SecurityValidation.IsSafeFilename(filename));
        }

        [Theory]
        [InlineData("../../../etc/passwd")]
        [InlineData("..\\..\\windows\\system32\\config\\sam")]
        [InlineData("file\0name.exe")]
        [InlineData("file:stream.exe")]
        [InlineData("file<script>.exe")]
        [InlineData("file>output.exe")]
        [InlineData("file|pipe.exe")]
        [InlineData("file*glob.exe")]
        [InlineData("file?query.exe")]
        [InlineData("file\"quote.exe")]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void IsSafeFilename_RejectsDangerousFilenames(string? filename)
        {
            Assert.False(SecurityValidation.IsSafeFilename(filename!));
        }

        [Theory]
        [InlineData("CON")]
        [InlineData("PRN")]
        [InlineData("AUX")]
        [InlineData("NUL")]
        [InlineData("COM1")]
        [InlineData("COM9")]
        [InlineData("LPT1")]
        [InlineData("LPT9")]
        [InlineData("CON.txt")]
        [InlineData("NUL.exe")]
        public void IsSafeFilename_RejectsWindowsReservedNames(string filename)
        {
            Assert.False(SecurityValidation.IsSafeFilename(filename));
        }

        [Theory]
        [InlineData("path/traversal.exe")]
        [InlineData("path\\traversal.exe")]
        [InlineData("..file.exe")]
        [InlineData("file..exe")]
        public void IsSafeFilename_RejectsPathTraversal(string filename)
        {
            Assert.False(SecurityValidation.IsSafeFilename(filename));
        }

        //  IsPathWithinDirectory 

        [Theory]
        [InlineData(@"C:\ProgramData\Sentinel\Quarantine\file.quarantined", @"C:\ProgramData\Sentinel\Quarantine")]
        [InlineData(@"C:\ProgramData\Sentinel\Quarantine\sub\file.quarantined", @"C:\ProgramData\Sentinel\Quarantine")]
        public void IsPathWithinDirectory_AcceptsValidPaths(string fullPath, string expectedDir)
        {
            Assert.True(SecurityValidation.IsPathWithinDirectory(fullPath, expectedDir));
        }

        [Theory]
        [InlineData(@"C:\ProgramData\Sentinel\Quarantine\..\..\..\Windows\System32\config\sam", @"C:\ProgramData\Sentinel\Quarantine")]
        [InlineData(@"C:\Windows\System32\cmd.exe", @"C:\ProgramData\Sentinel\Quarantine")]
        [InlineData(@"D:\other\path\file.exe", @"C:\ProgramData\Sentinel\Quarantine")]
        public void IsPathWithinDirectory_RejectsPathTraversal(string fullPath, string expectedDir)
        {
            Assert.False(SecurityValidation.IsPathWithinDirectory(fullPath, expectedDir));
        }

        [Theory]
        [InlineData("", @"C:\ProgramData")]
        [InlineData(null, @"C:\ProgramData")]
        [InlineData(@"C:\file.exe", "")]
        [InlineData(@"C:\file.exe", null)]
        public void IsPathWithinDirectory_RejectsNullOrEmpty(string? fullPath, string? expectedDir)
        {
            Assert.False(SecurityValidation.IsPathWithinDirectory(fullPath!, expectedDir!));
        }

        //  IsPrivateIpAddress 

        [Theory]
        [InlineData("127.0.0.1")]
        [InlineData("::1")]
        [InlineData("localhost")]
        [InlineData("10.0.0.1")]
        [InlineData("10.255.255.255")]
        [InlineData("172.16.0.1")]
        [InlineData("172.31.255.255")]
        [InlineData("192.168.0.1")]
        [InlineData("192.168.255.255")]
        [InlineData("169.254.1.1")]
        public void IsPrivateIpAddress_DetectsPrivateAddresses(string ip)
        {
            Assert.True(SecurityValidation.IsPrivateIpAddress(ip));
        }

        [Theory]
        [InlineData("8.8.8.8")]
        [InlineData("1.1.1.1")]
        [InlineData("203.0.113.1")]
        [InlineData("45.33.32.156")]
        public void IsPrivateIpAddress_AllowsPublicAddresses(string ip)
        {
            Assert.False(SecurityValidation.IsPrivateIpAddress(ip));
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("   ")]
        public void IsPrivateIpAddress_TreatsNullAsPrivate(string? ip)
        {
            Assert.True(SecurityValidation.IsPrivateIpAddress(ip!));
        }

        //  IsValidProcessId 

        [Theory]
        [InlineData(1)]
        [InlineData(4)]
        [InlineData(1234)]
        [InlineData(65535)]
        [InlineData(999999)]
        public void IsValidProcessId_AcceptsValidPids(int pid)
        {
            Assert.True(SecurityValidation.IsValidProcessId(pid));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-999)]
        [InlineData(1000000)]
        [InlineData(int.MaxValue)]
        [InlineData(int.MinValue)]
        public void IsValidProcessId_RejectsInvalidPids(int pid)
        {
            Assert.False(SecurityValidation.IsValidProcessId(pid));
        }

        //  IsValidPort 

        [Theory]
        [InlineData(1)]
        [InlineData(80)]
        [InlineData(443)]
        [InlineData(8080)]
        [InlineData(65535)]
        public void IsValidPort_AcceptsValidPorts(int port)
        {
            Assert.True(SecurityValidation.IsValidPort(port));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(65536)]
        [InlineData(int.MaxValue)]
        public void IsValidPort_RejectsInvalidPorts(int port)
        {
            Assert.False(SecurityValidation.IsValidPort(port));
        }

        //  IsValidTimestamp 

        [Fact]
        public void IsValidTimestamp_AcceptsRecentTimestamp()
        {
            Assert.True(SecurityValidation.IsValidTimestamp(System.DateTime.UtcNow));
            Assert.True(SecurityValidation.IsValidTimestamp(System.DateTime.UtcNow.AddDays(-30)));
        }

        [Fact]
        public void IsValidTimestamp_RejectsOldTimestamp()
        {
            Assert.False(SecurityValidation.IsValidTimestamp(System.DateTime.UtcNow.AddDays(-400)));
            Assert.False(SecurityValidation.IsValidTimestamp(System.DateTime.MinValue));
        }

        [Fact]
        public void IsValidTimestamp_RejectsFutureTimestamp()
        {
            Assert.False(SecurityValidation.IsValidTimestamp(System.DateTime.UtcNow.AddDays(7)));
            Assert.False(SecurityValidation.IsValidTimestamp(System.DateTime.MaxValue));
        }

        //  SecureCompare 

        [Fact]
        public void SecureCompare_ReturnsTrueForEqualArrays()
        {
            var a = new byte[] { 1, 2, 3, 4, 5 };
            var b = new byte[] { 1, 2, 3, 4, 5 };
            Assert.True(SecurityValidation.SecureCompare(a, b));
        }

        [Fact]
        public void SecureCompare_ReturnsFalseForDifferentArrays()
        {
            var a = new byte[] { 1, 2, 3, 4, 5 };
            var b = new byte[] { 1, 2, 3, 4, 6 };
            Assert.False(SecurityValidation.SecureCompare(a, b));
        }

        [Fact]
        public void SecureCompare_ReturnsFalseForNull()
        {
            var a = new byte[] { 1, 2, 3 };
            Assert.False(SecurityValidation.SecureCompare(a, null));
            Assert.False(SecurityValidation.SecureCompare(null, a));
            Assert.False(SecurityValidation.SecureCompare(null, null));
        }

        //  VerifyAuthenticodeSignature 

        [Fact]
        public void VerifyAuthenticodeSignature_ReturnsFalseForNullOrEmpty()
        {
            Assert.False(SecurityValidation.VerifyAuthenticodeSignature(null!));
            Assert.False(SecurityValidation.VerifyAuthenticodeSignature(""));
        }

        [Fact]
        public void VerifyAuthenticodeSignature_ReturnsFalseForNonExistentFile()
        {
            Assert.False(SecurityValidation.VerifyAuthenticodeSignature(@"C:\non_existent_file_123456789.exe"));
        }
    }
}
