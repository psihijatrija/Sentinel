using System;
using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for Net48Compat - polyfill helper classes that provide .NET 6+ APIs on .NET 4.8.
    /// </summary>
    public class Net48CompatTests
    {
        // 
        // ConvertHex
        // 

        [Fact]
        public void ConvertHex_ToHexString_EmptyArray_ReturnsEmpty()
        {
            Assert.Equal("", System.ConvertHex.ToHexString(Array.Empty<byte>()));
        }

        [Fact]
        public void ConvertHex_ToHexString_ProducesLowercase()
        {
            var bytes = new byte[] { 0xAB, 0xCD, 0xEF };
            var hex = System.ConvertHex.ToHexString(bytes);
            Assert.Equal("abcdef", hex);
        }

        [Fact]
        public void ConvertHex_RoundTrip()
        {
            var original = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            var hex = System.ConvertHex.ToHexString(original);
            var back = System.ConvertHex.FromHexString(hex);
            Assert.Equal(original, back);
        }

        [Fact]
        public void ConvertHex_FromHexString_UpperCase()
        {
            var bytes = System.ConvertHex.FromHexString("ABCDEF");
            Assert.Equal(new byte[] { 0xAB, 0xCD, 0xEF }, bytes);
        }

        [Fact]
        public void ConvertHex_FromHexString_EmptyString()
        {
            var bytes = System.ConvertHex.FromHexString("");
            Assert.Empty(bytes);
        }

        // 
        // MathNet48
        // 

        [Fact]
        public void MathNet48_Log2_KnownValues()
        {
            Assert.Equal(0.0, System.MathNet48.Log2(1.0));
            Assert.Equal(1.0, System.MathNet48.Log2(2.0), 10);
            Assert.Equal(3.0, System.MathNet48.Log2(8.0), 10);
            Assert.Equal(10.0, System.MathNet48.Log2(1024.0), 10);
        }

        [Theory]
        [InlineData(5, 0, 10, 5)]
        [InlineData(-5, 0, 10, 0)]
        [InlineData(15, 0, 10, 10)]
        [InlineData(0, 0, 0, 0)]
        public void MathNet48_Clamp_Int(int value, int min, int max, int expected)
        {
            Assert.Equal(expected, System.MathNet48.Clamp(value, min, max));
        }

        [Fact]
        public void MathNet48_Clamp_Double()
        {
            Assert.Equal(0.5, System.MathNet48.Clamp(0.5, 0.0, 1.0));
            Assert.Equal(0.0, System.MathNet48.Clamp(-1.0, 0.0, 1.0));
            Assert.Equal(1.0, System.MathNet48.Clamp(2.0, 0.0, 1.0));
        }

        [Fact]
        public void MathNet48_Clamp_Float()
        {
            Assert.Equal(0.5f, System.MathNet48.Clamp(0.5f, 0.0f, 1.0f));
            Assert.Equal(0.0f, System.MathNet48.Clamp(-1.0f, 0.0f, 1.0f));
            Assert.Equal(1.0f, System.MathNet48.Clamp(2.0f, 0.0f, 1.0f));
        }

        // 
        // Sha256Net48
        // 

        [Fact]
        public void Sha256Net48_HashData_ProducesCorrectLength()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("hello world");
            var hash = System.Security.Cryptography.Sha256Net48.HashData(data);
            Assert.Equal(32, hash.Length); // SHA-256 = 32 bytes
        }

        [Fact]
        public void Sha256Net48_HashData_Deterministic()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("test data");
            var hash1 = System.Security.Cryptography.Sha256Net48.HashData(data);
            var hash2 = System.Security.Cryptography.Sha256Net48.HashData(data);
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void Sha256Net48_HashData_DifferentInputs_DifferentHashes()
        {
            var hash1 = System.Security.Cryptography.Sha256Net48.HashData(new byte[] { 1 });
            var hash2 = System.Security.Cryptography.Sha256Net48.HashData(new byte[] { 2 });
            Assert.NotEqual(hash1, hash2);
        }

        // 
        // StringNet48
        // 

        [Fact]
        public void StringNet48_ReplaceIgnoreCase_Basic()
        {
            var result = StringNet48.ReplaceIgnoreCase("Hello WORLD test", "WORLD", "Earth");
            Assert.Contains("Earth", result);
        }

        [Fact]
        public void StringNet48_ReplaceIgnoreCase_NoMatch()
        {
            var result = StringNet48.ReplaceIgnoreCase("Hello", "xyz", "abc");
            Assert.Equal("Hello", result);
        }

        [Fact]
        public void StringNet48_Contains_CaseInsensitive()
        {
            Assert.True(StringNet48.Contains("Hello World", "WORLD", StringComparison.OrdinalIgnoreCase));
            Assert.False(StringNet48.Contains("Hello World", "WORLD", StringComparison.Ordinal));
        }

        [Fact]
        public void StringNet48_SplitLines_Basic()
        {
            var lines = StringNet48.SplitLines("line1\nline2\nline3");
            Assert.Equal(3, lines.Length);
            Assert.Equal("line1", lines[0]);
        }

        [Fact]
        public void StringNet48_SplitLines_WindowsLineEndings()
        {
            var lines = StringNet48.SplitLines("line1\r\nline2\r\nline3");
            Assert.Equal(3, lines.Length);
        }

        [Fact]
        public void StringNet48_Split_WithOptions()
        {
            var parts = StringNet48.Split("a,,b,,c", ",", StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(3, parts.Length);
        }

        [Fact]
        public void StringNet48_Join_Char()
        {
            var result = StringNet48.Join(',', "a", "b", "c");
            Assert.Equal("a,b,c", result);
        }

        // 
        // PathNet48
        // 

        [Theory]
        [InlineData(@"C:\Windows\System32", true)]
        [InlineData(@"D:\file.txt", true)]
        [InlineData(@"\\server\share", true)]
        [InlineData(@"relative\path", false)]
        [InlineData(@"file.txt", false)]
        public void PathNet48_IsPathFullyQualified(string path, bool expected)
        {
            Assert.Equal(expected, System.IO.PathNet48.IsPathFullyQualified(path));
        }

        // 
        // DictionaryNet48Extensions
        // 

        [Fact]
        public void DictionaryExtensions_GetValueOrDefault_KeyExists()
        {
            var dict = new Dictionary<string, string> { ["key"] = "value" };
            Assert.Equal("value", dict.GetValueOrDefault("key", "default"));
        }

        [Fact]
        public void DictionaryExtensions_GetValueOrDefault_KeyMissing()
        {
            var dict = new Dictionary<string, string>();
            Assert.Equal("default", dict.GetValueOrDefault("key", "default"));
        }

        // 
        // Net48Environment
        // 

        [Fact]
        public void Net48Environment_ProcessId_ReturnsPositive()
        {
            Assert.True(System.Net48Environment.ProcessId > 0);
        }

        [Fact]
        public void Net48Environment_TickCount64_ReturnsPositive()
        {
            Assert.True(System.Net48Environment.TickCount64 > 0);
        }
    }
}
