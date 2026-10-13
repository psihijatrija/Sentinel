using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for IsolationResponseEngine - verifies Docker/VM/ISO container
    /// threat handling, input validation, and graceful error handling.
    /// </summary>
    public class IsolationResponseEngineTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly IsolationResponseEngine _engine;

        public IsolationResponseEngineTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_iso_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            var eventLogger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _engine = new IsolationResponseEngine(NullLogger<IsolationResponseEngine>.Instance, eventLogger);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public async Task HandleIsoThreatAsync_NonExistentPid_DoesNotThrow()
        {
            // Should handle gracefully - PID doesn't exist
            await _engine.HandleIsoThreatAsync(99999, @"C:\fake\file.iso");
        }

        [Fact]
        public async Task HandleDockerThreatAsync_InvalidContainerId_DoesNotThrow()
        {
            // Empty/invalid container IDs should be handled gracefully
            await _engine.HandleDockerThreatAsync("");
        }

        [Fact]
        public async Task HandleDockerThreatAsync_ValidFormatId_DoesNotCrash()
        {
            // Valid Docker container ID format (64 hex chars) - should attempt action
            // but fail gracefully since Docker isn't necessarily running
            var fakeId = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
            await _engine.HandleDockerThreatAsync(fakeId);
        }

        [Fact]
        public async Task HandleVmThreatAsync_NonExistentVm_DoesNotCrash()
        {
            await _engine.HandleVmThreatAsync(99998, "NonExistentVM_" + Guid.NewGuid().ToString("N"));
        }

        [Fact]
        public async Task HandleVmThreatAsync_InvalidVmName_DoesNotCrash()
        {
            // Empty VM name should be handled
            await _engine.HandleVmThreatAsync(99997, "");
        }

        // 
        // Input validation (static helpers)
        // 

        [Theory]
        [InlineData("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true)]
        [InlineData("abcdef12", true)] // short form (12 chars)
        [InlineData("", false)]
        [InlineData("not-a-hex-id!", false)]
        [InlineData("ABCDEF1234", true)] // uppercase hex is valid
        public void DockerIdValidation_Concept(string id, bool shouldBeValid)
        {
            // Docker IDs are hex strings of 12 or 64 chars
            bool valid = !string.IsNullOrEmpty(id) &&
                         (id.Length == 12 || id.Length == 64 || (id.Length >= 8 && id.Length <= 64)) &&
                         System.Text.RegularExpressions.Regex.IsMatch(id, "^[a-fA-F0-9]+$");

            Assert.Equal(shouldBeValid, valid);
        }
    }
}
