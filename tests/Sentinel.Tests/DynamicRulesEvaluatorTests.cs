using System;
using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class DynamicRulesEvaluatorTests : IDisposable
    {
        private readonly string _tempDir;

        public DynamicRulesEvaluatorTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_dynrules_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void DynamicCondition_IsAllowedPropertyName_RejectsNull()
        {
            Assert.False(DynamicCondition.IsAllowedPropertyName(null));
        }

        [Fact]
        public void DynamicCondition_IsAllowedPropertyName_RejectsEmpty()
        {
            Assert.False(DynamicCondition.IsAllowedPropertyName(""));
        }

        [Fact]
        public void DynamicCondition_IsAllowedPropertyName_AcceptsValidNames()
        {
            Assert.True(DynamicCondition.IsAllowedPropertyName("ProcessName"));
            Assert.True(DynamicCondition.IsAllowedPropertyName("ProcessId"));
        }

        [Fact]
        public void Constructor_WithTestRulesPath_DoesNotThrow()
        {
            var rulesDir = Path.Combine(_tempDir, "rules");
            Directory.CreateDirectory(rulesDir);

            using var evaluator = new DynamicRulesEvaluator(rulesDir, NullLogger<DynamicRulesEvaluator>.Instance);
        }

        [Fact]
        public void Evaluate_EmptyRules_ReturnsNull()
        {
            var rulesDir = Path.Combine(_tempDir, "rules2");
            Directory.CreateDirectory(rulesDir);

            using var evaluator = new DynamicRulesEvaluator(rulesDir, NullLogger<DynamicRulesEvaluator>.Instance);

            var context = new FusedTelemetryContext
            {
                ProcessName = "test.exe",
                ProcessId = 1,
                TriggeringEvent = new ProcessTelemetry { ProcessId = 1, ProcessName = "test.exe", Timestamp = DateTime.UtcNow }
            };

            var result = evaluator.Evaluate(context);
            Assert.Null(result);
        }

        [Fact]
        public void DynamicCondition_Evaluate_ReturnsFalse_ForNullTarget()
        {
            var cond = new DynamicCondition();
            // Evaluating against null or mismatched targets should not crash
            Assert.False(cond.Evaluate(new object()));
        }
    }
}
