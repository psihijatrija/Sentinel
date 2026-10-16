using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ResponseOutcomeFlowTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "SentinelFlow_" + Guid.NewGuid().ToString("N"));
        private readonly ProcessAncestryCache _ancestry = new();
        private readonly ContextBus _bus = new(NullLogger<ContextBus>.Instance);
        private readonly JsonlEventLogger _log;
        private readonly IncidentManager _incidents;

        public ResponseOutcomeFlowTests()
        {
            Directory.CreateDirectory(_directory);
            _log = new JsonlEventLogger(Path.Combine(_directory, "events.jsonl"));
            _incidents = new IncidentManager(_ancestry, _log, NullLogger<IncidentManager>.Instance);
        }

        [Theory]
        [InlineData(ResponseExecutionStatus.Refused)]
        [InlineData(ResponseExecutionStatus.Attempted)]
        [InlineData(ResponseExecutionStatus.Failed)]
        [InlineData(ResponseExecutionStatus.PartiallyCompleted)]
        public async Task IncompleteResponseIsNotMarkedRespondedOrCachedAsSuccess(ResponseExecutionStatus status)
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            int calls = 0;
            using var coordinator = Coordinator(d => { calls++; return Task.FromResult(Receipt(d, status)); });
            var first = await coordinator.ExecuteResponseAsync(detection, incident.Id);
            await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(2, calls);
            Assert.Equal(status, first.Execution!.Status);
            Assert.NotEqual(ResponseOutcome.Verified, first.Outcome);
            Assert.Equal(IncidentState.Active, incident.State);
            Assert.Null(incident.RespondedAt);
            Assert.Equal(status, incident.ResponseStatus);
            Assert.Equal(2, incident.ResponseAttempts.Count);
            Assert.Equal(0, coordinator.GetStats().TotalExecuted);
        }

        [Fact]
        public async Task VerifiedRequestedActionMarksRespondedAndDeduplicatesExactAction()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            int calls = 0;
            using var coordinator = Coordinator(d => { calls++; return Task.FromResult(Receipt(d, ResponseExecutionStatus.Verified)); });
            var result = await coordinator.ExecuteResponseAsync(detection, incident.Id);
            var duplicate = await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(ResponseOutcome.Verified, result.Outcome);
            Assert.Equal(ResponseOutcome.Deduplicated, duplicate.Outcome);
            Assert.Equal(1, calls);
            Assert.Equal(IncidentState.Responded, incident.State);
            Assert.NotNull(incident.RespondedAt);
            Assert.Equal(1, coordinator.GetStats().TotalExecuted);
        }

        [Fact]
        public async Task EnumOrderingDoesNotDeduplicateDifferentActionKinds()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            int calls = 0;
            using var coordinator = Coordinator(d => { calls++; return Task.FromResult(Receipt(d, ResponseExecutionStatus.Verified)); });
            await coordinator.ExecuteResponseAsync(detection, incident.Id);
            detection.AuthorizedResponse = ResponseAction.RemoveCert;
            var second = await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(2, calls);
            Assert.Equal(ResponseOutcome.Verified, second.Outcome);
        }

        [Fact]
        public async Task MismatchedReceiptCannotCompleteAnIncident()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            using var coordinator = Coordinator(d =>
            {
                var receipt = Receipt(d, ResponseExecutionStatus.Verified);
                receipt.ProcessId++;
                return Task.FromResult(receipt);
            });
            var result = await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(ResponseOutcome.Failed, result.Outcome);
            Assert.Equal(IncidentState.Active, incident.State);
        }

        [Fact]
        public async Task ExecutorExceptionRemainsRetryableAndVisibleOnIncident()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            int calls = 0;
            using var coordinator = Coordinator(d => { calls++; throw new InvalidOperationException("denied"); });
            await coordinator.ExecuteResponseAsync(detection, incident.Id);
            await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(2, calls);
            Assert.Equal(ResponseExecutionStatus.Failed, incident.LastResponse!.Status);
            Assert.Equal("denied", incident.LastResponse.Reason);
        }

        [Fact]
        public async Task ExactIncidentIdRecordsHostWideResponsesWithoutAPidMapping()
        {
            var detection = Detection();
            detection.ProcessId = 0;
            detection.AuthorizedResponse = ResponseAction.RemoveCert;
            var incident = _incidents.RegisterDetection(detection);
            using var coordinator = Coordinator(d => Task.FromResult(Receipt(d, ResponseExecutionStatus.Verified)));
            await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(IncidentState.Responded, incident.State);
            Assert.Equal(ResponseExecutionStatus.Verified, incident.ResponseStatus);
        }

        [Fact]
        public void LogOnlyObservationCannotEraseAnUnresolvedResponse()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            _incidents.RecordResponse(incident.Id, Receipt(detection, ResponseExecutionStatus.Failed));
            detection.AuthorizedResponse = ResponseAction.LogOnly;
            _incidents.RecordResponse(incident.Id, new ResponseExecutionResult());
            Assert.Equal(IncidentState.Active, incident.State);
            Assert.Equal(ResponseExecutionStatus.Failed, incident.ResponseStatus);
            Assert.Single(incident.ResponseAttempts);
        }

        [Fact]
        public void FreshActionableEvidenceReopensPreviouslyRespondedIncident()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            _incidents.RecordResponse(incident.Id, Receipt(detection, ResponseExecutionStatus.Verified));
            _incidents.RegisterDetection(detection);
            Assert.Equal(IncidentState.Active, incident.State);
            Assert.Null(incident.RespondedAt);
            Assert.Null(incident.ResponseAction);
        }

        [Fact]
        public async Task TrustedInlineOutcomeIsRecordedWithoutSuccessfulActionDeduplication()
        {
            var detection = Detection();
            var verified = Receipt(detection, ResponseExecutionStatus.Verified);
            detection.AuthorizedResponse = ResponseAction.LogOnly;
            detection.RecordedExecution = verified;
            var incident = _incidents.RegisterDetection(detection);
            int calls = 0;
            using var coordinator = Coordinator(d => { calls++; return Task.FromResult(d.RecordedExecution!); });
            await coordinator.ExecuteResponseAsync(detection, incident.Id);
            detection.RecordedExecution = new ResponseExecutionResult
            {
                ProcessId = detection.ProcessId, RequestedAction = verified.RequestedAction,
                EffectiveAction = verified.EffectiveAction, CompletedAt = DateTimeOffset.UtcNow
            };
            detection.RecordedExecution.Add("ProcessTree", "fixture", ResponseExecutionStatus.Failed, "Later inline action failed.");
            var second = await coordinator.ExecuteResponseAsync(detection, incident.Id);
            Assert.Equal(2, calls);
            Assert.Equal(ResponseOutcome.Failed, second.Outcome);
            Assert.Equal(IncidentState.Active, incident.State);
        }

        [Fact]
        public void SerializedTelemetryCannotSupplyAnInlineExecutionReceipt()
        {
            var detection = Detection();
            detection.RecordedExecution = Receipt(detection, ResponseExecutionStatus.Verified);
            using var json = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(detection));
            Assert.False(json.RootElement.TryGetProperty("RecordedExecution", out _));
            var untrusted = System.Text.Json.JsonSerializer.Deserialize<DetectionEvent>(
                "{\"ProcessId\":500001,\"RecordedExecution\":{\"RequestedAction\":\"KillProcessTree\",\"Status\":\"Verified\"}}");
            Assert.Null(untrusted!.RecordedExecution);
        }

        [Fact]
        public void OlderSuccessfulReceiptCannotEraseANewerFailedResponse()
        {
            var detection = Detection();
            var incident = _incidents.RegisterDetection(detection);
            var older = Receipt(detection, ResponseExecutionStatus.Verified);
            var newer = Receipt(detection, ResponseExecutionStatus.Failed);
            newer.CompletedAt = older.CompletedAt!.Value.AddSeconds(1);
            _incidents.RecordResponse(incident.Id, newer);
            _incidents.RecordResponse(incident.Id, older);
            Assert.Equal(IncidentState.Active, incident.State);
            Assert.Equal(ResponseExecutionStatus.Failed, incident.ResponseStatus);
            Assert.Same(newer, incident.LastResponse);
            Assert.Equal(2, incident.ResponseAttempts.Count);
        }

        [Fact]
        public void ReceiptPredatingNewActionableEvidenceCannotCompleteItsIncident()
        {
            var detection = Detection();
            var receipt = Receipt(detection, ResponseExecutionStatus.Verified);
            receipt.CompletedAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            var incident = _incidents.RegisterDetection(detection);
            _incidents.RecordResponse(incident.Id, receipt);
            Assert.NotEqual(IncidentState.Responded, incident.State);
            Assert.Null(incident.RespondedAt);
        }

        private ResponseCoordinator Coordinator(Func<DetectionEvent, Task<ResponseExecutionResult>> executor)
            => new(executor, _incidents, _bus, _log, NullLogger<ResponseCoordinator>.Instance);
        private static DetectionEvent Detection() => new()
        {
            ProcessId = 500001, ProcessName = "fixture.exe", RuleName = "Fixture", Confidence = 0.99,
            Tier = DetectionTier.Tier1Behavioral, AuthorizedResponse = ResponseAction.KillProcessTree
        };
        private static ResponseExecutionResult Receipt(DetectionEvent detection, ResponseExecutionStatus status)
        {
            var result = new ResponseExecutionResult
            {
                ProcessId = detection.ProcessId, RequestedAction = detection.AuthorizedResponse.ToString(),
                EffectiveAction = detection.AuthorizedResponse.ToString(), CompletedAt = DateTimeOffset.UtcNow
            };
            if (status == ResponseExecutionStatus.PartiallyCompleted)
            {
                result.Add("ProcessTree", "fixture", ResponseExecutionStatus.Verified, "Root exited.");
                result.Add("ProcessTree", "fixture child", ResponseExecutionStatus.Failed, "Child survived.");
            }
            else if (detection.AuthorizedResponse == ResponseAction.RemoveCert)
                for (int i = 0; i < 4; i++)
                    result.Add("CertificateRemoval", "fixture store " + i, status, "Injected store outcome.");
            else result.Add("ProcessTree", detection.ProcessId.ToString(), status, "Injected executor outcome.");
            return result;
        }
        public void Dispose()
        {
            _incidents.Dispose();
            _ancestry.Dispose();
            _bus.Dispose();
            _log.DisposeAsync().AsTask().GetAwaiter().GetResult();
            Directory.Delete(_directory, true);
        }
    }
}
