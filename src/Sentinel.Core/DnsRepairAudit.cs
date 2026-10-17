using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public sealed class DnsRepairAudit : IDnsRepairAudit
    {
        private readonly JsonlEventLogger _log;
        public DnsRepairAudit(JsonlEventLogger log) => _log = log;
        public Task WriteBeforeAsync(DnsRepairRecord record, string operation, CancellationToken ct)
            => WriteAsync("dns_repair_before", new { Record = record, Operation = operation }, ct);
        public Task WriteResultAsync(DnsRepairReceipt receipt, CancellationToken ct)
            => WriteAsync("dns_repair_result", receipt, ct);
        private async Task WriteAsync<T>(string type, T data, CancellationToken ct)
        {
            long dropped = _log.DroppedEvents;
            var before = _log.GetAuditCheckpoint();
            await _log.LogEventAsync(type, data, ct).ConfigureAwait(false);
            var after = _log.GetAuditCheckpoint();
            if (after == null || before != null && before.File == after.File && before.Sequence >= after.Sequence
                || _log.AuditIntegrityDegraded || _log.DroppedEvents != dropped)
                throw new InvalidOperationException("DNS repair audit could not be durably recorded.");
        }
    }
}
