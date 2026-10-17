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
            await _log.LogEventAsync(type, data, ct).ConfigureAwait(false);
            if (_log.AuditIntegrityDegraded || _log.DroppedEvents != dropped)
                throw new InvalidOperationException("DNS repair audit could not be durably recorded.");
        }
    }
}
