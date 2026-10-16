using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    /// <summary>The same context feature calculation is used by live fusion and historical rule replay.</summary>
    public static class TelemetryContextBuilder
    {
        public static FusedTelemetryContext Build(TelemetryEvent trigger, IEnumerable<TelemetryEvent> history, DateTime nowUtc)
        {
            var context = new FusedTelemetryContext { TriggeringEvent = trigger, ProcessId = trigger.ProcessId, ProcessName = trigger.ProcessName };
            var cutoff = nowUtc - TimeSpan.FromSeconds(60);
            foreach (var item in history)
            {
                if (item.Timestamp < cutoff) continue;
                context.EventCount60s++;
                if (item is NetworkTelemetry) context.HasNetworkActivity = true;
                else if (item is FileActivityTelemetry file && file.OperationType == "WRITE") context.HasFileWrites = true;
                else if (item is ThreatIntelTelemetry) context.HasSuspiciousAPIs = true;
            }
            return context;
        }
    }
}
