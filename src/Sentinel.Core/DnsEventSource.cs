using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Xml;
using System.Xml.Linq;

namespace Sentinel.Core
{
    public sealed class DnsQueryRecord
    {
        public long RecordId { get; set; }
        public string Domain { get; set; } = "";
        public string? Error { get; set; }
    }

    public interface IDnsEventSource
    {
        void Initialize(bool mayEnableChannel);
        IReadOnlyList<DnsQueryRecord> ReadQueries(CancellationToken ct);
    }

    public interface IDnsEventLogSource : IDnsEventSource { }

    /// <summary>Reads named DNS event data. Localized rendered messages are never a domain.</summary>
    public sealed class WindowsDnsEventSource : IDnsEventLogSource
    {
        internal const string ChannelName = "Microsoft-Windows-DNS-Client/Operational";
        private long _lastRecordId;
        private bool _initialized;

        public void Initialize(bool mayEnableChannel)
        {
            using var config = new EventLogConfiguration(ChannelName);
            if (!config.IsEnabled)
            {
                if (!mayEnableChannel)
                    throw new InvalidOperationException("DNS event channel is disabled and posture does not permit enabling it.");
                config.IsEnabled = true;
                config.SaveChanges();
            }
            // Start at the current end, rather than replaying the entire historic log as new queries.
            using var reader = new EventLogReader(new EventLogQuery(ChannelName, PathType.LogName)
                { ReverseDirection = true });
            using var latest = reader.ReadEvent();
            _lastRecordId = latest?.RecordId ?? 0;
            _initialized = true;
        }

        public IReadOnlyList<DnsQueryRecord> ReadQueries(CancellationToken ct)
        {
            if (!_initialized) throw new InvalidOperationException("DNS event source has not initialized.");
            // Check for a cleared/rolled-back channel so a record-ID reset cannot blind us forever.
            using (var latestReader = new EventLogReader(new EventLogQuery(ChannelName, PathType.LogName)
                { ReverseDirection = true }))
            using (var latest = latestReader.ReadEvent())
            {
                if ((latest?.RecordId ?? 0) < _lastRecordId) _lastRecordId = 0;
            }
            string query = "*[System[(EventID=3006) and EventRecordID > " +
                _lastRecordId.ToString(CultureInfo.InvariantCulture) + "]]";
            using var reader = new EventLogReader(new EventLogQuery(ChannelName, PathType.LogName, query));
            var result = new List<DnsQueryRecord>();
            // Bound each poll; the cursor continues from here next time. 3008 is the completion
            // for the same query and must not double the rapid-query count.
            long cursor = _lastRecordId;
            for (int i = 0; i < 4096; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record == null) break;
                long id = record.RecordId ?? 0;
                var domain = ParseQueryName(record.ToXml());
                cursor = id;
                // Advance past unusable records, but surface their loss. A malformed query must
                // not permanently poison the cursor and block every later valid event.
                result.Add(new DnsQueryRecord
                {
                    RecordId = id, Domain = domain ?? "",
                    Error = domain == null ? "DNS event contains no supported QueryName field; record skipped." : null
                });
            }
            _lastRecordId = cursor;
            return result;
        }

        internal static string? ParseQueryName(string xml)
        {
            using var text = new System.IO.StringReader(xml);
            using var reader = XmlReader.Create(text, new XmlReaderSettings
                { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
            var document = XDocument.Load(reader);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var name = document.Root?.Element(ns + "EventData")?.Elements(ns + "Data")
                .FirstOrDefault(e => string.Equals((string?)e.Attribute("Name"), "QueryName", StringComparison.OrdinalIgnoreCase))?.Value;
            return NormalizeQueryName(name);
        }

        internal static string? NormalizeQueryName(string? name)
        {
            if (name == null || string.IsNullOrWhiteSpace(name)) return null;
            if (name == ".") return "."; // valid DNS root, no domain heuristic applies
            name = name.TrimEnd('.').ToLowerInvariant();
            if (name.Length == 0 || name.Length > 253 || name.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return null;
            if (name.Split('.').Any(label => label.Length == 0 || label.Length > 63 ||
                label.Any(c => !char.IsLetterOrDigit(c) && c != '-' && c != '_'))) return null;
            return name;
        }
    }
}
