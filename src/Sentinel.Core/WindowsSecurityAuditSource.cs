using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    public sealed class WindowsSecurityAuditSource : ISecurityAuditSource
    {
        private readonly ILogger<WindowsSecurityAuditSource> _logger;
        private const int MaxEvents = 200;
        private const int MaxDeviceEntries = 256;
        public WindowsSecurityAuditSource(ILogger<WindowsSecurityAuditSource> logger) => _logger = logger;

        public IEnumerable<HardeningAuditCheck> ReadRuntimeChecks(CancellationToken ct)
        {
            var results = new List<HardeningAuditCheck>();
            ReadRuntimeProvider(results, @"root\Microsoft\Windows\Defender", "MSFT_MpComputerStatus",
                new[] { "AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled" }, ct);
            ReadRuntimeProvider(results, @"root\Microsoft\Windows\DeviceGuard", "Win32_DeviceGuard",
                new[] { "VirtualizationBasedSecurityStatus" }, ct);
            return results;
        }

        private void ReadRuntimeProvider(List<HardeningAuditCheck> results, string scope, string className, string[] properties, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            int initialCount = results.Count;
            try
            {
                using var searcher = new ManagementObjectSearcher(scope, "SELECT " + string.Join(",", properties) + " FROM " + className);
                searcher.Options.Timeout = TimeSpan.FromSeconds(3);
                using var values = searcher.Get();
                foreach (ManagementObject instance in values)
                {
                    using (instance)
                    {
                        ct.ThrowIfCancellationRequested();
                        foreach (var property in properties)
                            results.Add(EvaluateRuntime(RuntimeLabel(property), instance[property]));
                        return;
                    }
                }
                foreach (var property in properties) results.Add(new HardeningAuditCheck { Name = RuntimeLabel(property), Detail = "Runtime provider returned no instance." });
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                results.RemoveRange(initialCount, results.Count - initialCount);
                _logger.LogDebug(ex, "[SecurityAudit] Runtime provider unavailable: {Provider}", className);
                foreach (var property in properties) results.Add(new HardeningAuditCheck { Name = RuntimeLabel(property), Detail = "Runtime provider unavailable: " + ex.GetType().Name });
            }
        }

        private static string RuntimeLabel(string property) => property switch
        {
            "AMServiceEnabled" => "Defender antimalware service",
            "AntivirusEnabled" => "Defender antivirus",
            "RealTimeProtectionEnabled" => "Defender real-time protection",
            "VirtualizationBasedSecurityStatus" => "Virtualization-based security",
            _ => property
        };

        internal static HardeningAuditCheck EvaluateRuntime(string name, object? value)
        {
            bool? active = name == "Virtualization-based security"
                ? value is uint state && state <= 2 ? state == 2 : (bool?)null
                : value is bool enabled ? enabled : (bool?)null;
            return new HardeningAuditCheck { Name = name,
                State = !active.HasValue ? "Unknown" : active.Value ? "ObservedActive" : "NeedsReview",
                Observed = value?.ToString() ?? "Unavailable",
                Detail = !active.HasValue ? "Runtime provider returned an unsupported or missing value." :
                    "Local runtime provider snapshot only; this is not a malware-free verdict or proof of every protection." +
                    (name == "Virtualization-based security" ? " VBS running does not by itself prove Credential Guard is running." : "") };
        }

        public AuditRegistryReading ReadPolicy(AuditPolicy policy, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = machine.OpenSubKey(policy.Key, false);
                return new AuditRegistryReading { Available = true, Value = key?.GetValue(policy.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SecurityAudit] Policy read unavailable: {Policy}", policy.Name);
                return new AuditRegistryReading { Detail = "Registry read unavailable: " + ex.GetType().Name };
            }
        }

        public AuditSection ReadHistory(string logName, int[] eventIds, DateTime startUtc, DateTime endUtc, CancellationToken ct)
        {
            var section = new AuditSection { Name = logName == "Security" ? "Logon history" :
                logName == "System" ? "Service installations" : "Scheduled task registrations" };
            int examined = 0, skipped = 0;
            try
            {
                string ids = string.Join(" or ", eventIds.Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture)));
                string query = "*[System[(" + ids + ") and TimeCreated[@SystemTime >= '" +
                    startUtc.ToString("o", CultureInfo.InvariantCulture) + "' and @SystemTime <= '" +
                    endUtc.ToString("o", CultureInfo.InvariantCulture) + "']]]";
                using var reader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, query) { ReverseDirection = true });
                section.State = "Available";
                while (examined <= MaxEvents)
                {
                    ct.ThrowIfCancellationRequested();
                    using var record = reader.ReadEvent(TimeSpan.FromSeconds(2));
                    if (record == null) break;
                    if (examined++ == MaxEvents) { section.State = "Partial"; break; }
                    try
                    {
                        var item = ParseEvent(record.ToXml());
                        if (item == null || !item.TimestampUtc.HasValue || item.TimestampUtc < startUtc || item.TimestampUtc > endUtc)
                        { skipped++; continue; }
                        section.Items.Add(item);
                    }
                    catch (Exception ex)
                    {
                        skipped++;
                        _logger.LogDebug(ex, "[SecurityAudit] Event could not be decoded in {Log}", logName);
                    }
                }
                if (skipped > 0) section.State = "Partial";
                section.Detail = "Retained events in the six-hour window only. Audit policy, retention and collection gaps can hide activity; zero records is not proof of no activity.";
                if (section.State == "Partial") section.Detail += " Results were capped at 200 events or some records could not be decoded.";
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SecurityAudit] Event source unavailable: {Log}", logName);
                section.State = examined > 0 ? "Partial" : "Unknown";
                section.Detail = "Event history unavailable or interrupted: " + ex.GetType().Name;
            }
            return section;
        }

        internal static AuditHistoryItem? ParseEvent(string xml)
        {
            using var input = new StringReader(xml);
            using var reader = XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
            var root = XDocument.Load(reader).Root;
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var system = root?.Element(ns + "System");
            if (!int.TryParse(system?.Element(ns + "EventID")?.Value, out int id)) return null;
            var data = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var field in root?.Element(ns + "EventData")?.Elements(ns + "Data") ?? Enumerable.Empty<XElement>())
            {
                var name = field.Attribute("Name")?.Value;
                if (name != null) data[name] = Bound(field.Value);
            }
            string Get(string name) => data.TryGetValue(name, out var value) ? value : "";
            DateTime? time = DateTime.TryParse(system?.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value,
                CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;
            var item = new AuditHistoryItem { TimestampUtc = time };
            switch (id)
            {
                case 4624:
                case 4625:
                    item.Kind = id == 4624 ? "Successful logon" : "Failed logon";
                    item.Account = Get("TargetDomainName") + "\\" + Get("TargetUserName");
                    item.Subject = Get("IpAddress");
                    item.Detail = "Logon type: " + Get("LogonType") + "; source address is an observation, not attacker identity.";
                    break;
                case 7045:
                    item.Kind = "Service installed"; item.Subject = Get("ServiceName"); item.Account = Get("AccountName");
                    item.Detail = "Service installation is not proof of malicious persistence.";
                    break;
                case 106:
                    item.Kind = "Scheduled task registered"; item.Subject = Get("TaskName"); item.Account = Get("UserContext");
                    item.Detail = "Task registration is not proof of malicious persistence.";
                    break;
                default: return null;
            }
            return item;
        }

        public AuditSection ReadDeviceUsage(DateTime startUtc, DateTime endUtc, CancellationToken ct)
        {
            var section = new AuditSection { Name = "Camera and microphone usage", State = "Available",
                Detail = "Usage timestamps from loaded interactive-user hives only; not proof of live capture or a complete access history." };
            int profiles = 0, stores = 0;
            try
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
                foreach (var sid in users.GetSubKeyNames().Where(IsInteractiveSid).Take(65))
                {
                    ct.ThrowIfCancellationRequested();
                    if (profiles++ == 64) { section.State = "Partial"; break; }
                    foreach (string capability in new[] { "webcam", "microphone" })
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var store = users.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\" + capability, false);
                            if (store == null) continue;
                            stores++;
                            ReadUsageChildren(store, sid, capability, startUtc, endUtc, section, ct);
                            using var unpackaged = store.OpenSubKey("NonPackaged", false);
                            if (unpackaged != null) ReadUsageChildren(unpackaged, sid, capability, startUtc, endUtc, section, ct);
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                        catch (Exception ex)
                        {
                            section.State = "Partial";
                            _logger.LogDebug(ex, "[SecurityAudit] Device usage profile could not be read");
                        }
                    }
                }
                if (profiles == 0) { section.State = "Unknown"; section.Detail = "No loaded interactive-user hives were available. Device access is unknown."; }
                else if (stores == 0 && section.State == "Available") { section.State = "Unknown"; section.Detail = "No readable camera/microphone usage stores were available in loaded user hives."; }
                if (section.State == "Partial") section.Detail += " Some entries were unavailable or collection limits were reached.";
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SecurityAudit] Device usage unavailable");
                section.State = "Unknown"; section.Detail = "Loaded-user registry enumeration unavailable: " + ex.GetType().Name;
            }
            return section;
        }

        private static bool IsInteractiveSid(string sid) => !sid.EndsWith("_Classes", StringComparison.Ordinal) &&
            (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.StartsWith("S-1-12-1-", StringComparison.Ordinal));

        private static void ReadUsageChildren(RegistryKey parent, string sid, string capability, DateTime startUtc, DateTime endUtc, AuditSection section, CancellationToken ct)
        {
            int examined = 0;
            foreach (string name in parent.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (name == "NonPackaged") continue;
                if (examined++ >= MaxDeviceEntries || section.Items.Count >= MaxDeviceEntries) { section.State = "Partial"; break; }
                using var key = parent.OpenSubKey(name, false);
                var time = FromFileTime(key?.GetValue("LastUsedTimeStart"));
                if (!time.HasValue || time < startUtc || time > endUtc) continue;
                section.Items.Add(new AuditHistoryItem { TimestampUtc = time, Kind = capability + " usage recorded",
                    Account = sid, Subject = Bound(name), Detail = "Recorded start timestamp; current capture state is not verified." });
            }
        }

        internal static DateTime? FromFileTime(object? value)
        {
            if (value is not long stamp || stamp <= 0) return null;
            try { return DateTime.FromFileTimeUtc(stamp); }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        private static string Bound(string text) => text.Length <= 512 ? text : text.Substring(0, 512);
    }
}
