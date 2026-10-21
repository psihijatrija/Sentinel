using System;
using System.Diagnostics;

namespace NanoAV
{
    // Send-ThreatAlert: writes to the Windows Application event log. Email and
    // webhook sinks from the original script are supported via the optional
    // EmailEnabled / WebhookUrl fields (disabled by default, same as the PS1
    // where $global:EmailConfig / $global:WebhookUrl start $null).
    internal static class Alerts
    {
        public static string WebhookUrl = null;

        public static void Send(string severity, string message, string details)
        {
            if (!Config.EnableAlerts) return;

            string severityUpper = severity.ToUpperInvariant();
            EventLogEntryType entryType;
            if (severityUpper == "CRITICAL")
                entryType = EventLogEntryType.Error;
            else if (severityUpper == "HIGH" || severityUpper == "MEDIUM")
                entryType = EventLogEntryType.Warning;
            else
                entryType = EventLogEntryType.Information;

            try
            {
                if (!EventLog.SourceExists("NanoAV"))
                {
                    try { EventLog.CreateEventSource("NanoAV", "Application"); } catch { }
                }
                EventLog.WriteEntry("NanoAV", message + " - " + details, entryType, 1001);
            }
            catch { }

            if (!string.IsNullOrEmpty(WebhookUrl))
            {
                try
                {
                    string payload = "{\"severity\":\"" + severityUpper +
                        "\",\"message\":" + JsonString(message) +
                        ",\"details\":" + JsonString(details) +
                        ",\"timestamp\":\"" + DateTime.Now.ToString("o") +
                        "\",\"hostname\":\"" + Environment.MachineName + "\"}";
                    ThreatIntel.PostJson(WebhookUrl, payload);
                }
                catch (Exception ex)
                {
                    Logger.Log("Webhook alert failed: " + ex.Message);
                }
            }
        }

        private static string JsonString(string s)
        {
            if (s == null) return "null";
            return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"")
                           .Replace("\r", " ").Replace("\n", " ") + "\"";
        }
    }
}
