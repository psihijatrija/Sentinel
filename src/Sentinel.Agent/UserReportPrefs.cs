using System;
using System.IO;
using System.Text.Json;

namespace Sentinel.Agent
{
    /// <summary>
    /// User-editable complainant defaults for police filing UI.
    /// Stored under LocalAppData so upgrades never wipe identity fields.
    /// </summary>
    public sealed class UserReportPrefs
    {
        public string FullName { get; set; } = "";
        public string Email { get; set; } = "";
        public string Phone { get; set; } = "";
        public string Address { get; set; } = "";
        public string NationalId { get; set; } = "";
        public string Relationship { get; set; } = "owner";
        public string AdditionalNarrative { get; set; } = "";
        public string FinancialLoss { get; set; } = "";
        public string DataAffected { get; set; } = "";
        public string OtherHarm { get; set; } = "";
        public string? PreferredCountryCode { get; set; }

        private static string PrefsPath =>
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Sentinel", "user_report_prefs.json");

        public static UserReportPrefs Load()
        {
            try
            {
                var path = PrefsPath;
                if (!File.Exists(path))
                    return new UserReportPrefs();

                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                var prefs = JsonSerializer.Deserialize<UserReportPrefs>(fs);
                return prefs ?? new UserReportPrefs();
            }
            catch
            {
                return new UserReportPrefs();
            }
        }

        public void Save()
        {
            try
            {
                var path = PrefsPath;
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch
            {
                // Best-effort preference persistence - never break the UI.
            }
        }
    }
}
