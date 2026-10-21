using System;
using System.IO;
using System.Net;
using System.Text;

namespace NanoAV
{
    // Threat-intel feeds: CIRCL hashlookup, Team Cymru MHR, MalwareBazaar, and
    // the hash-list download. Uses HttpWebRequest (no external dependencies) so
    // the exe stays small. Mirrors Test-CirclHashLookup / Test-CymruMalwareHash
    // / Test-MalwareBazaarHash / Update-ThreatIntelligence.
    internal static class ThreatIntel
    {
        static ThreatIntel()
        {
            // The old endpoints may negotiate TLS 1.2 only.
            try
            {
                ServicePointManager.SecurityProtocol =
                    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            }
            catch { }
        }

        private static string HttpGet(string url, int timeoutSec)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = timeoutSec * 1000;
            req.UserAgent = "NanoAV/1.0";
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream()))
                return sr.ReadToEnd();
        }

        public static string PostJson(string url, string json)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/json";
            req.Timeout = 10000;
            byte[] body = Encoding.UTF8.GetBytes(json);
            req.ContentLength = body.Length;
            using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream()))
                return sr.ReadToEnd();
        }

        public static bool CirclHashLookup(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            try
            {
                string url = Config.CirclHashLookupUrl + "/" + sha256;
                string response = HttpGet(url, 8);
                if (!string.IsNullOrEmpty(response))
                {
                    Logger.Log("CIRCL known-good match: " + sha256);
                    return true;
                }
            }
            catch { }
            return false;
        }

        public static bool CymruMalwareHash(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            try
            {
                string url = Config.CymruApiUrl + "/" + sha256;
                string response = HttpGet(url, 8);
                int detections = ExtractInt(response, "detections");
                if (detections >= Config.CymruDetectionThreshold)
                {
                    Logger.Log("CYMRU malware match: " + sha256 + " (detections: " + detections + ")");
                    return true;
                }
            }
            catch { }
            return false;
        }

        public static bool MalwareBazaarHash(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            try
            {
                var sb = new StringBuilder();
                sb.Append("query=get_info&hash=").Append(Uri.EscapeDataString(sha256));
                if (!string.IsNullOrEmpty(Config.MalwareBazaarApiKey))
                    sb.Append("&api_key=").Append(Uri.EscapeDataString(Config.MalwareBazaarApiKey));

                var req = (HttpWebRequest)WebRequest.Create(Config.MalwareBazaarApiUrl);
                req.Method = "POST";
                req.ContentType = "application/x-www-form-urlencoded";
                req.Timeout = 10000;
                byte[] body = Encoding.UTF8.GetBytes(sb.ToString());
                req.ContentLength = body.Length;
                using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);

                string response;
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                    response = sr.ReadToEnd();

                if (response.IndexOf("\"query_status\": \"ok\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    response.IndexOf("\"query_status\":\"ok\"", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Logger.Log("MalwareBazaar match: " + sha256);
                    return true;
                }
            }
            catch { }
            return false;
        }

        public static void UpdateThreatIntelligence()
        {
            if (!Config.EnableThreatIntel) return;
            Logger.Log("Updating threat intelligence feeds...");

            string[] hashLists =
            {
                "https://raw.githubusercontent.com/dNanoAVidonzo/Threat-Intel/master/lists/latest-hashes.txt"
            };

            foreach (string url in hashLists)
            {
                string fileName = url.Substring(url.LastIndexOf('/') + 1);
                string outputPath = Path.Combine(Config.BaseDirectory, fileName);
                try
                {
                    string content = HttpGet(url, 15);
                    File.WriteAllText(outputPath, content);
                    Logger.Log("Downloaded hash list: " + fileName);
                }
                catch (Exception ex)
                {
                    Logger.Log("Failed to download hash list " + fileName + " : " + ex.Message);
                }
            }
        }

        // Minimal JSON integer extractor for "key": <number>.
        private static int ExtractInt(string json, string key)
        {
            if (string.IsNullOrEmpty(json)) return 0;
            var m = System.Text.RegularExpressions.Regex.Match(
                json, "\"" + key + "\"\\s*:\\s*(\\d+)");
            int val;
            if (m.Success && int.TryParse(m.Groups[1].Value, out val)) return val;
            return 0;
        }
    }
}
