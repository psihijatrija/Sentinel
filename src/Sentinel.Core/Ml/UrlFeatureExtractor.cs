using System;
using System.Net;
using System.Text;

namespace Sentinel.Core.Ml
{
    /// <summary>
    /// Lexical URL / host features for the URL threat model.
    /// Accepts full URLs or bare hostnames (DNS queries).
    /// </summary>
    public static class UrlFeatureExtractor
    {
        private static readonly string[] SuspiciousTlds =
        {
            "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
            "country", "stream", "download", "racing", "review", "science", "party"
        };

        private static readonly string[] ShortenerHints =
        {
            "bit.ly", "goo.gl", "t.co", "tinyurl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"
        };

        public static UrlFeatureVector Extract(string urlOrHost)
        {
            var raw = (urlOrHost ?? string.Empty).Trim();
            var v = new UrlFeatureVector();
            if (raw.Length == 0) return v;

            // Normalize: allow bare hosts
            string forParse = raw;
            if (!raw.Contains("://") && !raw.StartsWith("//"))
                forParse = "http://" + raw;

            string host = "";
            string path = "";
            string query = "";
            try
            {
                if (Uri.TryCreate(forParse, UriKind.Absolute, out var uri))
                {
                    host = uri.IdnHost ?? uri.Host ?? "";
                    path = uri.AbsolutePath ?? "";
                    query = uri.Query ?? "";
                    v.HasHttps = uri.Scheme.Equals("https") ? 1f : 0f;
                    v.HasHttp = uri.Scheme.Equals("http") ? 1f : 0f;
                }
                else
                {
                    host = raw;
                }
            }
            catch
            {
                host = raw;
            }

            v.UrlLength = raw.Length;
            v.HostLength = host.Length;
            v.PathLength = path.Length;
            v.QueryLength = query.Length;

            int digits = 0, letters = 0, specials = 0;
            int dots = 0, hyphens = 0, underscores = 0, slashes = 0;
            int questions = 0, equals = 0, ats = 0, amps = 0, percents = 0, doubleSlash = 0;

            for (int i = 0; i < raw.Length; i++)
            {
                char c = raw[i];
                if (char.IsDigit(c)) digits++;
                else if (char.IsLetter(c)) letters++;
                else specials++;

                switch (c)
                {
                    case '.': dots++; break;
                    case '-': hyphens++; break;
                    case '_': underscores++; break;
                    case '/':
                        slashes++;
                        if (i + 1 < raw.Length && raw[i + 1] == '/') doubleSlash++;
                        break;
                    case '?': questions++; break;
                    case '=': equals++; break;
                    case '@': ats++; break;
                    case '&': amps++; break;
                    case '%': percents++; break;
                }
            }

            v.DigitCount = digits;
            v.LetterCount = letters;
            v.SpecialCharCount = specials;
            v.DotCount = dots;
            v.HyphenCount = hyphens;
            v.UnderscoreCount = underscores;
            v.SlashCount = slashes;
            v.QuestionCount = questions;
            v.EqualsCount = equals;
            v.AtCount = ats;
            v.AmpCount = amps;
            v.PercentCount = percents;
            v.DoubleSlashCount = doubleSlash;
            v.DigitRatio = raw.Length > 0 ? (float)digits / raw.Length : 0f;
            v.Entropy = (float)Entropy(Encoding.UTF8.GetBytes(raw));

            v.HasIpHost = IsIpHost(host) ? 1f : 0f;

            var hostParts = host.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
            v.SubdomainCount = Math.Max(0, hostParts.Length - 2);
            string tld = hostParts.Length > 0 ? hostParts[^1] : "";
            v.TldLength = tld.Length;
            v.HasSuspiciousTld = 0f;
            foreach (var s in SuspiciousTlds)
            {
                if (tld.Equals(s))
                {
                    v.HasSuspiciousTld = 1f;
                    break;
                }
            }

            v.HasShortenerHint = 0f;
            foreach (var s in ShortenerHints)
            {
                if (raw.Contains(s))
                {
                    v.HasShortenerHint = 1f;
                    break;
                }
            }

            return v;
        }

        private static bool IsIpHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            if (IPAddress.TryParse(host, out _)) return true;
            // Strip brackets for IPv6 URLs
            if (host.StartsWith("[") && host.EndsWith("]"))
                return IPAddress.TryParse(host.Substring(1, host.Length - 2), out _);
            return false;
        }

        private static double Entropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var freq = new int[256];
            foreach (var b in data) freq[b]++;
            double ent = 0, len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                ent -= p * MathNet48.Log2(p);
            }
            return ent;
        }
    }
}
