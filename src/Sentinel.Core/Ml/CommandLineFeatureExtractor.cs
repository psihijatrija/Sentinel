using System;
using System.Text;

namespace Sentinel.Core.Ml
{
    /// <summary>
    /// Lexical / statistical feature extraction for process command lines.
    ///
    /// Companion to <see cref="UrlFeatureExtractor"/> / <see cref="PeFeatureExtractor"/>: pure,
    /// side-effect-free, no process access. Given the raw command-line string it produces a
    /// <see cref="CommandLineFeatureVector"/> describing the *shape* of any obfuscation, which the
    /// command-line model (or the deterministic heuristic fallback) scores in [0,1].
    ///
    /// This never reads a process's memory or shells out - it only analyses a string a monitor
    /// already holds. It is observe-fuel; it does not authorise any response on its own.
    /// </summary>
    public static class CommandLineFeatureExtractor
    {
        // Tokens whose presence is a weak obfuscation/abuse indicator (never a kill on their own).
        private static readonly string[] DownloadTokens =
        {
            "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", " iwr ",
            "start-bitstransfer", "bitsadmin", "certutil", "curl ", "wget ", "webclient",
            "net.webclient", "system.net.webclient"
        };

        private static readonly string[] IexTokens =
        {
            "iex", "invoke-expression", "invoke-command", "icm ", "&('i'+'ex')", "$executioncontext"
        };

        private static readonly string[] LolbinTokens =
        {
            "rundll32", "regsvr32", "mshta", "wscript", "cscript", "installutil", "regasm",
            "regsvcs", "msbuild", "cmstp", "odbcconf", "forfiles", "pcalua", "wmic ", "hh.exe"
        };

        public static CommandLineFeatureVector Extract(string commandLine)
        {
            var raw = commandLine ?? string.Empty;
            var v = new CommandLineFeatureVector();
            if (raw.Length == 0) return v;

            string lower = raw.ToLowerInvariant();
            int len = raw.Length;

            int digits = 0, uppers = 0, specials = 0, nonAscii = 0;
            int carets = 0, backticks = 0, quotes = 0, parenBrace = 0, plus = 0, commas = 0;
            int base64Chars = 0, hexChars = 0;
            int envRefs = 0;

            int curAlnumRun = 0, maxAlnumRun = 0;

            for (int i = 0; i < len; i++)
            {
                char c = raw[i];

                if (char.IsDigit(c)) digits++;
                else if (char.IsUpper(c)) uppers++;

                if (c > 0x7F) nonAscii++;

                bool isLetter = char.IsLetter(c);
                bool isDigit = char.IsDigit(c);
                if (!isLetter && !isDigit && !char.IsWhiteSpace(c)) specials++;

                // Base64 alphabet (approx): A-Za-z0-9+/=
                if (isLetter || isDigit || c == '+' || c == '/' || c == '=')
                    base64Chars++;

                // Hex alphabet
                if (isDigit || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    hexChars++;

                // Longest contiguous alnum run (a big opaque blob = likely encoded payload)
                if (isLetter || isDigit || c == '+' || c == '/' || c == '=')
                {
                    curAlnumRun++;
                    if (curAlnumRun > maxAlnumRun) maxAlnumRun = curAlnumRun;
                }
                else
                {
                    curAlnumRun = 0;
                }

                switch (c)
                {
                    case '^': carets++; break;
                    case '`': backticks++; break;
                    case '"':
                    case '\'': quotes++; break;
                    case '(':
                    case ')':
                    case '{':
                    case '}': parenBrace++; break;
                    case '+': plus++; break;
                    case ',': commas++; break;
                    case '%': envRefs++; break;
                }
            }

            // $env: PowerShell env substitution (count occurrences)
            int idx = 0;
            while ((idx = lower.IndexOf("$env:", idx, StringComparison.Ordinal)) >= 0)
            {
                envRefs++;
                idx += 5;
            }

            int tokenCount = 0;
            foreach (var _ in raw.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                tokenCount++;

            v.Length = len;
            v.TokenCount = tokenCount;
            v.DigitRatio = (float)digits / len;
            v.UpperRatio = (float)uppers / len;
            v.SpecialRatio = (float)specials / len;
            v.Entropy = (float)Entropy(Encoding.UTF8.GetBytes(raw));
            v.MaxAlnumRunLength = maxAlnumRun;
            v.Base64CharRatio = (float)base64Chars / len;
            v.HexCharRatio = (float)hexChars / len;
            v.CaretCount = carets;
            v.BacktickCount = backticks;
            v.EnvVarRefCount = envRefs;
            v.QuoteCount = quotes;
            v.ParenBraceCount = parenBrace;
            v.PlusCount = plus;
            v.CommaCount = commas;
            v.NonAsciiRatio = (float)nonAscii / len;

            v.HasEncodedCommandFlag = HasEncodedCommandFlag(lower) ? 1f : 0f;
            v.HasHiddenWindowFlag = (Contains(lower, "-w hidden") || Contains(lower, "-windowstyle hidden")
                                     || Contains(lower, "/w hidden")) ? 1f : 0f;
            v.HasExecBypassFlag = (Contains(lower, "-ep bypass") || Contains(lower, "-executionpolicy bypass")
                                   || Contains(lower, "-exec bypass") || Contains(lower, "unrestricted")) ? 1f : 0f;
            v.HasDownloadToken = ContainsAny(lower, DownloadTokens) ? 1f : 0f;
            v.HasIexToken = ContainsAny(lower, IexTokens) ? 1f : 0f;
            v.HasLolbinToken = ContainsAny(lower, LolbinTokens) ? 1f : 0f;

            return v;
        }

        private static bool HasEncodedCommandFlag(string lower)
        {
            // -enc / -e / -encodedcommand / -encoded  (PowerShell base64 command)
            return Contains(lower, "-encodedcommand") || Contains(lower, "-enc ")
                   || Contains(lower, "-enc\"") || lower.EndsWith("-enc", StringComparison.Ordinal)
                   || Contains(lower, "-encoded ") || Contains(lower, " -e ")
                   || Contains(lower, "/encodedcommand");
        }

        private static bool Contains(string haystack, string needle)
            => haystack.IndexOf(needle, StringComparison.Ordinal) >= 0;

        private static bool ContainsAny(string haystack, string[] needles)
        {
            foreach (var n in needles)
                if (haystack.IndexOf(n, StringComparison.Ordinal) >= 0) return true;
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
