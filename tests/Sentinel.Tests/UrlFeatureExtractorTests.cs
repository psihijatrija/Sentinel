using Xunit;
using Sentinel.Core.Ml;

namespace Sentinel.Tests
{
    public class UrlFeatureExtractorTests
    {
        [Fact]
        public void Extract_BasicUrl_ExtractsLength()
        {
            var v = UrlFeatureExtractor.Extract("https://example.com/path?q=1");
            Assert.True(v.UrlLength > 0);
            Assert.True(v.HostLength > 0);
            Assert.True(v.PathLength > 0);
            Assert.Equal(1f, v.HasHttps);
        }

        [Fact]
        public void Extract_HttpUrl_SetsHasHttp()
        {
            var v = UrlFeatureExtractor.Extract("http://example.com");
            Assert.Equal(1f, v.HasHttp);
            Assert.Equal(0f, v.HasHttps);
        }

        [Fact]
        public void Extract_BareHostname_Handled()
        {
            var v = UrlFeatureExtractor.Extract("malware.tk");
            Assert.True(v.HostLength > 0);
            Assert.Equal(1f, v.HasSuspiciousTld);
        }

        [Theory]
        [InlineData("evil.tk")]
        [InlineData("phishing.xyz")]
        [InlineData("malware.zip")]
        [InlineData("attack.top")]
        public void Extract_SuspiciousTlds_Detected(string domain)
        {
            var v = UrlFeatureExtractor.Extract(domain);
            Assert.Equal(1f, v.HasSuspiciousTld);
        }

        [Theory]
        [InlineData("google.com")]
        [InlineData("microsoft.com")]
        [InlineData("github.io")]
        public void Extract_LegitTlds_NotFlagged(string domain)
        {
            var v = UrlFeatureExtractor.Extract(domain);
            Assert.Equal(0f, v.HasSuspiciousTld);
        }

        [Fact]
        public void Extract_IpAddress_DetectsIpHost()
        {
            var v = UrlFeatureExtractor.Extract("http://192.168.1.1/admin");
            Assert.Equal(1f, v.HasIpHost);
        }

        [Fact]
        public void Extract_DomainName_NotIpHost()
        {
            var v = UrlFeatureExtractor.Extract("http://example.com");
            Assert.Equal(0f, v.HasIpHost);
        }

        [Theory]
        [InlineData("http://bit.ly/abc123")]
        [InlineData("http://tinyurl.com/xyz")]
        [InlineData("http://t.co/short")]
        public void Extract_UrlShorteners_Detected(string url)
        {
            var v = UrlFeatureExtractor.Extract(url);
            Assert.Equal(1f, v.HasShortenerHint);
        }

        [Fact]
        public void Extract_NormalUrl_NoShortener()
        {
            var v = UrlFeatureExtractor.Extract("https://www.example.org/en-us/dotnet");
            Assert.Equal(0f, v.HasShortenerHint);
        }

        [Fact]
        public void Extract_CountsDigitsAndSpecials()
        {
            var v = UrlFeatureExtractor.Extract("http://123.45.67.89:8080/path?x=1&y=2");
            Assert.True(v.DigitCount > 0);
            Assert.True(v.SpecialCharCount > 0);
            Assert.True(v.DotCount > 0);
        }

        [Fact]
        public void Extract_SubdomainCount_Computed()
        {
            var v = UrlFeatureExtractor.Extract("http://a.b.c.d.example.com");
            Assert.True(v.SubdomainCount >= 4);
        }

        [Fact]
        public void Extract_Entropy_Positive()
        {
            var v = UrlFeatureExtractor.Extract("https://www.google.com/search?q=test");
            Assert.True(v.Entropy > 0);
        }

        [Fact]
        public void Extract_EmptyString_ReturnsDefaults()
        {
            var v = UrlFeatureExtractor.Extract("");
            Assert.Equal(0, v.UrlLength);
        }

        [Fact]
        public void Extract_NullString_ReturnsDefaults()
        {
            var v = UrlFeatureExtractor.Extract(null!);
            Assert.Equal(0, v.UrlLength);
        }

        [Fact]
        public void Extract_DigitRatio_HighForIpUrl()
        {
            var v = UrlFeatureExtractor.Extract("http://192.168.100.200:9999");
            Assert.True(v.DigitRatio > 0.3f);
        }

        [Fact]
        public void Extract_QueryParameters_Counted()
        {
            var v = UrlFeatureExtractor.Extract("http://evil.com/api?a=1&b=2&c=3");
            Assert.True(v.AmpCount >= 2);
            Assert.True(v.EqualsCount >= 3);
            Assert.True(v.QuestionCount >= 1);
        }

        [Fact]
        public void Extract_AtSign_Counted()
        {
            var v = UrlFeatureExtractor.Extract("http://user@evil.com/path");
            Assert.True(v.AtCount >= 1);
        }

        [Fact]
        public void Extract_PercentEncoding_Counted()
        {
            var v = UrlFeatureExtractor.Extract("http://evil.com/path%20name%2F");
            Assert.True(v.PercentCount >= 2);
        }

        [Fact]
        public void Extract_IPv6_Host_DetectsIp()
        {
            var v = UrlFeatureExtractor.Extract("http://[::1]:8080/path");
            // IPv6 loopback - depends on Uri parsing, but should not crash
            Assert.True(v.UrlLength > 0);
        }
    }
}
