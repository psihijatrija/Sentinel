using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for GpuProcessMonitor's GPU-driver-CVE advisory surface.
    ///
    /// This monitor enumerates installed GPU driver versions (NVIDIA / AMD / Intel) and flags
    /// versions that fall within known-vulnerable CVE ranges. The findings are purely advisory
    /// ("update your driver") and must NEVER authorize a response.
    ///
    /// Enforces the docs/constraints.md testing contract for the changed surface:
    ///   (1) Every driver-CVE rule is Tier2Indicator (no Tier1 rules on this surface - a
    ///       vulnerable-driver-installed fact is not a behavioral kill-grade terminal).
    ///   (2) The Tier2 log-only contract holds: AuthorizedResponse == LogOnly and
    ///       KillAuthorized == false, even though these are active advisories.
    ///   (3) ResponsePolicy.ApplyTierLaw keeps them Tier2/LogOnly (a high-confidence advisory
    ///       must not be promoted to Tier1 - "critical score alone must not promote noise").
    ///   (4) NVIDIA Win32_VideoController 4-part version normalization maps to the branded
    ///       form used by the range tables (a matching bug would silently disable detection).
    /// </summary>
    public class GpuProcessMonitorTests
    {
        //  Tier contract: NVIDIA 

        [Theory]
        [InlineData("576.02", "CVE-2025-33218")]   // in 570.0-576.79 nvlddmkm cluster
        [InlineData("552.44", "CVE-2025-33218")]   // in 550.0-553.99
        [InlineData("580.50", "CVE-2025-23347")]   // in 577.0-580.87 Oct-2025 bulletin
        public void Nvidia_VulnerableVersion_IsTier2LogOnlyAdvisory(string version, string expectedCve)
        {
            var detections = GpuProcessMonitor.BuildNvidiaDriverDetections(version);

            Assert.NotEmpty(detections);
            Assert.Contains(detections, d => d.Metadata["CVE"] == expectedCve);

            foreach (var d in detections)
            {
                Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
                Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
                Assert.False(d.KillAuthorized);
                Assert.Equal("NVIDIA", d.Metadata["DriverVendor"]);
                Assert.Null(d.Family); // never a kill-grade terminal family
            }
        }

        [Theory]
        [InlineData("581.00")]   // above all vulnerable ranges (patched)
        [InlineData("500.00")]   // below the tracked ranges
        public void Nvidia_PatchedVersion_ProducesNoAdvisory(string version)
        {
            var detections = GpuProcessMonitor.BuildNvidiaDriverDetections(version);
            Assert.Empty(detections);
        }

        //  Tier contract: AMD 

        [Theory]
        [InlineData("24.9.1", "CVE-2025-54517")]   // AMDGV OOB-write LPE
        [InlineData("25.3.0", "CVE-2025-52540")]   // PMF driver LPE cluster
        public void Amd_VulnerableVersion_IsTier2LogOnlyAdvisory(string version, string expectedCve)
        {
            var detections = GpuProcessMonitor.BuildAmdDriverDetections(version);

            Assert.NotEmpty(detections);
            Assert.Contains(detections, d => d.Metadata["CVE"] == expectedCve);

            foreach (var d in detections)
            {
                Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
                Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
                Assert.False(d.KillAuthorized);
                Assert.Equal("AMD", d.Metadata["DriverVendor"]);
                Assert.Null(d.Family);
            }
        }

        [Fact]
        public void Amd_PatchedVersion_ProducesNoAdvisory()
        {
            var detections = GpuProcessMonitor.BuildAmdDriverDetections("25.9.9");
            Assert.Empty(detections);
        }

        //  Tier contract: Intel 

        [Fact]
        public void Intel_OutdatedVersion_IsTier2LogOnlyAdvisory()
        {
            var d = GpuProcessMonitor.BuildIntelDriverDetection("31.0.101.4000");

            Assert.NotNull(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d!.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.False(d.KillAuthorized);
            Assert.Equal("Intel", d.Metadata["DriverVendor"]);
            Assert.Null(d.Family);
        }

        [Fact]
        public void Intel_CurrentVersion_ProducesNoAdvisory()
        {
            var d = GpuProcessMonitor.BuildIntelDriverDetection("31.0.101.5000");
            Assert.Null(d);
        }

        //  ApplyTierLaw must not promote advisories 

        [Fact]
        public void DriverAdvisory_SurvivesTierLaw_AsTier2LogOnly()
        {
            // A high-confidence NVIDIA advisory pushed through the standing tier law must stay
            // observe-only. A vulnerable-driver-installed fact is not a kill-grade terminal, so
            // score/confidence alone must never promote it to Tier1.
            var detections = GpuProcessMonitor.BuildNvidiaDriverDetections("576.02");
            Assert.NotEmpty(detections);

            foreach (var d in detections)
            {
                d.Confidence = 0.99; // adversarially high - must not matter
                ResponsePolicy.ApplyTierLaw(d);

                Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
                Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
                Assert.False(d.KillAuthorized);
            }
        }

        //  Dedup key present for the caller's suppression 

        [Fact]
        public void Advisory_CarriesStableAlertKey_ForDedup()
        {
            var d = GpuProcessMonitor.BuildNvidiaDriverDetections("576.02").First();
            Assert.True(d.Metadata.ContainsKey("AlertKey"));
            Assert.Equal("NVIDIA_576.02_CVE-2025-33218", d.Metadata["AlertKey"]);
        }

        //  NVIDIA version normalization (Win32_VideoController 4-part -> branded) 

        [Theory]
        [InlineData("31.0.15.5222", "552.22")]   // 4-part Windows form -> branded
        [InlineData("31.0.15.7602", "576.02")]   // trailing 5 digits "57602" -> 576.02
        [InlineData("552.22", "552.22")]         // already branded, unchanged
        public void NormalizeNvidiaVersion_MapsToBrandedForm(string raw, string expected)
        {
            Assert.Equal(expected, GpuProcessMonitor.NormalizeNvidiaVersion(raw));
        }

        [Fact]
        public void NormalizeNvidiaVersion_ThenRangeMatch_FlagsVulnerableWindowsForm()
        {
            // End-to-end: a Win32_VideoController 4-part version for a vulnerable branded build
            // must normalize and then match a CVE range.
            var branded = GpuProcessMonitor.NormalizeNvidiaVersion("31.0.15.7602"); // -> 576.02
            var detections = GpuProcessMonitor.BuildNvidiaDriverDetections(branded);
            Assert.NotEmpty(detections);
            Assert.All(detections, d => Assert.Equal(DetectionTier.Tier2Indicator, d.Tier));
        }
    }
}
