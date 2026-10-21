using System;
using System.IO;
using NanoAV;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class NanoAvCoexistenceTests
{
    [Fact]
    public void CoexistenceTestsDoNotLoadTheStandaloneScanner()
    {
        var assembly = typeof(NanoAvCoexistenceTests).Assembly;
        Assert.Same(assembly, typeof(SentinelCoexistencePaths).Assembly);
        Assert.DoesNotContain(assembly.GetReferencedAssemblies(), name => name.Name == "NanoAV");
    }

    [Theory]
    [InlineData("Sentinel.Service.exe")]
    [InlineData("Sentinel.Agent.exe")]
    [InlineData("Sentinel.Core.dll")]
    [InlineData("SentinelAutoRotate.exe")]
    public void OriginalNanoAvGuardProtectsInstalledSentinelFiles(string name)
    {
        string root = Path.Combine(Path.GetTempPath(), "Sentinel-coexistence-install");
        string data = Path.Combine(Path.GetTempPath(), "Sentinel-coexistence-data");
        Assert.True(SentinelCoexistencePaths.IsProtectedResolvedPath(Path.Combine(root, name), root, data));
        Assert.True(SentinelCoexistencePaths.IsProtectedResolvedPath(Path.Combine(data, "events.jsonl"), root, data));
    }

    [Theory]
    [InlineData("Sentinel.Service.exe")]
    [InlineData("Sentinel.Agent.exe")]
    [InlineData("NanoAV.exe")]
    [InlineData("ordinary.exe")]
    public void MatchingNamesOutsideSentinelKeepOriginalNanoAvPolicy(string name)
    {
        string root = Path.Combine(Path.GetTempPath(), "Sentinel-coexistence-install");
        string data = Path.Combine(Path.GetTempPath(), "Sentinel-coexistence-data");
        Assert.False(SentinelCoexistencePaths.IsProtectedResolvedPath(Path.Combine(root + "-other", name), root, data));
        Assert.False(SentinelCoexistencePaths.IsProtectedResolvedPath(Path.Combine(root, "..", "outside", name), root, data));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("Sentinel.Service.exe")]
    public void RelativeNamesCannotBecomeAProtectedFile(string path)
    {
        Assert.False(SentinelCoexistencePaths.IsInside(path, Path.GetTempPath()));
    }

    [WindowsContainmentFact]
    public void SentinelExemptsCoInstalledNanoAvButNotACopyElsewhere()
    {
        Assert.True(SelfPathGuard.IsInstalledNanoAvBinary(Path.Combine(AppContext.BaseDirectory, "NanoAV.exe")));
        Assert.False(SelfPathGuard.IsInstalledNanoAvBinary(Path.Combine(Path.GetTempPath(), "NanoAV.exe")));
        Assert.False(SelfPathGuard.IsInstalledNanoAvBinary(Path.Combine(AppContext.BaseDirectory, "NanoAV-other.exe")));
    }

    [Theory]
    [InlineData("identical", true)]
    [InlineData("modified", false)]
    [InlineData("elsewhere", false)]
    [InlineData("missing-source", false)]
    [InlineData("missing-copy", false)]
    [InlineData("no-path", false)]
    public void RuntimeCopyExemptionRequiresExactPathAndPayload(string scenario, bool expected)
    {
        string directory = Path.Combine(Path.GetTempPath(), "NanoAvCopy_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string source = Path.Combine(directory, "NanoAV.exe");
            string copy = Path.Combine(directory, "NanoAV.dll");
            File.WriteAllText(source, "fixture payload");
            File.WriteAllText(copy, "fixture payload");
            string? requested = copy;
            if (scenario == "modified") File.WriteAllText(copy, "modifiedpayload");
            if (scenario == "elsewhere")
            {
                requested = Path.Combine(directory, "outside-NanoAV.dll");
                File.Copy(copy, requested);
            }
            if (scenario == "missing-source") File.Delete(source);
            if (scenario == "missing-copy") File.Delete(copy);
            if (scenario == "no-path") requested = null;
            Assert.Equal(expected, SelfPathGuard.MatchesNanoAvRuntimeCopy(requested, source, copy));
        }
        finally { Directory.Delete(directory, true); }
    }
}
