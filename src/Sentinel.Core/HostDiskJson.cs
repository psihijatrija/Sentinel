using System;
using Microsoft.Extensions.Configuration;

namespace Sentinel.Core
{
    /// <summary>
    /// Host builders use compiled defaults + DPAPI config.enc only.
    /// Disk JSON configuration sources are discarded so a planted file cannot bind.
    /// </summary>
    public static class HostDiskJson
    {
        public static void RemoveJsonSources(IConfigurationBuilder builder)
        {
            if (builder == null) return;
            for (int i = builder.Sources.Count - 1; i >= 0; i--)
            {
                var name = builder.Sources[i].GetType().FullName ?? "";
                if (name.IndexOf("JsonConfigurationSource", StringComparison.OrdinalIgnoreCase) >= 0)
                    builder.Sources.RemoveAt(i);
            }
        }
    }
}
