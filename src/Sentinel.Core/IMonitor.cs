using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>A startup operation that legitimately completes rather than collecting continuously.</summary>
    public interface IMonitorStartupTask { string CompletionDescription { get; } }

    /// <summary>Worker liveness, independent of collection success.</summary>
    public interface IMonitorHealthCheck { void CheckHealth(); }

    public interface IMonitorWorker { bool IsWorkerRunning { get; } }

    public interface IMonitor
    {
        string Name { get; }
        Task StartAsync(CancellationToken ct);
        Task StopAsync();
    }
}
