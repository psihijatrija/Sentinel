using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public interface IMonitor
    {
        string Name { get; }
        Task StartAsync(CancellationToken ct);
        Task StopAsync();
    }
}
