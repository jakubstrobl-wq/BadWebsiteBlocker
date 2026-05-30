using System.ServiceProcess;

namespace BadBlocker.Guard;

public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _log;

    public Worker(ILogger<Worker> log) => _log = log;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("BadBlockerGuard watchdog started");
        while (!stoppingToken.IsCancellationRequested)
        {
            try { EnsureServiceRunning("BadBlockerService"); }
            catch (Exception ex) { _log.LogWarning(ex, "Could not check BadBlockerService"); }
            await Task.Delay(5_000, stoppingToken);
        }
    }

    private void EnsureServiceRunning(string serviceName)
    {
        using var sc = new ServiceController(serviceName);
        var status = sc.Status;
        if (status != ServiceControllerStatus.Running &&
            status != ServiceControllerStatus.StartPending)
        {
            _log.LogWarning("{Service} was {Status} — restarting", serviceName, status);
            sc.Start();
        }
    }
}
