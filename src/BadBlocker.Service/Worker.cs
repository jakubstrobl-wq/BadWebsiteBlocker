using BadBlocker.Core;
using System.Net.NetworkInformation;
using System.ServiceProcess;

namespace BadBlocker.Service;

public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _log;
    private BlocklistManager? _blocklist;
    private DnsSinkhole? _sinkhole;
    private HostsFileManager? _hostsManager;

    public Worker(ILogger<Worker> log) => _log = log;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("BadBlockerService starting");

        _blocklist = LoadBlocklist();
        _log.LogInformation("Loaded {Count} blocked domains", _blocklist.Count);

        _sinkhole = new DnsSinkhole(_blocklist);
        try { _sinkhole.Start(); _log.LogInformation("DNS sinkhole running on 127.0.0.1:53"); }
        catch (Exception ex) { _log.LogError(ex, "Failed to start DNS sinkhole"); }

        _hostsManager = new HostsFileManager(_blocklist);
        try { _hostsManager.WriteAndWatch(); _log.LogInformation("Hosts file written and locked"); }
        catch (Exception ex) { _log.LogError(ex, "Failed to write hosts file"); }

        if (!WfpManager.FiltersInstalled())
        {
            try { WfpManager.InstallFilters(); _log.LogInformation("Firewall filters re-installed"); }
            catch (Exception ex) { _log.LogError(ex, "Failed to install firewall filters"); }
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try { EnsureServiceRunning("BadBlockerGuard"); }
            catch { /* guard not installed yet or transient */ }

            // Restore DNS to 127.0.0.1 if it was changed
            try { RestoreDnsIfChanged(); }
            catch { /* best effort */ }

            await Task.Delay(5_000, stoppingToken);
        }
    }

    public override void Dispose()
    {
        _sinkhole?.Dispose();
        _hostsManager?.Dispose();
        base.Dispose();
    }

    private static BlocklistManager LoadBlocklist()
    {
        var mgr = new BlocklistManager();
        var dir = Config.DataDir;
        mgr.LoadFromFile(Path.Combine(dir, "lists", "adult.txt"));
        mgr.MergeFromFile(Path.Combine(dir, "lists", "gambling.txt"));
        if (Config.GetBlockSocial())
            mgr.MergeFromFile(Path.Combine(dir, "lists", "social.txt"));
        // Always block DNS-over-HTTPS provider domains so browsers can't bypass the sinkhole
        mgr.MergeFromLines(BlocklistManager.DohBypassDomains.Select(d => $"0.0.0.0 {d}"));
        return mgr;
    }

    private static void RestoreDnsIfChanged()
    {
        const string sinkhole = "127.0.0.1";
        foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
        {
            // Skip loopback and virtual adapters — only fix real physical/wifi adapters
            if (iface.OperationalStatus != OperationalStatus.Up) continue;
            if (iface.NetworkInterfaceType is NetworkInterfaceType.Loopback
                                           or NetworkInterfaceType.Tunnel) continue;
            var dns = iface.GetIPProperties().DnsAddresses;
            bool alreadyCorrect = dns.Count > 0 && dns[0].ToString() == sinkhole;
            if (!alreadyCorrect)
            {
                // Fire-and-forget: do not block the service loop waiting for netsh
                var ifaceName = iface.Name;
                _ = Task.Run(() =>
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                        "netsh",
                        $"interface ip set dns \"{ifaceName}\" static {sinkhole} primary")
                    {
                        UseShellExecute = false, CreateNoWindow = true
                    })?.WaitForExit(5000));
            }
        }
    }

    private static void EnsureServiceRunning(string serviceName)
    {
        using var sc = new ServiceController(serviceName);
        if (sc.Status != ServiceControllerStatus.Running &&
            sc.Status != ServiceControllerStatus.StartPending)
            sc.Start();
    }
}
