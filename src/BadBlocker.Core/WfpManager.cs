using System.Diagnostics;

namespace BadBlocker.Core;

// Adds persistent Windows Firewall rules that force all DNS through the local sinkhole.
// Strategy:
//   1. Allow our service binary to make outbound DNS queries (so it can forward upstream)
//   2. Allow DNS to 127.0.0.1 (the sinkhole itself)
//   3. Block all other outbound DNS (port 53 UDP/TCP, port 853 DoT)
//   4. Block known DoH server domains via the blocklist (not IP blocks, which are too broad)
public static class WfpManager
{
    private const string RulePrefix = "BadWebsiteBlocker";

    // Called with the installed service binary path so the service can still
    // reach upstream DNS while all other programs are forced through the sinkhole.
    public static void InstallFilters(string serviceBinPath)
    {
        RemoveFilters();

        // Allow our service to reach upstream DNS (e.g. 1.1.1.1:53) for forwarding
        Netsh("add rule",
            $"name=\"{RulePrefix} - Service upstream DNS\"",
            $"program=\"{serviceBinPath}\"",
            "protocol=UDP dir=out action=allow remoteport=53");

        // Allow DNS to 127.0.0.1 (the sinkhole) for all programs
        Netsh("add rule",
            $"name=\"{RulePrefix} - Allow DNS to localhost\"",
            "protocol=UDP dir=out action=allow",
            "remoteip=127.0.0.1 remoteport=53");

        Netsh("add rule",
            $"name=\"{RulePrefix} - Allow DNS TCP to localhost\"",
            "protocol=TCP dir=out action=allow",
            "remoteip=127.0.0.1 remoteport=53");

        // Block all other outbound DNS UDP/TCP (forces all other apps through sinkhole)
        Netsh("add rule",
            $"name=\"{RulePrefix} - Block DNS UDP\"",
            "protocol=UDP dir=out action=block remoteport=53");

        Netsh("add rule",
            $"name=\"{RulePrefix} - Block DNS TCP\"",
            "protocol=TCP dir=out action=block remoteport=53");

        // Block DNS-over-TLS (port 853) — no legitimate browsing uses this port
        Netsh("add rule",
            $"name=\"{RulePrefix} - Block DoT\"",
            "protocol=TCP dir=out action=block remoteport=853");
    }

    // Overload used when service path isn't known yet (service verifies at startup)
    public static void InstallFilters() =>
        InstallFilters(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            @"BadWebsiteBlocker\BadBlocker.Service.exe"));

    // All rule names we create — must match exactly what InstallFilters adds
    private static readonly string[] RuleNames =
    {
        $"{RulePrefix} - Service upstream DNS",
        $"{RulePrefix} - Allow DNS to localhost",
        $"{RulePrefix} - Allow DNS TCP to localhost",
        $"{RulePrefix} - Block DNS UDP",
        $"{RulePrefix} - Block DNS TCP",
        $"{RulePrefix} - Block DoT",
    };

    public static void RemoveFilters()
    {
        // netsh does not support wildcards in rule names — delete each by exact name
        foreach (var name in RuleNames)
        {
            try { RunNetsh($"advfirewall firewall delete rule name=\"{name}\""); }
            catch { /* best effort */ }
        }
    }

    public static bool FiltersInstalled()
    {
        try
        {
            var output = RunNetshCapture(
                $"advfirewall firewall show rule name=\"{RulePrefix} - Block DNS UDP\"");
            return output.Contains("BadWebsiteBlocker");
        }
        catch { return false; }
    }

    private static void Netsh(params string[] args) =>
        RunNetsh("advfirewall firewall " + string.Join(" ", args));

    private static void RunNetsh(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("netsh", args)
        {
            UseShellExecute = false,
            CreateNoWindow  = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        })!;
        p.WaitForExit(10_000);
    }

    private static string RunNetshCapture(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("netsh", args)
        {
            UseShellExecute = false,
            CreateNoWindow  = true,
            RedirectStandardOutput = true
        })!;
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(10_000);
        return output;
    }
}
