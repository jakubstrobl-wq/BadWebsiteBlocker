using BadBlocker.Core;
using System.Diagnostics;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Principal;

Console.Title = "BadWebsiteBlocker Installer";
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("=================================================");
Console.WriteLine("  BadWebsiteBlocker Installer");
Console.WriteLine("  Block adult, gambling, and social media sites");
Console.WriteLine("=================================================");
Console.ResetColor();

// Must run as admin
if (!IsAdmin())
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("\nERROR: This installer must be run as Administrator.");
    Console.WriteLine("Right-click the .exe and choose 'Run as administrator'.");
    Console.ResetColor();
    Console.ReadKey();
    return 1;
}

if (Config.IsInstalled())
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("\nBadWebsiteBlocker is already installed.");
    Console.WriteLine("Settings are permanently locked. There is no uninstaller.");
    Console.ResetColor();
    Console.ReadKey();
    return 0;
}

// Ask about social media categories
Console.WriteLine();
Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine("Choose social media categories to block:");
Console.ResetColor();
Console.WriteLine("  [1] Very harmful   - Instagram, TikTok, Facebook, Snapchat, Twitter/X, BeReal, Threads (+2 more)");
Console.WriteLine("  [2] Feeds & forums - Reddit, Tumblr, Pinterest, Imgur, 9gag, LinkedIn (+6 more)");
Console.WriteLine("  [3] Streaming      - Twitch");
Console.WriteLine("  [4] YouTube        - youtube.com");
Console.WriteLine("  [5] Messaging      - Discord, Telegram, WhatsApp");
Console.WriteLine();
Console.Write("Enter numbers to block (e.g. 1,3,4), or press Enter to skip all: ");
var input = Console.ReadLine()?.Trim() ?? "";
var chosen = input.Split(',', StringSplitOptions.RemoveEmptyEntries)
                  .Select(s => s.Trim())
                  .ToHashSet();
var social = new SocialCategories(
    Harmful:     chosen.Contains("1"),
    FeedsForums: chosen.Contains("2"),
    Streaming:   chosen.Contains("3"),
    YouTube:     chosen.Contains("4"),
    Messaging:   chosen.Contains("5"));

Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("WARNING: Once installed this software CANNOT be uninstalled.");
Console.WriteLine("There is no admin panel, no password, no way to change settings.");
Console.Write("Type 'CONFIRM' to proceed: ");
Console.ResetColor();
var confirm = Console.ReadLine()?.Trim();
if (confirm != "CONFIRM")
{
    Console.WriteLine("Installation cancelled.");
    return 0;
}

Console.WriteLine();
Step("Downloading domain blocklists...");
await DownloadBlocklists(social);

Step("Copying service binaries...");
var installDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
    "BadWebsiteBlocker");
Directory.CreateDirectory(installDir);
CopyBinaries(installDir);

Step("Installing Windows services...");
var serviceBin  = Path.Combine(installDir, "BadBlocker.Service.exe");
var guardBin    = Path.Combine(installDir, "BadBlocker.Guard.exe");
InstallService("BadBlockerService", "BadWebsiteBlocker - Blocker Service", serviceBin);
InstallService("BadBlockerGuard",   "BadWebsiteBlocker - Guard Service",   guardBin);

Step("Configuring service recovery (auto-restart on failure)...");
SetServiceRecovery("BadBlockerService");
SetServiceRecovery("BadBlockerGuard");

Step("Installing firewall rules (DNS lockdown)...");
WfpManager.InstallFilters();

Step("Writing blocked domains to hosts file...");
var blocklist = new BlocklistManager();
blocklist.LoadFromFile(Path.Combine(Config.DataDir, "lists", "adult.txt"));
blocklist.MergeFromFile(Path.Combine(Config.DataDir, "lists", "gambling.txt"));
foreach (var file in social.EnabledFileNames())
    blocklist.MergeFromFile(Path.Combine(Config.DataDir, "lists", file));
blocklist.MergeFromLines(BlocklistManager.DohBypassDomains.Select(d => $"0.0.0.0 {d}"));
var hostsManager = new HostsFileManager(blocklist);
hostsManager.WriteHosts();

Step("Setting DNS to local sinkhole (127.0.0.1)...");
SetDnsToLocalhost();

Step("Locking installation directory permissions...");
LockInstallDir(installDir);

Step("Saving configuration...");
Config.WriteInstallConfig(social);

Step("Starting services...");
Run("sc", "start BadBlockerService");
await Task.Delay(2000);
Run("sc", "start BadBlockerGuard");

Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("Installation complete!");
Console.WriteLine($"Blocking {blocklist.Count:N0} domains.");
Console.WriteLine("Your computer will now block adult and gambling sites.");
if (social.AnyEnabled)
{
    var cats = new List<string>();
    if (social.Harmful)     cats.Add("very harmful social media");
    if (social.FeedsForums) cats.Add("feeds & forums");
    if (social.Streaming)   cats.Add("streaming");
    if (social.YouTube)     cats.Add("YouTube");
    if (social.Messaging)   cats.Add("messaging apps");
    Console.WriteLine($"Also blocking: {string.Join(", ", cats)}.");
}
Console.ResetColor();
Console.WriteLine("\nPress any key to exit.");
Console.ReadKey();
return 0;

// ── helpers ────────────────────────────────────────────────────────────────

static void Step(string msg)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write("  >> ");
    Console.ResetColor();
    Console.WriteLine(msg);
}

static bool IsAdmin()
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

static async Task DownloadBlocklists(SocialCategories social)
{
    var listsDir = Path.Combine(Config.DataDir, "lists");
    Directory.CreateDirectory(listsDir);

    using var http = new HttpClient();
    http.Timeout = TimeSpan.FromMinutes(3);
    http.DefaultRequestHeaders.UserAgent.ParseAdd("BadWebsiteBlocker/1.0");

    await DownloadList(http,
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
        Path.Combine(listsDir, "adult.txt"));

    await DownloadList(http,
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
        Path.Combine(listsDir, "gambling.txt"));

    // Copy bundled social category files from installer directory
    var srcDir = Path.Combine(AppContext.BaseDirectory, "lists");
    foreach (var file in social.EnabledFileNames())
    {
        var src = Path.Combine(srcDir, file);
        if (File.Exists(src))
            File.Copy(src, Path.Combine(listsDir, file), overwrite: true);
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"     WARNING: Missing bundled list file: {file}");
            Console.ResetColor();
        }
    }
}

static async Task DownloadList(HttpClient http, string url, string dest)
{
    try
    {
        Console.WriteLine($"     Downloading {Path.GetFileName(dest)}...");
        var content = await http.GetStringAsync(url);
        await File.WriteAllTextAsync(dest, content);
        Console.WriteLine($"     OK - {content.Split('\n').Length:N0} lines");
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"     WARNING: Could not download {Path.GetFileName(dest)}: {ex.Message}");
        Console.ResetColor();
        if (!File.Exists(dest)) await File.WriteAllTextAsync(dest, "# download failed\n");
    }
}

static void CopyBinaries(string destDir)
{
    var baseDir = AppContext.BaseDirectory;
    var exes = new[] { "BadBlocker.Service.exe", "BadBlocker.Guard.exe" };
    foreach (var exe in exes)
    {
        var src = Path.Combine(baseDir, exe);
        if (File.Exists(src))
            File.Copy(src, Path.Combine(destDir, exe), overwrite: true);
    }
    foreach (var file in Directory.GetFiles(baseDir, "*.dll")
        .Concat(Directory.GetFiles(baseDir, "*.json"))
        .Concat(Directory.GetFiles(baseDir, "*.runtimeconfig.json")))
    {
        File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)), overwrite: true);
    }
}

static void InstallService(string name, string displayName, string binPath)
{
    Run("sc", $"stop {name}");
    Run("sc", $"delete {name}");
    Thread.Sleep(500);
    Run("sc", $"create {name} binPath= \"{binPath}\" start= auto obj= LocalSystem DisplayName= \"{displayName}\"");
    Run("sc", $"description {name} \"BadWebsiteBlocker protection service - do not disable\"");
}

static void SetServiceRecovery(string name)
{
    // reset=86400: failure count resets only after 24h of clean uptime so escalation actually fires
    Run("sc", $"failure {name} reset= 86400 actions= restart/0/restart/0/reboot/0");
    Run("sc", $"failureflag {name} 1");
}

static void SetDnsToLocalhost()
{
    Run("powershell", "-NoProfile -Command \"" +
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | " +
        "ForEach-Object { " +
        "Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '127.0.0.1'; " +
        "netsh interface ipv6 set dnsservers name=$($_.InterfaceIndex) static '::1' primary | Out-Null " +
        "}\"");
}

static void LockInstallDir(string dir)
{
    try
    {
        var info = new DirectoryInfo(dir);
        var acl  = info.GetAccessControl();
        acl.SetAccessRuleProtection(true, false);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var trustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        acl.AddAccessRule(new FileSystemAccessRule(system,
            FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(trustedInstaller,
            FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        acl.AddAccessRule(new FileSystemAccessRule(admins,
            FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"     WARNING: Could not lock install dir ACLs: {ex.Message}");
        Console.ResetColor();
    }
}

static void Run(string exe, string args)
{
    try
    {
        using var p = Process.Start(new ProcessStartInfo(exe, args)
        {
            UseShellExecute        = false,
            CreateNoWindow         = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        })!;
        p.WaitForExit(15_000);
    }
    catch { }
}
