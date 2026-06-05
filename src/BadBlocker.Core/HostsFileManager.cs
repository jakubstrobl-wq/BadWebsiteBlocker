using System.Security.AccessControl;
using System.Security.Principal;

namespace BadBlocker.Core;

public sealed class HostsFileManager : IDisposable
{
    private static readonly string HostsPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");

    private const string BlockMarkerBegin = "# === BadWebsiteBlocker START ===";
    private const string BlockMarkerEnd   = "# === BadWebsiteBlocker END ===";

    private readonly BlocklistManager _blocklist;
    private FileSystemWatcher? _watcher;
    private readonly object _writeLock = new();

    public HostsFileManager(BlocklistManager blocklist) => _blocklist = blocklist;

    public void WriteAndWatch()
    {
        WriteHosts(); // WriteHosts already locks the file at the end
        StartWatcher();
    }

    public void WriteHosts()
    {
        lock (_writeLock)
        {
            var existing = File.Exists(HostsPath)
                ? File.ReadAllText(HostsPath)
                : string.Empty;

            var stripped = StripOurBlock(existing);

            var lines = new System.Text.StringBuilder();
            lines.AppendLine(stripped.TrimEnd());
            lines.AppendLine();
            lines.AppendLine(BlockMarkerBegin);
            foreach (var domain in _blocklist.AllDomains)
            {
                lines.AppendLine($"127.0.0.1 {domain}");
                lines.AppendLine($"127.0.0.1 www.{domain}");
                lines.AppendLine($"::1 {domain}");
                lines.AppendLine($"::1 www.{domain}");
            }
            lines.AppendLine(BlockMarkerEnd);

            UnlockHostsFile();
            File.WriteAllText(HostsPath, lines.ToString());
            LockHostsFile();
        }
    }

    private void StartWatcher()
    {
        var dir = Path.GetDirectoryName(HostsPath)!;
        _watcher = new FileSystemWatcher(dir, "hosts")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true
        };
        _watcher.Changed += OnHostsChanged;
        _watcher.Deleted += OnHostsChanged;
    }

    private void OnHostsChanged(object _, FileSystemEventArgs e)
    {
        Thread.Sleep(200); // let any external writer finish before we grab the lock
        WriteHosts();      // lock inside WriteHosts serialises concurrent callbacks
    }

    private static string StripOurBlock(string content)
    {
        var start = content.IndexOf(BlockMarkerBegin, StringComparison.Ordinal);
        var end   = content.IndexOf(BlockMarkerEnd,   StringComparison.Ordinal);
        if (start < 0) return content;
        var after = end >= 0 ? end + BlockMarkerEnd.Length : content.Length;
        // Consume the newline that follows the end marker so trailing content doesn't drift
        if (after < content.Length && content[after] == '\r') after++;
        if (after < content.Length && content[after] == '\n') after++;
        return content[..start] + content[Math.Min(after, content.Length)..];
    }

    private static void LockHostsFile()
    {
        try
        {
            var fi  = new FileInfo(HostsPath);
            var acl = fi.GetAccessControl();
            acl.SetAccessRuleProtection(true, false);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            // SetAccessRule replaces existing rules for the same identity, preventing ACE accumulation
            acl.SetAccessRule(new FileSystemAccessRule(system,
                FileSystemRights.FullControl, AccessControlType.Allow));
            acl.SetAccessRule(new FileSystemAccessRule(admins,
                FileSystemRights.Read, AccessControlType.Allow));
            fi.SetAccessControl(acl);
        }
        catch { /* best effort */ }
    }

    private static void UnlockHostsFile()
    {
        try
        {
            var fi  = new FileInfo(HostsPath);
            var acl = fi.GetAccessControl();
            acl.SetAccessRuleProtection(false, true);
            fi.SetAccessControl(acl);
        }
        catch { /* best effort */ }
    }

    public void Dispose()
    {
        _watcher?.Dispose();
        _watcher = null;
    }
}
