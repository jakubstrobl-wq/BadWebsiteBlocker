namespace BadBlocker.Core;

public sealed class BlocklistManager
{
    private HashSet<string> _blocked = new(StringComparer.OrdinalIgnoreCase);

    public void LoadFromLines(IEnumerable<string> lines)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] == '#') continue;
            string domain;
            if (trimmed.StartsWith("0.0.0.0 ", StringComparison.OrdinalIgnoreCase))
                domain = trimmed[8..].Trim();
            else if (trimmed.StartsWith("127.0.0.1 ", StringComparison.OrdinalIgnoreCase))
                domain = trimmed[10..].Trim();
            else if (!trimmed.Contains(' ') && !trimmed.Contains('\t'))
                domain = trimmed;
            else continue;

            // Remove trailing comments
            var spaceIdx = domain.IndexOf(' ');
            if (spaceIdx >= 0) domain = domain[..spaceIdx];
            domain = domain.ToLowerInvariant().TrimEnd('.');

            if (domain.Length > 0 && domain != "localhost" && !domain.StartsWith("0.0.0.0"))
                set.Add(domain);
        }
        _blocked = set;
    }

    public void LoadFromFile(string path)
    {
        if (!File.Exists(path)) return;
        LoadFromLines(File.ReadLines(path));
    }

    public void MergeFromFile(string path)
    {
        if (!File.Exists(path)) return;
        var extra = new BlocklistManager();
        extra.LoadFromFile(path);
        foreach (var d in extra._blocked) _blocked.Add(d);
    }

    public void MergeFromLines(IEnumerable<string> lines)
    {
        var extra = new BlocklistManager();
        extra.LoadFromLines(lines);
        foreach (var d in extra._blocked) _blocked.Add(d);
    }

    public bool IsBlocked(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        var d = domain.TrimEnd('.'); // OrdinalIgnoreCase handles case; only strip trailing dot
        if (_blocked.Contains(d)) return true;
        // Check parent domains so subdomains are also blocked
        var idx = d.IndexOf('.');
        while (idx > 0 && idx < d.Length - 1)
        {
            var parent = d[(idx + 1)..];
            if (_blocked.Contains(parent)) return true;
            idx = d.IndexOf('.', idx + 1);
        }
        return false;
    }

    // Domains for DNS-over-HTTPS providers — blocked so browsers can't bypass the sinkhole
    public static readonly IReadOnlyList<string> DohBypassDomains = new[]
    {
        "dns.google", "dns64.dns.google",
        "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
        "dns.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
        "doh.opendns.com", "doh.familyshield.opendns.com",
        "doh.cleanbrowsing.org",
        "dns.nextdns.io",
        "doh.dns.sb",
        "odvr.nic.cz",
    };

    public IReadOnlyCollection<string> AllDomains => _blocked;
    public int Count => _blocked.Count;
}
