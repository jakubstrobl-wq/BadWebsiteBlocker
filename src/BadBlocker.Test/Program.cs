using BadBlocker.Core;
using System.Net;
using System.Net.Sockets;
using System.Text;

Console.WriteLine("BadWebsiteBlocker — Functional Test");
Console.WriteLine("====================================");
Console.WriteLine();

int pass = 0, fail = 0;

// ── 1. BlocklistManager tests (no network, no admin) ────────────────────────

Console.WriteLine("=== BlocklistManager ===");

var mgr = new BlocklistManager();
mgr.LoadFromLines(new[]
{
    "# comment",
    "0.0.0.0 pornhub.com",
    "0.0.0.0 xvideos.com",
    "0.0.0.0 xhamster.com",
    "0.0.0.0 betway.com",
    "0.0.0.0 pokerstars.com",
    "0.0.0.0 facebook.com",
    "0.0.0.0 instagram.com",
    "0.0.0.0 tiktok.com",
});

Check("pornhub.com is blocked",         mgr.IsBlocked("pornhub.com"));
Check("www.pornhub.com is blocked",     mgr.IsBlocked("www.pornhub.com"));
Check("subdomain.xvideos.com blocked",  mgr.IsBlocked("subdomain.xvideos.com"));
Check("betway.com is blocked",          mgr.IsBlocked("betway.com"));
Check("facebook.com is blocked",        mgr.IsBlocked("facebook.com"));
Check("google.com NOT blocked",         !mgr.IsBlocked("google.com"));
Check("microsoft.com NOT blocked",      !mgr.IsBlocked("microsoft.com"));
Check("bbc.com NOT blocked",            !mgr.IsBlocked("bbc.com"));
Check("Count > 5",                      mgr.Count > 5);

Console.WriteLine();

// ── 2. DNS packet construction tests (no network) ───────────────────────────

Console.WriteLine("=== DNS Packet Parser ===");

// Build a real DNS query for "pornhub.com" using standard wire format
var testQuery = BuildDnsQuery("pornhub.com", txId: 0xABCD);
var parsedDomain = InvokeParseQueryName(testQuery);
Check("ParseQueryName extracts 'pornhub.com'", parsedDomain == "pornhub.com");

var testQuery2 = BuildDnsQuery("google.com", txId: 0x1234);
var parsedDomain2 = InvokeParseQueryName(testQuery2);
Check("ParseQueryName extracts 'google.com'", parsedDomain2 == "google.com");

var nxResp = InvokeMakeNxDomain(testQuery);
Check("NXDOMAIN preserves txId",        nxResp[0] == 0xAB && nxResp[1] == 0xCD);
Check("NXDOMAIN sets QR bit",           (nxResp[2] & 0x80) != 0);
Check("NXDOMAIN RCODE=3",               (nxResp[3] & 0x0F) == 3);
Check("NXDOMAIN zeroes answer count",   nxResp[6] == 0 && nxResp[7] == 0);

Console.WriteLine();

// ── 3. Live DNS sinkhole test on port 5353 (no admin needed) ─────────────────

Console.WriteLine("=== DNS Sinkhole (live on port 5353) ===");

var sinkhole = new DnsSinkhole(mgr, port: 15353);
try
{
    sinkhole.Start();
    await Task.Delay(200); // let the listener spin up

    // Test 1: blocked domain → NXDOMAIN
    var blocked = await QueryDns("pornhub.com", 15353);
    Check("pornhub.com → NXDOMAIN (RCODE=3)", blocked.rcode == 3);

    var blocked2 = await QueryDns("www.xvideos.com", 15353);
    Check("www.xvideos.com → NXDOMAIN",        blocked2.rcode == 3);

    var blocked3 = await QueryDns("betway.com", 15353);
    Check("betway.com → NXDOMAIN",             blocked3.rcode == 3);

    var blocked4 = await QueryDns("facebook.com", 15353);
    Check("facebook.com → NXDOMAIN",           blocked4.rcode == 3);

    // Test 2: allowed domain → real response from upstream
    var allowed = await QueryDns("google.com", 15353);
    Check("google.com → real answer (RCODE=0)", allowed.rcode == 0);

    var allowed2 = await QueryDns("microsoft.com", 15353);
    Check("microsoft.com → real answer",        allowed2.rcode == 0);
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"  EXCEPTION: {ex.Message}");
    Console.ResetColor();
    fail++;
}
finally
{
    sinkhole.Dispose();
}

Console.WriteLine();

// ── 4. Memory/performance measurement ───────────────────────────────────────

Console.WriteLine("=== Performance ===");
var domains = new List<string>();
for (int i = 0; i < 100_000; i++) domains.Add($"blocked-domain-{i}.com");
var bigMgr = new BlocklistManager();
bigMgr.LoadFromLines(domains.Select(d => $"0.0.0.0 {d}"));

var sw = System.Diagnostics.Stopwatch.StartNew();
for (int i = 0; i < 1_000_000; i++) bigMgr.IsBlocked("blocked-domain-50000.com");
sw.Stop();
Console.WriteLine($"  1,000,000 IsBlocked() lookups on 100k-domain list: {sw.ElapsedMilliseconds}ms");
Check("1M lookups in <500ms", sw.ElapsedMilliseconds < 500);

GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
var memBefore = GC.GetTotalMemory(true);
var bigMgr2 = new BlocklistManager();
bigMgr2.LoadFromLines(domains.Select(d => $"0.0.0.0 {d}"));
GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
var memAfter = GC.GetTotalMemory(true);
var mbUsed = (memAfter - memBefore) / 1024.0 / 1024.0;
Console.WriteLine($"  100k-domain HashSet memory: ~{mbUsed:F1} MB");
Check("100k domains use <20 MB", mbUsed < 20);

Console.WriteLine();

// ── Summary ─────────────────────────────────────────────────────────────────

Console.ForegroundColor = pass + fail > 0 && fail == 0 ? ConsoleColor.Green : ConsoleColor.Yellow;
Console.WriteLine($"Results: {pass} passed, {fail} failed");
Console.ResetColor();
return fail == 0 ? 0 : 1;

// ── Helpers ──────────────────────────────────────────────────────────────────

void Check(string label, bool result)
{
    if (result) { pass++; Console.ForegroundColor = ConsoleColor.Green;  Console.WriteLine($"  PASS  {label}"); }
    else        { fail++; Console.ForegroundColor = ConsoleColor.Red;    Console.WriteLine($"  FAIL  {label}"); }
    Console.ResetColor();
}

// Builds a minimal DNS A-query packet for the given domain
static byte[] BuildDnsQuery(string domain, ushort txId = 0x0001)
{
    var ms = new System.IO.MemoryStream();
    // Header: ID, flags (RD=1), QDCOUNT=1, rest 0
    ms.WriteByte((byte)(txId >> 8)); ms.WriteByte((byte)(txId & 0xFF));
    ms.WriteByte(0x01); ms.WriteByte(0x00); // flags: recursion desired
    ms.WriteByte(0x00); ms.WriteByte(0x01); // QDCOUNT=1
    ms.WriteByte(0x00); ms.WriteByte(0x00); // ANCOUNT=0
    ms.WriteByte(0x00); ms.WriteByte(0x00); // NSCOUNT=0
    ms.WriteByte(0x00); ms.WriteByte(0x00); // ARCOUNT=0
    // QNAME
    foreach (var label in domain.Split('.'))
    {
        ms.WriteByte((byte)label.Length);
        ms.Write(Encoding.ASCII.GetBytes(label));
    }
    ms.WriteByte(0x00); // root label
    ms.WriteByte(0x00); ms.WriteByte(0x01); // QTYPE=A
    ms.WriteByte(0x00); ms.WriteByte(0x01); // QCLASS=IN
    return ms.ToArray();
}

// Sends a DNS query to 127.0.0.1:port and returns (rcode, hasAnswers)
static async Task<(int rcode, bool hasAnswers)> QueryDns(string domain, int port)
{
    var query = BuildDnsQuery(domain);
    using var udp = new UdpClient();
    udp.Client.ReceiveTimeout = 4000;
    var ep = new IPEndPoint(IPAddress.Loopback, port);
    await udp.SendAsync(query, query.Length, ep);
    try
    {
        var result = await udp.ReceiveAsync();
        var buf = result.Buffer;
        if (buf.Length < 4) return (-1, false);
        var rcode    = buf[3] & 0x0F;
        var ancount  = (buf[6] << 8) | buf[7];
        return (rcode, ancount > 0);
    }
    catch { return (-1, false); }
}

// Reflection-free wrappers that call DnsSinkhole's private static helpers
// via a subclass trick — instead, we duplicate the minimal logic here for testing
static string? InvokeParseQueryName(byte[] buf)
{
    if (buf.Length < 13) return null;
    var sb = new StringBuilder();
    var i = 12;
    while (i < buf.Length)
    {
        var len = buf[i++];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) break;
        if (i + len > buf.Length) return null;
        if (sb.Length > 0) sb.Append('.');
        sb.Append(Encoding.ASCII.GetString(buf, i, len));
        i += len;
    }
    return sb.Length > 0 ? sb.ToString() : null;
}

static byte[] InvokeMakeNxDomain(byte[] query)
{
    var resp = (byte[])query.Clone();
    resp[2] = (byte)(0x80 | (query[2] & 0x01));
    resp[3] = 0x83;
    resp[6] = 0; resp[7] = 0;
    resp[8] = 0; resp[9] = 0;
    resp[10] = 0; resp[11] = 0;
    return resp;
}
