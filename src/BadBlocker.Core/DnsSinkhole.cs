using System.Net;
using System.Net.Sockets;
using System.Text;

namespace BadBlocker.Core;

public sealed class DnsSinkhole : IDisposable
{
    private readonly BlocklistManager _blocklist;
    private readonly IPEndPoint _upstream = new(IPAddress.Parse("1.1.1.1"), 53);
    private readonly int _port;
    private UdpClient? _server;
    private CancellationTokenSource? _cts;

    public DnsSinkhole(BlocklistManager blocklist, int port = 53)
    {
        _blocklist = blocklist;
        _port = port;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _server = new UdpClient(new IPEndPoint(IPAddress.Loopback, _port));
        Task.Run(() => RunLoop(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _server?.Close();
        _server = null;
    }

    public void Dispose() => Stop();

    private async Task RunLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _server!.ReceiveAsync(ct);
                _ = Task.Run(() => HandleQuery(result.Buffer, result.RemoteEndPoint), ct);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(100, ct).ConfigureAwait(false); }
        }
    }

    private async Task HandleQuery(byte[] data, IPEndPoint client)
    {
        // Capture server reference once; avoids null-race with Stop() and serialises nothing
        var server = _server;
        if (server == null) return;
        try
        {
            var domain = ParseQueryName(data);
            if (domain != null && _blocklist.IsBlocked(domain))
            {
                var nxdomain = MakeNxDomain(data);
                await server.SendAsync(nxdomain, nxdomain.Length, client);
                return;
            }
            // Forward to upstream DNS with a hard 3-second timeout
            using var up = new UdpClient();
            await up.SendAsync(data, data.Length, _upstream);
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                var resp = await up.ReceiveAsync(timeoutCts.Token);
                await server.SendAsync(resp.Buffer, resp.Buffer.Length, client);
            }
            catch { /* upstream timeout or cancelled — drop */ }
        }
        catch { /* drop malformed queries */ }
    }

    // Reads the QNAME from the question section (starts at offset 12).
    // Follows compression pointers (RFC 1035 §4.1.4) so compressed queries are checked correctly.
    private static string? ParseQueryName(byte[] buf)
    {
        if (buf.Length < 13) return null;
        var sb = new StringBuilder();
        var i = 12;
        var maxJumps = 16; // prevent infinite loops from circular pointers
        while (i < buf.Length && maxJumps-- > 0)
        {
            var len = buf[i++];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0)
            {
                // Compression pointer: 14-bit offset from start of message
                if (i >= buf.Length) return null;
                var offset = ((len & 0x3F) << 8) | buf[i];
                if (offset >= buf.Length) return null;
                i = offset; // follow the pointer; no need to advance past it
                continue;
            }
            if (i + len > buf.Length) return null;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(buf, i, len));
            i += len;
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }

    // Returns a NXDOMAIN response reusing the same transaction ID and question
    private static byte[] MakeNxDomain(byte[] query)
    {
        var resp = (byte[])query.Clone();
        // QR=1 (response), OPCODE=0, AA=0, TC=0, RD=copy from query
        resp[2] = (byte)(0x80 | (query[2] & 0x01)); // QR=1, keep RD bit
        resp[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
        // Zero out ANCOUNT, NSCOUNT, ARCOUNT
        resp[6] = 0; resp[7] = 0;
        resp[8] = 0; resp[9] = 0;
        resp[10] = 0; resp[11] = 0;
        return resp;
    }
}
