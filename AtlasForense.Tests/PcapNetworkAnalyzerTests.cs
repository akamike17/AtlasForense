using System.Buffers.Binary;
using System.Net;
using System.Text;
using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

public sealed class PcapNetworkAnalyzerTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"atlas-pcap-{Guid.NewGuid():N}.pcap");

    [Fact]
    public async Task Analyzer_ExtractsDnsConversationEntitiesAndUtcTimeline()
    {
        var dns = BuildDnsQuery("evidence.example.test");
        var frame = BuildUdpFrame("192.0.2.10", "198.51.100.53", 53000, 53, dns);
        await File.WriteAllBytesAsync(_path, BuildCapture(frame, littleEndian: true, seconds: 1_700_000_000, fraction: 123_456));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-PCAP", OriginalFileName = "traffic.pcap" };

        var output = await new PcapNetworkAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Domain && x.Value == "evidence.example.test");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.IpAddress && x.Value == "192.0.2.10");
        Assert.Contains(output.Entities, x => x.Type == "Domain" && x.Value == "evidence.example.test");
        Assert.Contains(output.Relationships, x => x.RelationshipType == "UDP" && x.Description.Contains(":53"));
        Assert.Single(output.Events);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddTicks(1_234_560), output.Events[0].OccurredAtUtc);
    }

    [Fact]
    public async Task Analyzer_HandlesBigEndianCaptureAndVisibleHttpHost()
    {
        var http = Encoding.ASCII.GetBytes("GET /case HTTP/1.1\r\nHost: portal.example.org\r\n\r\n");
        var frame = BuildTcpFrame("203.0.113.8", "203.0.113.9", 49152, 80, http);
        await File.WriteAllBytesAsync(_path, BuildCapture(frame, littleEndian: false, seconds: 1_710_000_000, fraction: 5));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-HTTP", OriginalFileName = "web.cap" };

        var output = await new PcapNetworkAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Formato de captura" && x.Context.Contains("endian=big"));
        Assert.Contains(output.Artifacts, x => x.Name == "Host HTTP" && x.Value == "portal.example.org");
        Assert.Contains(output.Relationships, x => x.RelationshipType == "TCP");
    }

    [Fact]
    public async Task Analyzer_RejectsTruncatedPacketInsteadOfReadingPastCapture()
    {
        var capture = BuildCapture([1, 2, 3], littleEndian: true, seconds: 1_700_000_000, fraction: 0);
        BinaryPrimitives.WriteUInt32LittleEndian(capture.AsSpan(32, 4), 50);
        await File.WriteAllBytesAsync(_path, capture);
        var evidence = new EvidenceItem { OriginalFileName = "broken.pcap" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new PcapNetworkAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    [Fact]
    public async Task Analyzer_ReadsPcapNgInterfaceResolutionAndIpv6Dns()
    {
        var dns = BuildDnsQuery("ipv6.example.test");
        var frame = BuildUdpIpv6Frame("2001:db8::10", "2001:db8::53", 54000, 53, dns);
        const ulong timestamp = 1_700_000_000_123_456;
        await File.WriteAllBytesAsync(_path, BuildPcapNg(frame, timestamp));
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-PCAPNG", OriginalFileName = "traffic.pcapng" };

        var output = await new PcapNetworkAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Formato de captura" && x.Value == "PCAPNG");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.IpAddress && x.Value == "2001:db8::10");
        Assert.Contains(output.Indicators, x => x.Type == IndicatorType.Domain && x.Value == "ipv6.example.test");
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddTicks(1_234_560), Assert.Single(output.Events).OccurredAtUtc);
    }

    [Fact]
    public async Task Analyzer_RejectsPcapNgWithMismatchedTrailingLength()
    {
        var data = BuildPcapNg(BuildUdpIpv6Frame("2001:db8::1", "2001:db8::2", 1, 2, []), 0);
        data[^1] ^= 1;
        await File.WriteAllBytesAsync(_path, data);
        var evidence = new EvidenceItem { OriginalFileName = "broken.pcapng" };

        await Assert.ThrowsAsync<InvalidDataException>(() => new PcapNetworkAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, _path, default)));
    }

    private static byte[] BuildCapture(byte[] frame, bool littleEndian, uint seconds, uint fraction)
    {
        var data = new byte[24 + 16 + frame.Length];
        (littleEndian ? new byte[] { 0xd4, 0xc3, 0xb2, 0xa1 } : [0xa1, 0xb2, 0xc3, 0xd4]).CopyTo(data, 0);
        Write16(data, 4, 2, littleEndian); Write16(data, 6, 4, littleEndian); Write32(data, 16, 65535, littleEndian); Write32(data, 20, 1, littleEndian);
        Write32(data, 24, seconds, littleEndian); Write32(data, 28, fraction, littleEndian); Write32(data, 32, (uint)frame.Length, littleEndian); Write32(data, 36, (uint)frame.Length, littleEndian);
        frame.CopyTo(data, 40); return data;
    }

    private static byte[] BuildDnsQuery(string domain)
    {
        var result = new List<byte>([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        foreach (var label in domain.Split('.')) { result.Add((byte)label.Length); result.AddRange(Encoding.ASCII.GetBytes(label)); }
        result.Add(0); result.AddRange([0, 1, 0, 1]); return result.ToArray();
    }

    private static byte[] BuildUdpFrame(string source, string target, ushort sourcePort, ushort targetPort, byte[] payload)
    {
        var transport = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(transport, sourcePort); BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(2), targetPort); BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(4), (ushort)transport.Length); payload.CopyTo(transport, 8);
        return BuildIpv4Frame(source, target, 17, transport);
    }

    private static byte[] BuildTcpFrame(string source, string target, ushort sourcePort, ushort targetPort, byte[] payload)
    {
        var transport = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(transport, sourcePort); BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(2), targetPort); transport[12] = 0x50; payload.CopyTo(transport, 20);
        return BuildIpv4Frame(source, target, 6, transport);
    }

    private static byte[] BuildIpv4Frame(string source, string target, byte protocol, byte[] transport)
    {
        var frame = new byte[14 + 20 + transport.Length];
        frame[12] = 0x08; frame[13] = 0x00; var ip = frame.AsSpan(14); ip[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(2), (ushort)(20 + transport.Length)); ip[8] = 64; ip[9] = protocol;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 26); IPAddress.Parse(target).GetAddressBytes().CopyTo(frame, 30); transport.CopyTo(frame, 34); return frame;
    }

    private static byte[] BuildUdpIpv6Frame(string source, string target, ushort sourcePort, ushort targetPort, byte[] payload)
    {
        var transport = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(transport, sourcePort); BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(2), targetPort); BinaryPrimitives.WriteUInt16BigEndian(transport.AsSpan(4), (ushort)transport.Length); payload.CopyTo(transport, 8);
        var frame = new byte[14 + 40 + transport.Length];
        frame[12] = 0x86; frame[13] = 0xdd; var ip = frame.AsSpan(14); ip[0] = 0x60; BinaryPrimitives.WriteUInt16BigEndian(ip.Slice(4), (ushort)transport.Length); ip[6] = 17; ip[7] = 64;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(frame, 22); IPAddress.Parse(target).GetAddressBytes().CopyTo(frame, 38); transport.CopyTo(frame, 54); return frame;
    }

    private static byte[] BuildPcapNg(byte[] frame, ulong timestamp)
    {
        var padded = (frame.Length + 3) & ~3;
        var data = new byte[28 + 32 + 32 + padded];
        var offset = 0;
        WriteBlockHeader(data, offset, 0x0a0d0d0a, 28); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 8), 0x1a2b3c4d); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset + 12), 1); BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset + 16), ulong.MaxValue); WriteBlockTrailer(data, offset, 28); offset += 28;
        WriteBlockHeader(data, offset, 1, 32); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset + 8), 1); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 12), 65535); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset + 16), 9); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset + 18), 1); data[offset + 20] = 6; WriteBlockTrailer(data, offset, 32); offset += 32;
        var blockLength = 32 + padded; WriteBlockHeader(data, offset, 6, blockLength); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 12), (uint)(timestamp >> 32)); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 16), (uint)timestamp); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 20), (uint)frame.Length); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 24), (uint)frame.Length); frame.CopyTo(data, offset + 28); WriteBlockTrailer(data, offset, blockLength);
        return data;
    }

    private static void WriteBlockHeader(byte[] data, int offset, uint type, int length) { BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), type); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 4), (uint)length); }
    private static void WriteBlockTrailer(byte[] data, int offset, int length) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + length - 4), (uint)length);

    private static void Write16(byte[] data, int offset, ushort value, bool little) { if (little) BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset), value); else BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(offset), value); }
    private static void Write32(byte[] data, int offset, uint value, bool little) { if (little) BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value); else BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset), value); }
    public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
}
