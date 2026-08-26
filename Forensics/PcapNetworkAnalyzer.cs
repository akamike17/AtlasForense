using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;
using AtlasForense.Models;

namespace AtlasForense.Forensics;

public sealed class PcapNetworkAnalyzer : IForensicAnalyzer
{
    private const int MaxCaptureBytes = 64 * 1024 * 1024;
    private const int MaxPacketBytes = 1024 * 1024;
    private const int MaxPackets = 100_000;
    private const int MaxTimelineEvents = 10_000;
    public string Id => "pcap-network-conversations";
    public string Version => "1.1.0";
    public bool CanAnalyze(EvidenceItem evidence) => new[] { ".pcap", ".cap", ".pcapng" }.Contains(Path.GetExtension(evidence.OriginalFileName), StringComparer.OrdinalIgnoreCase);

    public async Task<AnalyzerOutput> AnalyzeAsync(AnalyzerContext context)
    {
        var data = await ReadBounded(context.FilePath, context.CancellationToken);
        if (data.Length >= 4 && data.AsSpan(0, 4).SequenceEqual(new byte[] { 0x0a, 0x0d, 0x0d, 0x0a }))
            return AnalyzePcapNg(data, new FileInfo(context.FilePath).Length > data.Length, context);
        if (data.Length < 24) throw new InvalidDataException("La cabecera PCAP está truncada.");
        var format = DetectFormat(data);
        var major = ReadUInt16(data, 4, format.LittleEndian);
        var network = ReadUInt32(data, 20, format.LittleEndian);
        if (major != 2) throw new InvalidDataException($"Versión PCAP no soportada: {major}.");
        if (network != 1) throw new InvalidDataException($"Solo se admite enlace Ethernet (DLT 1); observado {network}.");

        var output = new AnalyzerOutput();
        Add(output, context, ArtifactKind.Metadata, "Formato de captura", "PCAP clásico", $"endian={(format.LittleEndian ? "little" : "big")}; precisión={(format.Nanoseconds ? "nanosegundos" : "microsegundos")}; enlace=Ethernet", 0);
        var offset = 24;
        var packets = 0;
        var ipPackets = 0;
        var truncatedByBudget = new FileInfo(context.FilePath).Length > data.Length;
        while (offset < data.Length && packets < MaxPackets)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (data.Length - offset < 16) throw new InvalidDataException($"Cabecera de paquete truncada en offset {offset}.");
            var packetOffset = offset;
            var seconds = ReadUInt32(data, offset, format.LittleEndian);
            var fraction = ReadUInt32(data, offset + 4, format.LittleEndian);
            var included = ReadUInt32(data, offset + 8, format.LittleEndian);
            var original = ReadUInt32(data, offset + 12, format.LittleEndian);
            offset += 16;
            if (included > MaxPacketBytes || included > data.Length - offset) throw new InvalidDataException($"Longitud de paquete inválida en offset {packetOffset}.");
            packets++;
            var time = PacketTime(seconds, fraction, format.Nanoseconds);
            if (TryParseIp(data.AsSpan(offset, (int)included), out var ip))
            {
                ipPackets++;
                ProcessIpPacket(output, context, ip, time, packets, packetOffset, original, included);
            }
            offset += (int)included;
        }

        if (packets == MaxPackets && offset < data.Length) truncatedByBudget = true;
        Add(output, context, ArtifactKind.Metadata, "Límite de captura", truncatedByBudget ? "Lectura parcial" : "Lectura completa", $"bytes inspeccionados={data.Length}; paquetes={packets}", null);
        output.Summary = $"PCAP estático: {packets} paquete(s), {ipPackets} IP, {output.Relationships.Count} conversación(es), {output.Indicators.Count(x => x.Type == IndicatorType.Domain)} dominio(s); {(truncatedByBudget ? "lectura acotada" : "captura completa")}, sin transmisión de red.";
        return output;
    }

    private static AnalyzerOutput AnalyzePcapNg(byte[] data, bool truncatedByBudget, AnalyzerContext context)
    {
        var output = new AnalyzerOutput();
        var interfaces = new List<PcapNgInterface>();
        var offset = 0;
        var packets = 0;
        var ipPackets = 0;
        var little = true;
        var sectionSeen = false;
        while (offset < data.Length && packets < MaxPackets)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (data.Length - offset < 12) throw new InvalidDataException($"Bloque PCAPNG truncado en offset {offset}.");
            var rawType = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
            if (rawType == 0x0a0d0d0a)
            {
                var magic = data.AsSpan(offset + 8, 4);
                little = magic.SequenceEqual(new byte[] { 0x4d, 0x3c, 0x2b, 0x1a });
                if (!little && !magic.SequenceEqual(new byte[] { 0x1a, 0x2b, 0x3c, 0x4d })) throw new InvalidDataException("Byte-order magic PCAPNG inválido.");
                interfaces.Clear(); sectionSeen = true;
            }
            if (!sectionSeen) throw new InvalidDataException("PCAPNG debe iniciar con un Section Header Block.");
            var type = ReadUInt32(data, offset, little);
            var blockLength = ReadUInt32(data, offset + 4, little);
            if (blockLength < 12 || (blockLength & 3) != 0 || blockLength > data.Length - offset) throw new InvalidDataException($"Longitud de bloque PCAPNG inválida en offset {offset}.");
            if (ReadUInt32(data, offset + (int)blockLength - 4, little) != blockLength) throw new InvalidDataException($"Longitudes PCAPNG no coinciden en offset {offset}.");
            if (type == 1)
            {
                if (blockLength < 20) throw new InvalidDataException("Interface Description Block truncado.");
                var linkType = ReadUInt16(data, offset + 8, little);
                var units = ReadTimestampUnits(data, offset + 16, offset + (int)blockLength - 4, little);
                interfaces.Add(new PcapNgInterface(linkType, units));
            }
            else if (type == 6)
            {
                if (blockLength < 32) throw new InvalidDataException("Enhanced Packet Block truncado.");
                var interfaceId = ReadUInt32(data, offset + 8, little);
                if (interfaceId >= interfaces.Count) throw new InvalidDataException("Enhanced Packet Block referencia una interfaz inexistente.");
                var captured = ReadUInt32(data, offset + 20, little);
                var original = ReadUInt32(data, offset + 24, little);
                if (captured > MaxPacketBytes || captured > blockLength - 32) throw new InvalidDataException("Longitud capturada PCAPNG inválida.");
                packets++;
                var iface = interfaces[(int)interfaceId];
                if (iface.LinkType == 1 && TryParseIp(data.AsSpan(offset + 28, (int)captured), out var ip))
                {
                    ipPackets++;
                    var rawTime = ((ulong)ReadUInt32(data, offset + 12, little) << 32) | ReadUInt32(data, offset + 16, little);
                    ProcessIpPacket(output, context, ip, PcapNgTime(rawTime, iface.TimestampUnits), packets, offset, original, captured);
                }
            }
            else if (type == 3)
            {
                if (blockLength < 16 || interfaces.Count == 0) throw new InvalidDataException("Simple Packet Block inválido o sin interfaz.");
                var original = ReadUInt32(data, offset + 8, little);
                var captured = Math.Min(original, blockLength - 16);
                if (captured > MaxPacketBytes) throw new InvalidDataException("Simple Packet Block excede el límite.");
                packets++;
                if (interfaces[0].LinkType == 1 && TryParseIp(data.AsSpan(offset + 12, (int)captured), out var ip)) { ipPackets++; ProcessIpPacket(output, context, ip, null, packets, offset, original, captured); }
            }
            offset += (int)blockLength;
        }
        if (packets == MaxPackets && offset < data.Length) truncatedByBudget = true;
        Add(output, context, ArtifactKind.Metadata, "Formato de captura", "PCAPNG", $"interfaces={interfaces.Count}; secciones interpretadas; resolución temporal por interfaz", 0);
        Add(output, context, ArtifactKind.Metadata, "Límite de captura", truncatedByBudget ? "Lectura parcial" : "Lectura completa", $"bytes inspeccionados={data.Length}; paquetes={packets}", null);
        output.Summary = $"PCAPNG estático: {packets} paquete(s), {ipPackets} IP, {output.Relationships.Count} conversación(es), {output.Indicators.Count(x => x.Type == IndicatorType.Domain)} dominio(s); {(truncatedByBudget ? "lectura acotada" : "captura completa")}, sin transmisión de red.";
        return output;
    }

    private static void ProcessIpPacket(AnalyzerOutput output, AnalyzerContext context, IpPacket ip, DateTimeOffset? time, int packetNumber, long packetOffset, uint originalLength, uint includedLength)
    {
        var source = AddEntity(output, context, "IpAddress", ip.Source.ToString());
        var target = AddEntity(output, context, "IpAddress", ip.Destination.ToString());
        AddIpIndicator(output, context, ip.Source.ToString(), packetNumber);
        AddIpIndicator(output, context, ip.Destination.ToString(), packetNumber);
        var protocol = ip.Protocol switch { 6 => "TCP", 17 => "UDP", _ => $"IP-{ip.Protocol}" };
        var sourceEndpoint = ip.SourcePort.HasValue ? $"{ip.Source}:{ip.SourcePort}" : ip.Source.ToString();
        var targetEndpoint = ip.DestinationPort.HasValue ? $"{ip.Destination}:{ip.DestinationPort}" : ip.Destination.ToString();
        if (!output.Relationships.Any(x => x.SourceEntityId == source.Id && x.TargetEntityId == target.Id && x.RelationshipType == protocol))
            output.Relationships.Add(new CaseRelationship { SourceEntityId = source.Id, TargetEntityId = target.Id, RelationshipType = protocol, Description = $"{sourceEndpoint} → {targetEndpoint}", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
        if (!output.Artifacts.Any(x => x.Kind == ArtifactKind.NetworkEndpoint && x.Value == $"{protocol} {sourceEndpoint} -> {targetEndpoint}"))
            Add(output, context, ArtifactKind.NetworkEndpoint, "Conversación", $"{protocol} {sourceEndpoint} -> {targetEndpoint}", $"observada desde paquete {packetNumber}", packetOffset);

        if (time.HasValue && output.Events.Count < MaxTimelineEvents)
            output.Events.Add(new TimelineEvent { EvidenceId = context.Evidence.Id, OccurredAtUtc = time.Value, Category = "Red", Title = $"Paquete {packetNumber}: {protocol}", Description = $"{sourceEndpoint} → {targetEndpoint}; capturado={includedLength}; original={originalLength}", Source = $"{context.Evidence.Identifier}/pcap@{packetOffset}", Confidence = ConfidenceLevel.Observed });
        if (ip.Protocol == 17 && (ip.SourcePort == 53 || ip.DestinationPort == 53)) ExtractDns(output, context, ip.Payload, packetNumber, packetOffset);
        if (ip.Protocol == 6 && (ip.SourcePort is 80 or 8080 or 8000 || ip.DestinationPort is 80 or 8080 or 8000)) ExtractHttpHost(output, context, ip.Payload, packetNumber, packetOffset);
    }

    private static bool TryParseIp(ReadOnlySpan<byte> frame, out IpPacket packet)
    {
        packet = default;
        if (frame.Length < 14) return false;
        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[12..14]);
        var ipOffset = 14;
        if (etherType == 0x8100 && frame.Length >= 18) { etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[16..18]); ipOffset = 18; }
        if (etherType == 0x86dd) return TryParseIpv6(frame[ipOffset..], out packet);
        if (etherType != 0x0800 || frame.Length < ipOffset + 20 || frame[ipOffset] >> 4 != 4) return false;
        var headerLength = (frame[ipOffset] & 0x0f) * 4;
        if (headerLength < 20 || frame.Length < ipOffset + headerLength) return false;
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 2, 2));
        if (totalLength < headerLength || frame.Length < ipOffset + totalLength) return false;
        var fragment = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ipOffset + 6, 2));
        var protocol = frame[ipOffset + 9];
        var source = new IPAddress(frame.Slice(ipOffset + 12, 4));
        var destination = new IPAddress(frame.Slice(ipOffset + 16, 4));
        var transport = frame.Slice(ipOffset + headerLength, totalLength - headerLength);
        ushort? sourcePort = null, destinationPort = null;
        ReadOnlySpan<byte> payload = transport;
        if ((fragment & 0x1fff) == 0 && protocol == 17 && transport.Length >= 8)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport[..2]); destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2)); payload = transport[8..];
        }
        else if ((fragment & 0x1fff) == 0 && protocol == 6 && transport.Length >= 20)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport[..2]); destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2));
            var tcpHeader = (transport[12] >> 4) * 4; payload = tcpHeader >= 20 && tcpHeader <= transport.Length ? transport[tcpHeader..] : [];
        }
        packet = new IpPacket(source, destination, protocol, sourcePort, destinationPort, payload.ToArray());
        return true;
    }

    private static bool TryParseIpv6(ReadOnlySpan<byte> ip, out IpPacket packet)
    {
        packet = default;
        if (ip.Length < 40 || ip[0] >> 4 != 6) return false;
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(ip.Slice(4, 2));
        if (ip.Length < 40 + payloadLength) return false;
        var nextHeader = ip[6];
        var source = new IPAddress(ip.Slice(8, 16));
        var destination = new IPAddress(ip.Slice(24, 16));
        var cursor = 40;
        var fragmented = false;
        for (var extension = 0; extension < 8; extension++)
        {
            if (nextHeader is 0 or 43 or 60)
            {
                if (cursor > 40 + payloadLength - 2) return false;
                var length = (ip[cursor + 1] + 1) * 8;
                if (length < 8 || cursor > 40 + payloadLength - length) return false;
                nextHeader = ip[cursor]; cursor += length; continue;
            }
            if (nextHeader == 44)
            {
                if (cursor > 40 + payloadLength - 8) return false;
                var fragment = BinaryPrimitives.ReadUInt16BigEndian(ip.Slice(cursor + 2, 2));
                fragmented = (fragment & 0xfff8) != 0;
                nextHeader = ip[cursor]; cursor += 8; continue;
            }
            if (nextHeader == 51)
            {
                if (cursor > 40 + payloadLength - 2) return false;
                var length = (ip[cursor + 1] + 2) * 4;
                if (length < 8 || cursor > 40 + payloadLength - length) return false;
                nextHeader = ip[cursor]; cursor += length; continue;
            }
            break;
        }
        var transport = ip.Slice(cursor, 40 + payloadLength - cursor);
        ushort? sourcePort = null, destinationPort = null;
        ReadOnlySpan<byte> payload = transport;
        if (!fragmented && nextHeader == 17 && transport.Length >= 8)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport[..2]); destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2)); payload = transport[8..];
        }
        else if (!fragmented && nextHeader == 6 && transport.Length >= 20)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport[..2]); destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2));
            var tcpHeader = (transport[12] >> 4) * 4; payload = tcpHeader >= 20 && tcpHeader <= transport.Length ? transport[tcpHeader..] : [];
        }
        packet = new IpPacket(source, destination, nextHeader, sourcePort, destinationPort, payload.ToArray());
        return true;
    }

    private static long ReadTimestampUnits(byte[] data, int optionOffset, int optionEnd, bool little)
    {
        var units = 1_000_000L;
        while (optionOffset <= optionEnd - 4)
        {
            var code = ReadUInt16(data, optionOffset, little);
            var length = ReadUInt16(data, optionOffset + 2, little);
            optionOffset += 4;
            if (code == 0) break;
            if (length > optionEnd - optionOffset) throw new InvalidDataException("Opción PCAPNG truncada.");
            if (code == 9 && length == 1)
            {
                var resolution = data[optionOffset];
                var exponent = resolution & 0x7f;
                if ((resolution & 0x80) == 0 && exponent <= 9) units = Pow(10, exponent);
                else if ((resolution & 0x80) != 0 && exponent <= 30) units = 1L << exponent;
                else units = 0;
            }
            optionOffset += (length + 3) & ~3;
        }
        return units;
    }

    private static DateTimeOffset? PcapNgTime(ulong value, long units)
    {
        if (units <= 0) return null;
        try
        {
            var seconds = value / (ulong)units;
            var remainder = value % (ulong)units;
            if (seconds > long.MaxValue) return null;
            return DateTimeOffset.FromUnixTimeSeconds((long)seconds).AddTicks((long)(remainder * 10_000_000UL / (ulong)units));
        }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static long Pow(int value, int exponent) { long result = 1; for (var index = 0; index < exponent; index++) result *= value; return result; }

    private static void ExtractDns(AnalyzerOutput output, AnalyzerContext context, byte[] payload, int packet, long offset)
    {
        if (payload.Length < 13) return;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(4, 2));
        var cursor = 12;
        for (var question = 0; question < Math.Min(questions, (ushort)20); question++)
        {
            var labels = new List<string>();
            var total = 0;
            while (cursor < payload.Length && payload[cursor] != 0)
            {
                var length = payload[cursor++];
                if ((length & 0xc0) != 0 || length > 63 || cursor + length > payload.Length || total + length > 253) return;
                labels.Add(Encoding.ASCII.GetString(payload, cursor, length)); cursor += length; total += length + 1;
            }
            if (cursor >= payload.Length) return;
            cursor++;
            if (cursor + 4 > payload.Length) return;
            cursor += 4;
            var domain = string.Join('.', labels).TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(domain) || output.Indicators.Any(x => x.Type == IndicatorType.Domain && x.NormalizedValue == domain)) continue;
            Add(output, context, ArtifactKind.Domain, "Consulta DNS", domain, $"paquete={packet}", offset);
            output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Domain, Value = domain, NormalizedValue = domain, Description = $"Consulta DNS observada en paquete {packet}", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
            AddEntity(output, context, "Domain", domain);
        }
    }

    private static void ExtractHttpHost(AnalyzerOutput output, AnalyzerContext context, byte[] payload, int packet, long offset)
    {
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 8192));
        foreach (var line in text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) continue;
            var authority = line[5..].Trim();
            var domain = authority.Split(':')[0].Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253 || output.Indicators.Any(x => x.Type == IndicatorType.Domain && x.NormalizedValue == domain)) return;
            Add(output, context, ArtifactKind.Domain, "Host HTTP", domain, $"texto claro; paquete={packet}", offset);
            output.Indicators.Add(new CaseIndicator { Type = IndicatorType.Domain, Value = domain, NormalizedValue = domain, Description = $"Cabecera Host HTTP en paquete {packet}", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
            AddEntity(output, context, "Domain", domain);
            return;
        }
    }

    private static CaseEntity AddEntity(AnalyzerOutput output, AnalyzerContext context, string type, string value)
    {
        var existing = output.Entities.FirstOrDefault(x => x.Type == type && x.Value.Equals(value, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) return existing;
        var entity = new CaseEntity { Type = type, Value = value.ToLowerInvariant(), DisplayName = value, Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] };
        output.Entities.Add(entity); return entity;
    }

    private static void AddIpIndicator(AnalyzerOutput output, AnalyzerContext context, string value, int packet)
    {
        if (output.Indicators.Any(x => x.Type == IndicatorType.IpAddress && x.NormalizedValue == value)) return;
        output.Indicators.Add(new CaseIndicator { Type = IndicatorType.IpAddress, Value = value, NormalizedValue = value, Description = $"Observada en paquete {packet}", Confidence = ConfidenceLevel.Observed, EvidenceIds = [context.Evidence.Id] });
    }

    private static DateTimeOffset? PacketTime(uint seconds, uint fraction, bool nanoseconds)
    {
        try
        {
            if ((!nanoseconds && fraction >= 1_000_000) || (nanoseconds && fraction >= 1_000_000_000)) return null;
            return DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(nanoseconds ? fraction / 100 : fraction * 10L);
        }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static CaptureFormat DetectFormat(byte[] data) => data.AsSpan(0, 4) switch
    {
        [0xd4, 0xc3, 0xb2, 0xa1] => new(true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => new(false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => new(true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => new(false, true),
        _ => throw new InvalidDataException("Firma PCAP desconocida; PCAPNG todavía no se interpreta como PCAP clásico.")
    };
    private static async Task<byte[]> ReadBounded(string path, CancellationToken token) { await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true); var length = (int)Math.Min(stream.Length, MaxCaptureBytes); var data = new byte[length]; var offset = 0; while (offset < length) { var read = await stream.ReadAsync(data.AsMemory(offset), token); if (read == 0) break; offset += read; } return offset == length ? data : data[..offset]; }
    private static ushort ReadUInt16(byte[] data, int offset, bool little) => little ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2)) : BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));
    private static uint ReadUInt32(byte[] data, int offset, bool little) => little ? BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4)) : BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
    private static void Add(AnalyzerOutput output, AnalyzerContext context, ArtifactKind kind, string name, string value, string detail, long? offset) => output.Artifacts.Add(new AnalysisArtifact { EvidenceId = context.Evidence.Id, AnalysisRunId = context.AnalysisRunId, Kind = kind, Name = name, Value = value, Context = detail, Offset = offset, Confidence = ConfidenceLevel.Observed });
    private readonly record struct CaptureFormat(bool LittleEndian, bool Nanoseconds);
    private readonly record struct PcapNgInterface(ushort LinkType, long TimestampUnits);
    private readonly record struct IpPacket(IPAddress Source, IPAddress Destination, byte Protocol, ushort? SourcePort, ushort? DestinationPort, byte[] Payload);
}
