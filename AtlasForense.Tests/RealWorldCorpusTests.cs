using AtlasForense.Forensics;
using AtlasForense.Models;
using Xunit;

namespace AtlasForense.Tests;

// Corpus generado por escritores oficiales del sistema (wevtutil, reg save, kernel de Windows),
// independiente de los builders sintéticos de los demás tests: los parsers se validan contra
// bytes que ellos no ayudaron a definir.
public sealed class RealWorldCorpusTests
{
    private static string Corpus(string name) => Path.Combine(AppContext.BaseDirectory, "Corpus", name);

    [Fact]
    public async Task Evtx_RealExportFromWevtutil_ParsesCleanlyWithoutCorruptionFlags()
    {
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-CORPUS", OriginalFileName = "real-eventlog.evtx" };

        var output = await new EvtxStructureAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, Corpus("real-eventlog.evtx"), default));

        Assert.Contains(output.Artifacts, x => x.Name == "Cabecera EVTX" && x.Value.StartsWith("v3."));
        var chunk = Assert.Single(output.Artifacts, x => x.Name == "Chunk EVTX");
        Assert.Contains("registros=", chunk.Context);
        Assert.True(output.Events.Count >= 2, "El export real debe producir marcas de primer y último registro.");
        Assert.All(output.Events, x => Assert.InRange(x.OccurredAtUtc.Year, 2006, 2100));
        Assert.DoesNotContain(output.Artifacts, x => x.Name is "Registro EVTX con copia de tamaño inconsistente" or "Chunk EVTX dañado o ausente" or "Offsets de registros inconsistentes" or "Numeración de registros inconsistente" or "Índice de chunk inconsistente");
        Assert.Contains(output.Artifacts, x => x.Name == "Cadena UTF-16");
    }

    [Fact]
    public async Task Registry_RealHiveFromRegSave_TraversesKeysWithoutErrors()
    {
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-CORPUS", OriginalFileName = "corpus.hive", DetectedFileType = "REGF" };

        var output = await new RegistryHiveAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, Corpus("real-hardware.hive"), default));

        Assert.Contains(output.Artifacts, x => x.Name == "Colmena de registro");
        Assert.True(output.Artifacts.Count(x => x.Name == "Clave de registro") >= 2, "La colmena HARDWARE real contiene al menos la raíz y una subclave.");
        Assert.DoesNotContain(output.Artifacts, x => x.Name == "Secuencias de transacción divergentes");
        Assert.Contains("muestra no ejecutada", output.Summary);
    }

    [Fact]
    public async Task Prefetch_RealWindows11File_IsIdentifiedAsCompressedMamContainer()
    {
        var bytes = await File.ReadAllBytesAsync(Corpus("real-sample.pf"));
        if (bytes.Length >= 8 && bytes[4] == (byte)'S' && bytes[5] == (byte)'C' && bytes[6] == (byte)'C' && bytes[7] == (byte)'A')
        {
            var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-CORPUS", OriginalFileName = "real-sample.pf" };
            var output = await new PrefetchAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, Corpus("real-sample.pf"), default));
            Assert.Contains(output.Artifacts, x => x.Name == "Ejecutable Prefetch");
            return;
        }

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => new PrefetchAnalyzer().AnalyzeAsync(
            new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), new EvidenceItem { OriginalFileName = "real-sample.pf" }, Corpus("real-sample.pf"), default)));
        Assert.Contains("MAM", exception.Message);
    }

    [Fact]
    public async Task PortableExecutable_RealToolchainBinary_ParsesHeadersAndSections()
    {
        var realPe = Path.Combine(AppContext.BaseDirectory, "AtlasForense.Tests.dll");
        var evidence = new EvidenceItem { Id = Guid.NewGuid(), Identifier = "EV-CORPUS", OriginalFileName = "AtlasForense.Tests.dll" };

        var output = await new PortableExecutableAnalyzer().AnalyzeAsync(new AnalyzerContext(Guid.NewGuid(), Guid.NewGuid(), evidence, realPe, default));

        Assert.Contains(output.Artifacts, x => x.Name == "Arquitectura PE" && x.Value is "x86" or "x64");
        Assert.True(output.Artifacts.Count(x => x.Name == "Sección PE") >= 1, "Un PE real de la toolchain contiene secciones.");
        Assert.Contains("PE estático", output.Summary);
    }
}
