using System.ComponentModel.DataAnnotations;

namespace AtlasForense.Models;

public sealed class ForensicStorageOptions
{
    public const string SectionName = "ForensicStorage";
    [Range(1_048_576, 10L * 1024 * 1024 * 1024)] public long MaxEvidenceBytes { get; set; } = 100 * 1024 * 1024;
    [Range(5, 3600)] public int AcquisitionTimeoutSeconds { get; set; } = 300;
    [Range(1, 100_000)] public int MaxArchiveEntries { get; set; } = 10_000;
    [Range(1_048_576, 100L * 1024 * 1024 * 1024)] public long MaxArchiveExpandedBytes { get; set; } = 1024L * 1024 * 1024;
    [Range(2, 10_000)] public double MaxCompressionRatio { get; set; } = 100;
    [Range(0, 20)] public int MaxArchiveDepth { get; set; } = 3;
}

public enum EvidenceClassification { Original, WorkingCopy, DerivedArtifact, ExportedPackage }
