using System.ComponentModel.DataAnnotations;

namespace AtlasForense.Models;

public enum TransformationDirection { Encode, Decode }
public enum TransformationAlgorithm
{
    Base2, Base8, Base10, Base16, Base32, Base58, Base64, Base64Url, Ascii85,
    RotAlpha, Rot47, RotateBits, Xor, Reverse, Url, Html, UnicodeEscape
}

public sealed class TransformationInput
{
    [Required, StringLength(1_048_576)] public string Input { get; set; } = string.Empty;
    public TransformationDirection Direction { get; set; }
    public TransformationAlgorithm Algorithm { get; set; } = TransformationAlgorithm.Base64;
    [StringLength(256)] public string Parameter { get; set; } = string.Empty;
}

public sealed record TransformationResult(
    bool Success,
    string Output,
    string Error,
    string InputSha256,
    string OutputSha256,
    int InputBytes,
    int OutputBytes,
    string Recipe);

public sealed record DecodingLayer(int Depth, string Algorithm, string InputSha256, string OutputSha256, string Output, double PrintableRatio);

public sealed class TransformationLabViewModel
{
    public TransformationInput Input { get; set; } = new();
    public TransformationResult? Result { get; set; }
    public IReadOnlyList<DecodingLayer> DetectedLayers { get; set; } = [];
}
