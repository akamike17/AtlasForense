using AtlasForense.Models;
using AtlasForense.Services;
using Xunit;

namespace AtlasForense.Tests;

public sealed class ContentTransformationServiceTests
{
    private readonly ContentTransformationService _service = new();

    public static TheoryData<TransformationAlgorithm, string> ReversibleAlgorithms => new()
    {
        { TransformationAlgorithm.Base2, "" },
        { TransformationAlgorithm.Base8, "" },
        { TransformationAlgorithm.Base10, "" },
        { TransformationAlgorithm.Base16, "" },
        { TransformationAlgorithm.Base32, "" },
        { TransformationAlgorithm.Base58, "" },
        { TransformationAlgorithm.Base64, "" },
        { TransformationAlgorithm.Base64Url, "" },
        { TransformationAlgorithm.Ascii85, "" },
        { TransformationAlgorithm.RotAlpha, "7" },
        { TransformationAlgorithm.Rot47, "" },
        { TransformationAlgorithm.RotateBits, "3" },
        { TransformationAlgorithm.Xor, "forensic-key" },
        { TransformationAlgorithm.Reverse, "" },
        { TransformationAlgorithm.Url, "" },
        { TransformationAlgorithm.Html, "" },
        { TransformationAlgorithm.UnicodeEscape, "" }
    };

    [Theory]
    [MemberData(nameof(ReversibleAlgorithms))]
    public void EveryTransformation_RoundTripsUnicodeText(TransformationAlgorithm algorithm, string parameter)
    {
        const string original = "Atlas Forense — evidencia 2026 / áéíóú <tag>";
        var encoded = Apply(original, TransformationDirection.Encode, algorithm, parameter);
        Assert.True(encoded.Success, encoded.Error);

        var decoded = Apply(encoded.Output, TransformationDirection.Decode, algorithm, parameter);

        Assert.True(decoded.Success, decoded.Error);
        Assert.Equal(original, decoded.Output);
        Assert.Equal(64, encoded.InputSha256.Length);
        Assert.Equal(64, decoded.OutputSha256.Length);
    }

    [Theory]
    [InlineData(TransformationAlgorithm.Base16, "Atlas", "41746c6173")]
    [InlineData(TransformationAlgorithm.Base32, "foobar", "MZXW6YTBOI======")]
    [InlineData(TransformationAlgorithm.Base64, "forensic", "Zm9yZW5zaWM=")]
    [InlineData(TransformationAlgorithm.Base64Url, "???>>>", "Pz8_Pj4-")]
    [InlineData(TransformationAlgorithm.Ascii85, "Hello", "<~87cURDZ~>")]
    public void StandardEncodings_MatchKnownVectors(TransformationAlgorithm algorithm, string input, string expected)
    {
        var result = Apply(input, TransformationDirection.Encode, algorithm);
        Assert.True(result.Success, result.Error);
        Assert.Equal(expected, result.Output);
    }

    [Fact]
    public void RotAlpha_SupportsEveryClassicalRotation()
    {
        for (var rotation = 1; rotation <= 25; rotation++)
        {
            var encoded = Apply("AttackAtDawn", TransformationDirection.Encode, TransformationAlgorithm.RotAlpha, rotation.ToString());
            var decoded = Apply(encoded.Output, TransformationDirection.Decode, TransformationAlgorithm.RotAlpha, rotation.ToString());
            Assert.Equal("AttackAtDawn", decoded.Output);
        }
    }

    [Fact]
    public void AutoDecode_UnwrapsNestedBase64AndUrlLayers()
    {
        var url = Apply("https://c2.example.test/api?q=evidence", TransformationDirection.Encode, TransformationAlgorithm.Url).Output;
        var nested = Apply(url, TransformationDirection.Encode, TransformationAlgorithm.Base64).Output;

        var layers = _service.DetectAndDecode(nested);

        Assert.True(layers.Count >= 2);
        Assert.Equal("Base64", layers[0].Algorithm);
        Assert.Equal("URL", layers[1].Algorithm);
        Assert.Equal("https://c2.example.test/api?q=evidence", layers[1].Output);
        Assert.NotEqual(layers[0].InputSha256, layers[0].OutputSha256);
    }

    [Fact]
    public void InvalidInput_IsRejectedWithoutThrowingOrProducingOutput()
    {
        var result = Apply("not-base64%%%", TransformationDirection.Decode, TransformationAlgorithm.Base64);
        Assert.False(result.Success);
        Assert.Empty(result.Output);
        Assert.Contains("inválida", result.Error);
    }

    [Fact]
    public void OversizedInput_IsRejectedBeforeTransformation()
    {
        var result = Apply(new string('A', 1_048_577), TransformationDirection.Encode, TransformationAlgorithm.Base64);
        Assert.False(result.Success);
        Assert.Contains("1 MiB", result.Error);
    }

    private TransformationResult Apply(string value, TransformationDirection direction, TransformationAlgorithm algorithm, string parameter = "") =>
        _service.Transform(new TransformationInput { Input = value, Direction = direction, Algorithm = algorithm, Parameter = parameter });
}
