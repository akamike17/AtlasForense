using AtlasForense.Models;

namespace AtlasForense.Services;

public interface IContentTransformationService
{
    TransformationResult Transform(TransformationInput input);
    IReadOnlyList<DecodingLayer> DetectAndDecode(string input, int maxDepth = 6);
}
