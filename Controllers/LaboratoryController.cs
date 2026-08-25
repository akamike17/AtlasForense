using AtlasForense.Models;
using AtlasForense.Services;
using Microsoft.AspNetCore.Mvc;

namespace AtlasForense.Controllers;

[AutoValidateAntiforgeryToken]
public sealed class LaboratoryController(IContentTransformationService transformations) : Controller
{
    [HttpGet]
    public IActionResult Index() => View(new TransformationLabViewModel());

    [HttpPost]
    public IActionResult Transform(TransformationInput input)
    {
        var model = new TransformationLabViewModel { Input = input };
        if (!ModelState.IsValid) return View("Index", model);
        model.Result = transformations.Transform(input);
        return View("Index", model);
    }

    [HttpPost]
    public IActionResult Detect(TransformationInput input)
    {
        var model = new TransformationLabViewModel { Input = input };
        if (!ModelState.IsValid) return View("Index", model);
        model.DetectedLayers = transformations.DetectAndDecode(input.Input);
        return View("Index", model);
    }
}
