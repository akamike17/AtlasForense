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
    public IActionResult Transform(TransformationLabViewModel model)
    {
        if (!ModelState.IsValid) return View("Index", model);
        model.Result = transformations.Transform(model.Input);
        return View("Index", model);
    }

    [HttpPost]
    public IActionResult Detect(TransformationLabViewModel model)
    {
        if (!ModelState.IsValid) return View("Index", model);
        model.DetectedLayers = transformations.DetectAndDecode(model.Input.Input);
        return View("Index", model);
    }
}
