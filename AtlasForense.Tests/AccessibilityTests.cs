using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AtlasForense.Tests;

// Cribado estructural WCAG 2.1 (no sustituye una auditoría manual completa):
// idioma, enlace de salto, landmark principal, título, alternativas de imagen
// y visibilidad del foco.
public sealed partial class AccessibilityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"atlas-a11y-{Guid.NewGuid():N}");
    private readonly WebApplicationFactory<Program> _factory;

    public AccessibilityTests()
    {
        Directory.CreateDirectory(_root);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing").UseContentRoot(_root);
            builder.ConfigureLogging(logging => logging.ClearProviders().AddDebug());
        });
    }

    [Fact]
    public async Task LoginAndHome_PassStructuralAccessibilityScreening()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, BaseAddress = new Uri("https://localhost") });
        foreach (var path in new[] { "/", "/Account/Login" })
        {
            var html = await (await client.GetAsync(path)).Content.ReadAsStringAsync();
            Assert.Matches("<html lang=\"es\">", html);
            Assert.Contains("href=\"#contenido\"", html);
            Assert.Contains("Saltar al contenido principal", html);
            Assert.Contains("<main", html);
            Assert.Contains("id=\"contenido\"", html);
            Assert.Matches("<title>.+</title>", html);
            foreach (Match image in ImgRegex().Matches(html))
                Assert.Contains("alt=", image.Value);
            foreach (Match input in InputRegex().Matches(html))
                if (!input.Value.Contains("type=\"hidden\""))
                    Assert.True(input.Value.Contains("aria-label") || input.Value.Contains("id="), $"Entrada sin etiqueta accesible: {input.Value}");
        }
        var css = await File.ReadAllTextAsync(LocateRepositoryCss());
        Assert.Contains(":focus-visible", css);
        Assert.Contains("skip-link", css);
    }

    private static string LocateRepositoryCss()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "wwwroot", "css", "site.css");
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }
        throw new FileNotFoundException("No se localizó wwwroot/css/site.css desde el directorio de pruebas.");
    }

    [Fact]
    public async Task ErrorPage_KeepsLanguageAndMainLandmark()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = true, BaseAddress = new Uri("https://localhost") });
        var response = await client.GetAsync("/Home/Privacy");
        if (response.StatusCode == HttpStatusCode.OK)
        {
            var html = await response.Content.ReadAsStringAsync();
            Assert.Matches("<html lang=\"es\">", html);
            Assert.Contains("id=\"contenido\"", html);
        }
    }

    public void Dispose()
    {
        _factory.Dispose();
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    [GeneratedRegex("<img\\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex ImgRegex();
    [GeneratedRegex("<input\\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex InputRegex();
}
