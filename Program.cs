using AtlasForense.Services;
using AtlasForense.Forensics;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews(options => options.MaxModelValidationErrors = 100);
builder.Services.AddSingleton<IForensicCaseService, JsonForensicCaseService>();
builder.Services.AddSingleton<IForensicReportBuilder, MarkdownForensicReportBuilder>();
builder.Services.AddSingleton<IContentTransformationService, ContentTransformationService>();
builder.Services.AddSingleton<IForensicAnalyzer, StaticTextAnalyzer>();
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 104_857_600);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
