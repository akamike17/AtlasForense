using System.Diagnostics;
using AtlasForense.Services;
using Xunit;

namespace AtlasForense.Tests;

public sealed class IsolatedProcessSandboxTests
{
    private static readonly bool Windows = OperatingSystem.IsWindows();
    private readonly IsolatedProcessSandbox _sandbox = new();

    [Fact]
    public async Task Sandbox_CapturesOutputAndExitCodeWithoutExecutingEvidence()
    {
        if (!Windows) return;
        var result = await _sandbox.ExecuteAsync(new SandboxRequest("cmd.exe", "/c echo ATLAS_SANDBOX_OK", TimeSpan.FromSeconds(15), 256 * 1024 * 1024, TimeSpan.FromMinutes(1)), default);

        Assert.True(result.Completed, result.StandardError);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("ATLAS_SANDBOX_OK", result.StandardOutput);
        Assert.Contains("red", result.IsolationNotes);
    }

    [Fact]
    public async Task Sandbox_KillsProcessWhenWallClockLimitExpires()
    {
        if (!Windows) return;
        var stopwatch = Stopwatch.StartNew();
        var result = await _sandbox.ExecuteAsync(new SandboxRequest("ping.exe", "-n 25 127.0.0.1", TimeSpan.FromSeconds(1), 256 * 1024 * 1024, TimeSpan.FromMinutes(1)), default);
        stopwatch.Stop();

        Assert.True(result.TimedOut);
        Assert.False(result.Completed);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(15), $"El sandbox tardó {stopwatch.Elapsed} en matar el proceso.");
    }

    [Fact]
    public async Task Sandbox_ActiveProcessLimitPreventsChildren_DirectExecutionStillWorks()
    {
        if (!Windows) return;
        var direct = await _sandbox.ExecuteAsync(new SandboxRequest("ping.exe", "-n 1 127.0.0.1", TimeSpan.FromSeconds(20), 256 * 1024 * 1024, TimeSpan.FromMinutes(1)), default);
        Assert.True(direct.Completed, direct.StandardError);
        Assert.Equal(0, direct.ExitCode);

        var withChild = await _sandbox.ExecuteAsync(new SandboxRequest("cmd.exe", "/c ping -n 2 127.0.0.1", TimeSpan.FromSeconds(20), 256 * 1024 * 1024, TimeSpan.FromMinutes(1)), default);
        Assert.True(!withChild.Completed || withChild.ExitCode != 0, "El límite de procesos activos debe impedir el hijo.");
    }

    [Fact]
    public async Task Sandbox_MemoryLimitPreventsLargeAllocation()
    {
        if (!Windows) return;
        var result = await _sandbox.ExecuteAsync(new SandboxRequest("powershell.exe", "-NoProfile -Command \"$x = New-Object byte[] 300MB\"", TimeSpan.FromSeconds(30), 32 * 1024 * 1024, TimeSpan.FromMinutes(1)), default);

        Assert.True(!result.Completed || result.ExitCode != 0, "La asignación por encima del límite del job no debe prosperar.");
    }

    [Fact]
    public async Task Sandbox_RejectsMissingExecutableCleanly()
    {
        var result = await _sandbox.ExecuteAsync(new SandboxRequest(Path.Combine(Path.GetTempPath(), "no-existe-atlas.exe"), string.Empty, TimeSpan.FromSeconds(5), 1024, TimeSpan.FromSeconds(5)), default);

        Assert.False(result.Completed);
        Assert.Contains("no encontrado", result.StandardError, StringComparison.OrdinalIgnoreCase);
    }
}
