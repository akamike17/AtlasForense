using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AtlasForense.Services;

public sealed record SandboxRequest(string ExecutablePath, string Arguments, TimeSpan TimeLimit, long MaxMemoryBytes, TimeSpan MaxCpuTime, string? WorkingDirectory = null);
public sealed record SandboxResult(bool Completed, bool TimedOut, bool LimitExceeded, int ExitCode, string StandardOutput, string StandardError, long PeakMemoryBytes, TimeSpan Duration, string IsolationNotes);

public interface IIsolatedProcessSandbox
{
    bool IsSupported { get; }
    Task<SandboxResult> ExecuteAsync(SandboxRequest request, CancellationToken token);
}

// Base de análisis dinámico aislado: el proceso corre dentro de un Job Object de
// Windows con muerte al cerrar el job, límite de memoria confirmada, límite de
// procesos activos (impide hijos), límite de tiempo de CPU y límite de pared por
// temporizador. La red NO queda garantizada por el job: el aislamiento de red debe
// aplicarse en el anfitrión (firewall/perfil sin red) y así se documenta en el resultado.
public sealed class IsolatedProcessSandbox : IIsolatedProcessSandbox, IDisposable
{
    private const int OutputCap = 64 * 1024;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint LimitKillOnJobClose = 0x2000;
    private const uint LimitProcessMemory = 0x0100;
    private const uint LimitActiveProcess = 0x0008;
    private const uint LimitJobTime = 0x0004;

    public bool IsSupported => OperatingSystem.IsWindows() && Environment.Is64BitOperatingSystem;

    public async Task<SandboxResult> ExecuteAsync(SandboxRequest request, CancellationToken token)
    {
        if (!IsSupported) return new(false, false, false, -1, string.Empty, "Sandbox no soportado en esta plataforma.", 0, TimeSpan.Zero, "Se requiere Windows de 64 bits.");
        var executable = ResolveExecutable(request.ExecutablePath);
        if (executable is null) return new(false, false, false, -1, string.Empty, "Ejecutable no encontrado.", 0, TimeSpan.Zero, string.Empty);

        var start = DateTimeOffset.UtcNow;
        using var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) return new(false, false, false, -1, string.Empty, $"No se pudo crear el job aislado (error {Marshal.GetLastWin32Error()}).", 0, TimeSpan.Zero, string.Empty);

        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limits.BasicLimitInformation.LimitFlags = LimitKillOnJobClose | LimitProcessMemory | LimitActiveProcess | LimitJobTime;
        limits.ProcessMemoryLimit = new UIntPtr((ulong)Math.Max(1, request.MaxMemoryBytes));
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.BasicLimitInformation.PerJobUserTimeLimit = Math.Max(1, request.MaxCpuTime.Ticks);
        var size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, size))
            return new(false, false, false, -1, string.Empty, $"No se pudieron aplicar los límites del job (error {Marshal.GetLastWin32Error()}).", 0, TimeSpan.Zero, string.Empty);

        var info = new ProcessStartInfo
        {
            FileName = executable, Arguments = request.Arguments, UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, ErrorDialog = false,
            WorkingDirectory = string.IsNullOrWhiteSpace(request.WorkingDirectory) ? Path.GetTempPath() : request.WorkingDirectory
        };
        using var process = new Process { StartInfo = info };
        var stdout = new LimitedWriter(OutputCap);
        var stderr = new LimitedWriter(OutputCap);
        process.OutputDataReceived += (_, e) => stdout.Append(e.Data);
        process.ErrorDataReceived += (_, e) => stderr.Append(e.Data);

        var timedOut = false;
        var limitExceeded = false;
        try
        {
            if (!process.Start()) return new(false, false, false, -1, string.Empty, "No se pudo iniciar el proceso aislado.", 0, TimeSpan.Zero, string.Empty);
            if (!AssignProcessToJobObject(job, process.Handle))
            {
                try { process.Kill(true); } catch { }
                return new(false, false, false, -1, string.Empty, $"El proceso no pudo asignarse al job aislado (error {Marshal.GetLastWin32Error()}).", 0, TimeSpan.Zero, string.Empty);
            }
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var wall = CancellationTokenSource.CreateLinkedTokenSource(token);
            wall.CancelAfter(request.TimeLimit);
            try { await process.WaitForExitAsync(wall.Token); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                timedOut = true;
                TerminateJobObject(job, 1);
                try { process.Kill(true); } catch { }
            }

            if (!timedOut && process.ExitCode != 0) limitExceeded = process.ExitCode < 0 || process.ExitCode == 1;
            var peak = GetPeakJobMemory(job);
            return new(!timedOut, timedOut, limitExceeded, timedOut ? -1 : process.ExitCode, stdout.Value, stderr.Value, peak, DateTimeOffset.UtcNow - start,
                "Job Object con límites de memoria/procesos/CPU y muerte al cerrar; el aislamiento de red depende del anfitrión.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            return new(false, timedOut, limitExceeded, -1, stdout.Value, stderr.Value, 0, DateTimeOffset.UtcNow - start, $"Fallo de infraestructura: {exception.Message}");
        }
    }

    private static long GetPeakJobMemory(SafeFileHandle job)
    {
        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        return QueryInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(), out _) ? (long)limits.PeakJobMemoryUsed : 0;
    }

    private static string? ResolveExecutable(string candidate)
    {
        if (Path.IsPathRooted(candidate)) return File.Exists(candidate) ? candidate : null;
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator))
        {
            try
            {
                var full = Path.Combine(directory.Trim(), candidate);
                if (File.Exists(full)) return full;
            }
            catch (ArgumentException) { }
        }
        return null;
    }

    private sealed class LimitedWriter(int cap)
    {
        private readonly System.Text.StringBuilder _builder = new();
        private readonly object _gate = new();
        public void Append(string? line)
        {
            if (line is null) return;
            lock (_gate) { if (_builder.Length < cap) _builder.AppendLine(line.Length > cap ? line[..cap] : line); }
        }
        public string Value { get { lock (_gate) return _builder.ToString(); } }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle hJob, int jobObjectInformationClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation, int cbJobObjectInformationLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle hJob, int jobObjectInformationClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation, int cbJobObjectInformationLength, out int lpReturnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle hJob, IntPtr hProcess);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeFileHandle hJob, uint uExitCode);

    public void Dispose() { }
}
