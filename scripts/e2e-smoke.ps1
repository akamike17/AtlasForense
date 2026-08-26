param(
    [string]$DllPath = "",
    [int]$Port = 5199
)
# Prueba de humo E2E: arranca la aplicacion real en un sandbox temporal y recorre
# arranque -> bootstrap TOTP -> sesion autenticada -> metricas -> persistencia cifrada.
# Requiere PowerShell 5.1+ y el binario Release publicado (dotnet publish -c Release).
$ErrorActionPreference = 'Stop'
if (-not $DllPath) { $DllPath = Join-Path $PSScriptRoot "..\bin\Release\net8.0\AtlasForense.dll" }
$DllPath = (Resolve-Path $DllPath).Path
$sandbox = Join-Path ([Path]::GetTempPath()) "atlas-e2e-$(Get-Random)"
New-Item -ItemType Directory -Path $sandbox | Out-Null
$env:ASPNETCORE_URLS = "https://127.0.0.1:$Port"
$env:ASPNETCORE_ENVIRONMENT = "Production"
Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustAllCerts {
    public static void Enable() {
        System.Net.ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(TrustAllCerts.Validate);
        System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
    }
    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; }
}
"@
[TrustAllCerts]::Enable()
$proc = Start-Process -FilePath "dotnet" -ArgumentList "`"$DllPath`"" -WorkingDirectory $sandbox -PassThru -RedirectStandardOutput "$sandbox\app.log" -RedirectStandardError "$sandbox\err.log"
try {
    $base = "https://127.0.0.1:$Port"
    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Seconds 1
        try { $h = Invoke-WebRequest "$base/healthz" -UseBasicParsing -TimeoutSec 3; if ($h.StatusCode -eq 200) { $up = $true; break } } catch { }
    }
    if (-not $up) { throw "La aplicacion no arranco en el sandbox temporal. Ver $sandbox\err.log" }
    Write-Output "OK healthz 200"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $setup = Invoke-WebRequest "$base/Account/Setup" -WebSession $session -UseBasicParsing
    if ($setup.StatusCode -ne 200) { throw "Setup no respondio 200." }
    $token = [System.Net.WebUtility]::HtmlDecode(([regex]::Match($setup.Content, 'name="__RequestVerificationToken"[^>]*value="([^"]+)"').Groups[1].Value))
    $challenge = [System.Net.WebUtility]::HtmlDecode(([regex]::Match($setup.Content, 'name="Input.Challenge"[^>]*value="([^"]+)"').Groups[1].Value))
    $secret = [regex]::Match($setup.Content, '<code>([A-Z2-7]+)</code>').Groups[1].Value
    if (-not $token -or -not $challenge -or -not $secret) { throw "No se pudo extraer token/challenge/secreto de la pagina Setup." }
    Write-Output "OK pagina Setup con challenge y secreto TOTP"

    function Get-Totp([string]$s) {
        $b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        $bits = ""
        foreach ($c in $s.ToUpper().ToCharArray()) { $bits += [Convert]::ToString($b32.IndexOf($c), 2).PadLeft(5, '0') }
        $bytes = @()
        for ($i = 0; $i + 8 -le $bits.Length; $i += 8) { $bytes += [Convert]::ToByte($bits.Substring($i, 8), 2) }
        $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30
        $counter = [BitConverter]::GetBytes([long]$epoch)
        [Array]::Reverse($counter)
        $hmac = New-Object System.Security.Cryptography.HMACSHA1
        $hmac.Key = [byte[]]$bytes
        $h = $hmac.ComputeHash($counter)
        $offset = $h[$h.Length - 1] -band 0xf
        $code = (([int]$h[$offset] -band 0x7f) * 16777216) + ([int]$h[$offset + 1] * 65536) + ([int]$h[$offset + 2] * 256) + [int]$h[$offset + 3]
        return ($code % 1000000).ToString("D6")
    }

    $body = @{
        "__RequestVerificationToken" = $token
        "Input.UserName" = "admin"
        "Input.DisplayName" = "Administrador E2E"
        "Input.Password" = "E2E!Pass2026Smoke"
        "Input.ConfirmPassword" = "E2E!Pass2026Smoke"
        "Input.Challenge" = $challenge
        "Input.TotpCode" = (Get-Totp $secret)
    }
    $created = Invoke-WebRequest "$base/Account/Setup" -Method Post -Body $body -WebSession $session -UseBasicParsing
    if ($created.StatusCode -ne 200 -or $created.Content -notmatch "ecuperaci") { throw "El bootstrap no mostro los codigos de recuperacion (codigo $($created.StatusCode))." }
    Write-Output "OK bootstrap administrador con TOTP real y codigos de recuperacion"

    $cases = Invoke-WebRequest "$base/Cases" -WebSession $session -UseBasicParsing
    if ($cases.StatusCode -ne 200) { throw "La ruta autenticada /Cases devolvio $($cases.StatusCode)." }
    Write-Output "OK sesion autenticada con cookie cifrada"

    $metrics = Invoke-WebRequest "$base/Metrics" -WebSession $session -UseBasicParsing
    if ($metrics.StatusCode -ne 200 -or $metrics.Content -notmatch '"cases"') { throw "Metricas no operativas." }
    Write-Output "OK endpoint de metricas"

    $redirected = $false
    try { $null = Invoke-WebRequest "$base/Metrics" -UseBasicParsing -MaximumRedirection 0 } catch { $redirected = $true }
    if (-not $redirected) { throw "Metricas accesibles sin autenticacion." }
    Write-Output "OK metricas protegidas para anonimos"

    if (-not (Test-Path "$sandbox\App_Data\atlas-forense.db")) { throw "No se creo la base SQLite en el sandbox." }
    if (-not (Test-Path "$sandbox\App_Data\Keys\evidence-master.key")) { throw "No se creo la clave maestra de cifrado de evidencia." }
    Write-Output "OK persistencia y clave maestra en el sandbox"
    Write-Output "E2E COMPLETO SIN ERRORES"
}
finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path $sandbox) { Remove-Item $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
}
