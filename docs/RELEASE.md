# Release firmado y despliegue endurecido

## Producción de un release

1. `dotnet publish AtlasForense.csproj -c Release -r <rid> --self-contained` hacia un directorio limpio.
2. Generar el SBOM del release (CycloneDX ya está en el manifiesto de herramientas):
   `dotnet tool restore && dotnet tool run dotnet-CycloneDX AtlasForense.slnx -o docs --output-format json --filename sbom.json`
3. Construir el manifiesto de release (`ReleaseManifestBuilder`): inventario ordenado con SHA-256 de cada archivo publicado.
4. Firmar el manifiesto canónico con CMS (el mismo mecanismo y certificado que los paquetes forenses) y adjuntar `signature.bin` + certificado público.
5. Verificación independiente: `AtlasForense.Verifier` valida firma y hashes del manifiesto antes de distribuir.

## Distribución

Cada entrega incluye: binarios, `sbom.json`, manifiesto firmado y certificado. El receptor recalcula hashes, verifica la firma contra el certificado publicado y compara la huella del certificado por un canal distinto.

## Instalación endurecida (anfitrión)

1. Ejecutar bajo cuenta dedicada sin privilegios administrativos; `App_Data` con ACL restringida al cuenta de servicio.
2. HTTPS obligatorio (la aplicación ya emite cookies `__Host-` con `Secure`, `HttpOnly`, `SameSite=Strict` y HSTS).
3. Firewall de anfitrión: denegar tráfico saliente no solicitado; el análisis forense de la aplicación no usa red (invariante `NetworkBlocked=true`).
4. Sistema de archivos con auditoría (SACL) sobre `App_Data/Evidence` y `App_Data/Keys`.
5. Límites de recursos del proceso (cuota de disco para evidencia, límite de memoria) acordes a `ForensicStorage:MaxEvidenceBytes` y `MaxArchiveExpandedBytes`.
6. Backups programados según `RUNBOOKS.md`; ensayo de recuperación integral al menos una vez por ciclo de auditoría.

## Sandbox de análisis dinámico

La base `IsolatedProcessSandbox` (Job Objects: memoria, procesos activos, CPU, tiempo de pared, muerte al cerrar) está implementada y probada, pero el análisis dinámico de evidencia está deliberadamente fuera del flujo por defecto. Habilitarlo exige: anfitrión dedicado sin red, política explícita y registro de cada detonación; el sandbox por sí solo no garantiza aislamiento de red (documentado en el resultado de cada ejecución).
