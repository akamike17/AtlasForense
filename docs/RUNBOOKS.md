# Runbooks de operación

## Arranque y verificación diaria

1. Iniciar la aplicación (`dotnet AtlasForense.dll`).
2. `GET /healthz` debe responder 200 (anónimo a propósito, para orquestadores).
3. `GET /Metrics` (rol de auditoría) muestra expedientes, evidencia, ejecuciones de análisis y fallos; un crecimiento de `analysis.failures` exige investigación.
4. Los logs estructurados JSON (consola, UTC) se envían al colector del anfitrión; la aplicación no tiene colector propio: integrar con el sistema de alertas del despliegue (p. ej., regla sobre `INTEGRITY_FAILURE` o `STATIC_ANALYSIS_FAILED` en el log de auditoría).

## Respuesta ante INTEGRITY_FAILURE

1. Congelar el expediente: no ejecutar más análisis.
2. Comparar el SHA-256 almacenado contra el hash del archivo descifrado (`ATLEV1` en `App_Data/Evidence/<caso>/<hash-guid>`).
3. Si el sobre no se descifra o el hash difiere: restaurar evidencia desde el respaldo firmado más reciente (ver `RECOVERY.md`) y documentar la desviación en la cadena de custodia.

## Respaldo programado

1. `dotnet AtlasForense.dll --data-backup` (verifica y muestra SHA-256).
2. Copiar `App_Data/Evidence`, `App_Data/Keys` y el `.db` de respaldo a almacenamiento protegido; registrar el hash en el libro de respaldos.

## Restauración (ensayo o desastre)

Procedimiento completo y ensayo automatizado en `RECOVERY.md`. Resumen: detener instancias, devolver respaldo + evidencia + claves, `--data-restore <archivo>`, `--data-verify`, confirmar inventario.

## Verificación post-despliegue

Tras desplegar o actualizar, ejecutar la prueba de humo E2E (`scripts\e2e-smoke.ps1`): arranca la aplicación real en un sandbox temporal y verifica arranque, bootstrap con TOTP real, sesión autenticada, métricas, protección anónima y creación de la base + clave maestra de cifrado. El sandbox se destruye al terminar.

## DAST externo

El workflow `.github/workflows/dast.yml` publica la aplicación, la arranca contra `127.0.0.1:8080` y ejecuta un baseline de OWASP ZAP (manual, en cada push a master y semanalmente). La evidencia (`zap-report.json`, `zap-report.html`, log de la aplicación) queda archivada 90 días. Triaje: toda advertencia nueva se clasifica en el expediente de seguridad; las excepciones permanentes solo se aceptan en `.github/zap/rules.tsv` con justificación escrita. El escaneo cubre la superficie anónima; las rutas autenticadas están cubiertas por las sondas DAST automatizadas de la suite.

## Recuperación ante desastre (DR)

- Objetivo: restaurar la capacidad de análisis sobre el último respaldo válido; RPO = frecuencia de respaldo configurada, RTO = tiempo de re-despliegue del anfitrión.
- El despliegue es reproducible: `dotnet publish` + SBOM (`docs/sbom.json`) + manifiesto de release firmado (ver `RELEASE.md`); ningún estado vive fuera de `App_Data`.
- Tras un DR, ejecutar el ensayo de recuperación integral y adjuntar el resultado al expediente de continuidad.
