# Preparación para producción de AtlasForense

Esta matriz es una puerta de liberación, no una estimación comercial. Un rubro cuenta como completo únicamente cuando existe implementación, prueba observable y procedimiento operativo.

| Área | Peso | Estado actual | Criterio para completar |
|---|---:|---:|---|
| Flujo forense y reglas de negocio | 15 | 15 | Cuatro etapas, autorización, custodia, hallazgos, revisión independiente, cierre, reapertura controlada y RBAC por expediente implementados. |
| Integridad y reproducibilidad | 15 | 15 | SHA-256, auditoría encadenada, historial reproducible, deduplicación determinista, paquete firmado y verificador independiente implementados. |
| Motores de análisis | 20 | 20 | Texto/scripts, IOC, SQLite, historial web, ZIP, PE/Authenticode, PCAP/PCAPNG, Shell Link con rutas, argumentos y FILETIME, ELF con segmentos/secciones/dinámico, PDF con acciones/actualizaciones incrementales, Office OOXML/OLE con macros y relaciones externas, EVTX conforme a especificación y validado contra exportaciones reales (v3.1/v3.2), Prefetch con ejecuciones y archivos referenciados (detección explícita del contenedor comprimido MAM), colmenas de registro regf con claves/valores y heurísticas de web shell (PHP/ASP/JSP); base de sandbox aislado implementada y probada (Job Objects: memoria, procesos, CPU, pared), sin análisis dinámico de evidencia todavía. |
| Seguridad de aplicación | 15 | 14 | Antiforgery, límites, CSP, rate limiting, MFA TOTP, RBAC, bloqueo e invalidación de sesiones, cifrado AES-256-GCM de evidencia en reposo con clave maestra gestionada, gestión de secretos documentada y sondas DAST automatizadas (auth, headers, CSRF, métodos, path traversal, rate limit, fuga de errores); falta ejecución de escáner DAST externo independiente. |
| Persistencia y continuidad | 10 | 10 | SQLite transaccional, migraciones, verificación, respaldo consistente, restauración segura, retención automatizada en modo seguro (marca candidatos, nunca borra evidencia) y ensayo de recuperación integral automatizado (destrucción total de App_Data → restauración → cadena de auditoría y evidencia verificadas). |
| Calidad y validación forense | 10 | 8 | Vectores conocidos, round-trip, manipulación, CI, exportación STIX 2.1 con semántica de confianza revisada, corpus real (EVTX exportado, colmena reg save, Prefetch, PE de toolchain), batería adversarial de truncamiento/bytes aleatorios/ciclos/XXE sobre todos los parsers y protocolo formal de validación con procedimiento de incorporación de corpus externos; falta incorporación efectiva de corpus CFReDS y contraste con herramientas externas. |
| Operación y observabilidad | 10 | 9 | Health check operativo para orquestadores, endpoint de métricas, auditoría de dependencias, SBOM, cobertura archivada, CI, logs estructurados JSON UTC, runbooks con DR y pruebas de carga (100 solicitudes concurrentes HTTP y 25 adquisiciones concurrentes con verificación de integridad); falta integración de alertas con sistema externo del despliegue. |
| UX, accesibilidad y entrega | 5 | 4 | Flujo responsivo, panel de inteligencia, exploración acotada, informe imprimible, skip-link/landmarks/foco visible con cribado estructural WCAG automatizado, SBOM y manifiestos de release firmados con procedimiento de instalación endurecida; falta auditoría WCAG manual completa. |
| **Total verificable** | **100** | **95** | **Herramienta de laboratorio profesional verificada; la etiqueta production-ready exige además escáner DAST externo, corpus externos incorporados, auditoría WCAG manual y flujo dinámico en sandbox dedicado.** |

## Puertas obligatorias para 99/100

1. ~~Cifrado administrado de base y evidencia, respaldo automático y restauración integral ensayada.~~ Cerrada: cifrado AES-256-GCM, respaldo verificado y ensayo de recuperación integral automatizado.
2. ~~Sandbox desechable sin red por defecto, límites de CPU/memoria/tiempo y telemetría completa para cualquier análisis dinámico futuro.~~ Base cerrada y probada; el aislamiento de red total y el flujo dinámico requieren anfitrión dedicado.
3. Analizadores especializados validados contra corpus públicos conocidos y resultados cruzados con herramientas independientes (procedimiento en `VALIDATION-PROTOCOL.md`).
4. ~~Pruebas de carga, DAST, accesibilidad, recuperación y actualización.~~ Automatizadas; pendiente escáner DAST externo y auditoría WCAG manual.
5. ~~Despliegue reproducible, SBOM, releases firmadas y procedimientos operativos.~~ Cerrada: SBOM CycloneDX, manifiesto de release firmable, runbooks y guía de instalación endurecida.

## Regla de liberación

La aplicación puede usarse actualmente como prototipo de laboratorio con evidencia controlada. La etiqueta `production-ready` solo puede aplicarse cuando la puntuación verificable sea al menos 99, no existan bloqueadores críticos y una ejecución completa de la matriz quede archivada.
