# Preparación para producción de AtlasForense

Esta matriz es una puerta de liberación, no una estimación comercial. Un rubro cuenta como completo únicamente cuando existe implementación, prueba observable y procedimiento operativo.

| Área | Peso | Estado actual | Criterio para completar |
|---|---:|---:|---|
| Flujo forense y reglas de negocio | 15 | 15 | Cuatro etapas, autorización, custodia, hallazgos, revisión independiente, cierre, reapertura controlada y RBAC por expediente implementados. |
| Integridad y reproducibilidad | 15 | 15 | SHA-256, auditoría encadenada, historial reproducible, deduplicación determinista, paquete firmado y verificador independiente implementados. |
| Motores de análisis | 20 | 20 | Texto/scripts, IOC, SQLite, historial web, ZIP, PE/Authenticode, PCAP/PCAPNG, Shell Link con rutas, argumentos y FILETIME, ELF con segmentos/secciones/dinámico, PDF con acciones/actualizaciones incrementales, Office OOXML/OLE con macros y relaciones externas, EVTX conforme a especificación y validado contra exportaciones reales (v3.1/v3.2), Prefetch con ejecuciones y archivos referenciados (detección explícita del contenedor comprimido MAM), colmenas de registro regf con claves/valores y heurísticas de web shell (PHP/ASP/JSP); falta sandbox dinámico. |
| Seguridad de aplicación | 15 | 12 | Antiforgery, límites, CSP, rate limiting, MFA TOTP, RBAC, bloqueo e invalidación de sesiones; faltan gestión empresarial de secretos, cifrado de datos en reposo y pruebas DAST independientes. |
| Persistencia y continuidad | 10 | 8 | SQLite transaccional, migraciones, verificación, respaldo consistente y restauración segura; faltan retención automatizada y ensayo documentado de recuperación integral con evidencia. |
| Calidad y validación forense | 10 | 7 | Vectores conocidos, round-trip, manipulación, CI, exportación STIX 2.1 con semántica de confianza revisada, corpus real (EVTX exportado, colmena reg save, Prefetch, PE de toolchain) y batería adversarial de truncamiento/bytes aleatorios/ciclos/XXE sobre todos los parsers; faltan corpus CFReDS, pruebas cruzadas con herramientas independientes y protocolo formal de validación. |
| Operación y observabilidad | 10 | 4 | Health check, auditoría de dependencias, cobertura archivada, CI y logs estructurados JSON con marcas UTC; faltan métricas, alertas, runbooks, DR y pruebas de carga. |
| UX, accesibilidad y entrega | 5 | 3 | Flujo responsivo, panel de inteligencia, exploración acotada e informe imprimible; faltan evaluación WCAG, instalación endurecida y firma de releases. |
| **Total verificable** | **100** | **84** | **Prototipo avanzado de laboratorio; no declarar producción hasta validar sandbox, recuperación integral, cifrado, carga, accesibilidad y corpus externos.** |

## Puertas obligatorias para 99/100

1. Cifrado administrado de base y evidencia, respaldo automático y restauración integral ensayada.
2. Sandbox desechable sin red por defecto, límites de CPU/memoria/tiempo y telemetría completa para cualquier análisis dinámico futuro.
3. Analizadores especializados validados contra corpus públicos conocidos y resultados cruzados con herramientas independientes.
4. Pruebas de carga, DAST, accesibilidad, recuperación y actualización.
5. Despliegue reproducible, SBOM, releases firmadas y procedimientos operativos.

## Regla de liberación

La aplicación puede usarse actualmente como prototipo de laboratorio con evidencia controlada. La etiqueta `production-ready` solo puede aplicarse cuando la puntuación verificable sea al menos 99, no existan bloqueadores críticos y una ejecución completa de la matriz quede archivada.
