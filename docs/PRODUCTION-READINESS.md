# Preparación para producción de AtlasForense

Esta matriz es una puerta de liberación, no una estimación comercial. Un rubro cuenta como completo únicamente cuando existe implementación, prueba observable y procedimiento operativo.

| Área | Peso | Estado actual | Criterio para completar |
|---|---:|---:|---|
| Flujo forense y reglas de negocio | 15 | 11 | Cuatro etapas, autorización, custodia, hallazgos y cierre; faltan revisión/aprobación separadas y reapertura controlada. |
| Integridad y reproducibilidad | 15 | 12 | SHA-256, auditoría encadenada, manifiesto e historial de analizadores; falta firma con certificado y verificación externa del paquete. |
| Motores de análisis | 20 | 6 | Texto/scripts, IOC y capas codificadas; faltan Windows, navegador, SQLite, PE, red, archivos y sandbox dinámico. |
| Seguridad de aplicación | 15 | 6 | Antiforgery, almacenamiento fuera de web, límites, CSP y rate limiting; faltan identidad, MFA, RBAC, cifrado y gestión de secretos. |
| Persistencia y continuidad | 10 | 3 | Escritura serializada; faltan base transaccional, migraciones, respaldos, restauración probada y retención. |
| Calidad y validación forense | 10 | 6 | Vectores conocidos, round-trip, manipulación y CI; faltan corpus CFReDS, pruebas cruzadas y protocolo formal de validación. |
| Operación y observabilidad | 10 | 3 | Health check y CI; faltan métricas, alertas, logs estructurados, runbooks, DR y pruebas de carga. |
| UX, accesibilidad y entrega | 5 | 2 | Flujo web responsivo e informe; faltan evaluación WCAG, instalación endurecida, firma de releases y manuales. |
| **Total verificable** | **100** | **49** | **No liberar a clientes hasta cerrar los bloqueadores de identidad, persistencia, sandbox, firma y recuperación.** |

## Puertas obligatorias para 99/100

1. Identidad con MFA, roles por caso y separación entre perito, revisor y administrador.
2. Persistencia transaccional cifrada, respaldos automáticos y restauración ensayada.
3. Firma digital del expediente y verificador independiente.
4. Sandbox desechable sin red por defecto, límites de CPU/memoria/tiempo y telemetría completa.
5. Analizadores especializados con corpus conocido y resultados reproducibles.
6. Pruebas de carga, seguridad, accesibilidad, recuperación y actualización.
7. Despliegue reproducible, SBOM, releases firmadas y procedimientos operativos.

## Regla de liberación

La aplicación puede usarse actualmente como prototipo de laboratorio con evidencia controlada. La etiqueta `production-ready` solo puede aplicarse cuando la puntuación verificable sea al menos 99, no existan bloqueadores críticos y una ejecución completa de la matriz quede archivada.
