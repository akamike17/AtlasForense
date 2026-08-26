# Protocolo formal de validación

## Niveles cubiertos por la suite automatizada

1. **Vectores conocidos**: fixtures sintéticas con valores esperados fijos (cabeceras PE/ELF, registros EVTX, celdas regf).
2. **Corpus real**: `AtlasForense.Tests/Corpus` contiene artefactos generados por escritores oficiales (wevtutil, reg save, toolchain .NET, kernel de Windows); los parsers se validan contra bytes que no definieron.
3. **Pruebas cruzadas internas**: los resultados se contrastan con rutas de código independientes (p. ej., integridad verificada por hashing sobre descifrado en streaming vs. descifrado a archivo; paquetes verificados por `AtlasForense.Verifier`, binario separado).
4. **Batería adversarial**: truncamiento byte a byte, magia + bytes aleatorios (9 parsers × 11 tamaños × 3 semillas), ciclos, desbordes y XXE; la invariante es que solo escapen `IOException`, `UnauthorizedAccessException` o `InvalidDataException`.

## Incorporación de corpus externos (CFReDS y equivalentes)

Procedimiento obligatorio para aceptar una muestra externa:

1. **Procedencia**: registrar fuente, fecha, licencia y hash SHA-256 de descarga en este documento antes de copiar nada.
2. **Cuarentena**: descargar fuera del repositorio; nunca ejecutar ni montar la muestra.
3. **Revisión**: confirmar que el contenido no incluye datos personales o credenciales reales; si es una imagen de disco, trabajar solo con particiones de prueba publicadas por el proveedor del corpus.
4. **Incorporación**: copiar a `AtlasForense.Tests/Corpus/External/<fuente>/` con un archivo `PROVENANCE.md` (URL, hash, licencia, fecha, responsable).
5. **Prueba**: cada muestra externa necesita un test que fije el resultado esperado (estructura, conteos, marcas de tiempo) y documente la herramienta independiente usada para contrastar.

Fuentes candidatas: CFReDS (NIST), corpus públicos de EVTX/Prefetch publicados por laboratorios forenses con licencia de redistribución. Mientras no exista una muestra incorporada por este procedimiento, la matriz de preparación no puede reclamar "corpus externos validados".

## Comparación con herramientas independientes

Para cada analizador estructural, el contraste mínimo aceptable es: abrir la misma muestra con una herramienta de referencia (p. ej., visor de eventos exportado, editor hexadecimal con la especificación citada) y comparar conteos de registros/claves/secciones y marcas de tiempo. Los resultados del contraste se archivan como evidencia de validación del release.
