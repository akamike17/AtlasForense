# Respaldo y recuperación

AtlasForense conserva los metadatos transaccionales en `App_Data/atlas-forense.db` y los binarios adquiridos en `App_Data/Evidence` (cifrados en reposo con AES-256-GCM). Ambos directorios deben respaldarse juntos desde el mismo punto de recuperación, **junto con `App_Data/Keys`**: sin la clave maestra de evidencia (`evidence-master.key`, protegida por DPAPI/DPAPI-equivalente del proveedor de protección de datos) los binarios respaldados son irrecuperables. Los respaldos internos de SQLite se escriben con nombres generados por la aplicación en `App_Data/Backups`; ninguna ruta enviada por el usuario se acepta.

## Verificación y respaldo

Con la aplicación detenida o antes de recibir tráfico:

```powershell
dotnet AtlasForense.dll --data-verify
dotnet AtlasForense.dll --data-backup
```

La verificación ejecuta `PRAGMA quick_check` y comprueba secuencia, enlace y hash de cada cadena de auditoría. El respaldo usa la API consistente de SQLite, vuelve a ejecutar la comprobación de integridad y muestra su SHA-256. Copie después el archivo `.db` indicado y `App_Data/Evidence` a almacenamiento protegido, cifrado y con acceso restringido.

## Restauración

1. Detenga todas las instancias de AtlasForense.
2. Coloque el respaldo de metadatos en `App_Data/Backups` y restaure el árbol de evidencia correspondiente sin cambiar nombres internos.
3. Ejecute:

```powershell
dotnet AtlasForense.dll --data-restore atlas-forense-AAAAMMDDTHHMMSSfffZ-identificador.db
dotnet AtlasForense.dll --data-verify
```

4. Compare el SHA-256 del respaldo con el registrado al crearlo.
5. Inicie la aplicación y confirme el inventario de expedientes y evidencia antes de habilitar tráfico.

La restauración valida primero la copia, la vuelca a un archivo temporal y sólo reemplaza la base activa cuando la operación termina. Un respaldo corrupto o un nombre con componentes de ruta se rechaza sin modificar la base activa. El archivo heredado `cases.json`, si existe, se importa de forma idempotente únicamente cuando la base está vacía y nunca se elimina ni reescribe.

## Ensayo de recuperación integral

La suite de pruebas ejecuta el ensayo completo de forma automatizada (`FullRecoveryDrill_DestroysDataDirectoryAndRestoresAuditChainAndEvidence`): crea un expediente con evidencia cifrada y análisis, respalda la base, copia el árbol de evidencia a una zona de preparación, **elimina por completo `App_Data`**, restaura respaldo y evidencia sobre un servicio nuevo y verifica: cadena de auditoría (hash cabeza idéntico), `PRAGMA quick_check`, y re-ejecución del análisis sobre la evidencia descifrada con hash coincidente. Para un ensayo operativo en producción, repita estos pasos contra una copia del entorno real y registre fecha, operador y hash del respaldo utilizado como evidencia del ejercicio.
