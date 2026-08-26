# Gestión de secretos

Los secretos de AtlasForense nunca se almacenan en el repositorio ni en texto plano.

| Secreto | Almacenamiento | Protección |
|---|---|---|
| Claves de protección de datos (cookies, antiforgery) | `App_Data/Keys` | DPAPI en Windows (`ProtectKeysWithDpapi`); fuera de Windows, el proveedor de protección de datos del anfitrión |
| Clave maestra de cifrado de evidencia (`evidence-master.key`) | `App_Data/Keys` | Cifrada por el proveedor de protección de datos; los binarios de evidencia usan AES-256-GCM por trozos |
| Certificado de firma de paquetes forenses | Almacén de certificados de Windows | Se referencia solo por huella (`Signing:CertificateThumbprint`); la clave privada no sale del almacén |

## Configuración

`appsettings.json` solo contiene límites operativos. Cualquier valor sensible se inyecta por variables de entorno o configuración del anfitrión (`Signing__CertificateThumbprint`, etc.), nunca en el archivo versionado.

## Rotación

1. **Claves de protección de datos**: añadir una clave nueva al anillo (Data Protection lo hace automáticamente); las cookies antiguas caducan por política (30 min, sin deslizamiento).
2. **Clave maestra de evidencia**: rotar requiere re-cifrar la evidencia existente; procedimiento soportado: descifrar con la clave vigente y re-cifrar con la nueva dentro de la misma ventana de custodia, registrando el evento en la cadena de custodia.
3. **Certificado de firma**: emitir certificado nuevo, actualizar la huella y verificar con `AtlasForense.Verifier` un paquete de prueba. Los paquetes antiguos siguen verificándose con el certificado incluido en cada paquete.

## Custodia en respaldos

`App_Data/Keys` debe respaldarse junto con la base y la evidencia (ver `RECOVERY.md`). Sin la clave maestra, la evidencia cifrada es irrecuperable; sin el anillo de claves, las sesiones y tokens no pueden validarse tras la restauración.
