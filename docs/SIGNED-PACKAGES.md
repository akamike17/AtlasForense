# Paquetes forenses firmados

La exportación `.afpkg` contiene el informe aprobado, la evidencia original, un manifiesto JSON canónico, la firma, el certificado público y el identificador del algoritmo. No contiene la clave privada. Antes de escribir el paquete se vuelve a comprobar cada SHA-256; después de escribirlo se vuelve a leer cada entrada y se compara con el manifiesto.

## Activación de firma

Instale un certificado RSA o ECDSA con uso de firma y clave privada en el almacén de certificados de la cuenta que ejecuta AtlasForense. Configure sólo su huella pública:

```json
{
  "Signing": {
    "CertificateThumbprint": "HUELLA_SHA1_DEL_CERTIFICADO",
    "StoreLocation": "CurrentUser"
  }
}
```

No exporte el PFX al directorio de la aplicación y no almacene su contraseña en configuración. La cuenta del servicio necesita permiso de lectura sobre la clave privada. Sin certificado válido, AtlasForense bloquea la exportación firmada y mantiene disponibles los informes sin afirmar que están firmados.

## Verificación independiente

Publique el verificador junto con la liberación:

```powershell
dotnet publish AtlasForense.Verifier/AtlasForense.Verifier.csproj -c Release -r win-x64 --self-contained false
AtlasForense.Verifier.exe expediente.afpkg certificado-confiable.cer
```

El segundo argumento fija la confianza a un certificado obtenido por un canal independiente. Sin él, el verificador comprueba integridad y firma, e imprime SHA-256 del certificado para comparación manual. Devuelve código 0 únicamente cuando firma, rutas, tamaños y hashes son válidos; rechaza algoritmos desconocidos, rutas inseguras, entradas duplicadas, contenido no declarado y sustitución del certificado confiable.
