# Identidad y control de acceso

AtlasForense usa cuentas locales almacenadas en SQLite, contraseñas derivadas con `PasswordHasher`, MFA TOTP obligatorio, códigos de recuperación de un solo uso, bloqueo después de cinco fallos y cookies `__Host-` seguras sin persistencia. Los secretos TOTP y las claves de cookies se protegen mediante ASP.NET Core Data Protection; en Windows las claves persistidas en `App_Data/Keys` se cifran con DPAPI para la cuenta que ejecuta el servicio.

## Configuración inicial

En una instalación sin usuarios, abra `/Account/Setup`. La aplicación genera un secreto TOTP efímero protegido y exige comprobarlo antes de crear al primer administrador. No existe contraseña predeterminada ni secreto de configuración en archivos. Guarde los códigos de recuperación mostrados una sola vez fuera del servidor.

La cuenta del servicio de Windows debe conservar acceso a `App_Data/Keys` después de actualizaciones y restauraciones. No copie estas claves a otra identidad de Windows sin un procedimiento explícito de migración; DPAPI impedirá descifrarlas.

## Roles y separación

- `Administrator`: administra usuarios y asignaciones; tiene acceso de emergencia a expedientes.
- `Examiner`: adquiere, examina, analiza y prepara informes sólo en expedientes asignados.
- `Reviewer`: revisa y cierra sólo expedientes asignados; no puede promoverse desde examinador del mismo expediente.
- `Custodian`: registra custodia sólo en expedientes asignados.
- `Auditor`: acceso de lectura sólo a expedientes asignados.

Cada operación combina el rol global con una asignación activa por expediente y deniega por defecto. Los campos de actor no se aceptan del navegador: controladores y auditoría derivan usuario e identificador de la cookie autenticada. Una cuenta deshabilitada, una contraseña cambiada o una revocación renueva el sello de seguridad e invalida cookies anteriores.

## Operación

Las cuentas nuevas reciben una contraseña temporal y un secreto TOTP por entrega única; deben transmitirse por canales distintos. El primer acceso se limita al cambio de contraseña con reautenticación MFA. Los eventos de acceso se escriben en `SecurityEvents`, separado de la cadena forense y sin contraseñas, códigos, cookies ni secretos.
