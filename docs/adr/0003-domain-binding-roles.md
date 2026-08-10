# ADR-0003 — Roles normativos de domain binding

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-003

## Contexto

El protocolo XCIM define nombres explícitos para los roles autorizados de un dominio. El blueprint histórico también utiliza abreviaciones como `from`, `dkim`, `envelope` y `link`.

Las abreviaciones son ambiguas: `from` no distingue el header visible RFC 5322 del envelope sender SMTP, y `link` no expresa que se trata de dominios usados en URLs del mensaje.

## Decisión

XCIM v0.1 y Emabled usarán exclusivamente los siguientes valores normativos:

```text
organizational
rfc5322_from
dkim_signing
envelope_from
link_domain
consent_presentation_delegate
```

Un domain binding puede autorizar uno o varios roles. Estos valores se usarán sin traducción en:

- objetos firmados y transparency events;
- JSON Schemas y OpenAPI;
- APIs y SDKs;
- almacenamiento persistente;
- registry público;
- proof bundles y verifier.

La UI puede mostrar etiquetas localizadas, pero debe mapearlas internamente a estos valores. Las abreviaciones no se serializarán ni se aceptarán como aliases v0.1.

## Alternativas consideradas

### Adoptar los nombres abreviados

Se rechazó por ambigüedad semántica y contradicción con la especificación normativa.

### Aceptar nombres completos y abreviados

Se rechazó porque no existe compatibilidad histórica que preservar y permitiría objetos equivalentes con bytes canónicos diferentes.

## Consecuencias

- El modelo puede representar varios roles por binding sin crear identidades de dominio independientes.
- Los fixtures históricos del blueprint deben actualizarse al importarse o normalizarse.
- Valores desconocidos se rechazarán cuando afecten semántica crítica; futuras extensiones usarán el mecanismo de versionado/critical extensions.

## Evidencia y pruebas requeridas

- Round-trip de todos los valores normativos.
- Rechazo de `from`, `dkim`, `envelope` y `link` en objetos v0.1.
- Verificación independiente de bindings multirol.
- Fallo `XCIM_DOMAIN_NOT_BOUND` cuando el dominio está ligado a la aplicación pero carece del rol exigido.
- UI localizada que persiste siempre el valor normativo.

## Relación con XCIM

Implementa la sección 15.2 y permite que el paso 7 del algoritmo de verificación distinga correctamente RFC5322.From, DKIM y envelope sender.
