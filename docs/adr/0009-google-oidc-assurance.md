# ADR-0009 — Assurance del adapter Google OIDC

**Estado:** superseded by ADR-0016  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-009

## Contexto

Google puede autenticar cuentas Gmail, cuentas administradas por Google Workspace y Google Accounts creadas con una dirección externa. `email_verified=true` no significa por sí solo que Google continúe siendo autoridad del buzón externo. Google indica usar `hd` para identificar cuentas Workspace y no inferirlo desde el suffix del email.

## Decisión

El primer perfil se identifica como:

```text
adapter_version = google-oidc-0.1
```

### Matriz de assurance

| Condición validada | Clasificación |
|---|---|
| `email_verified=true`, dominio canónico `gmail.com` | `idp_authoritative_mailbox` |
| `email_verified=true`, claim `hd` presente y válido | `enterprise_federated` |
| `email_verified=true`, sin `hd`, dominio distinto de `gmail.com` | `idp_verified_external` |
| `email_verified=false`, ausente o email ausente | Rechazar |

La presencia de un suffix corporativo en `email` no sustituye `hd`. El valor `hd` se toma del ID token firmado, no del parámetro hint enviado en la authorization request.

### Validación previa obligatoria

Antes de clasificar, el adapter valida:

- firma con JWKS obtenido mediante discovery y cacheado según metadata HTTP;
- `iss` dentro del allowlist del perfil;
- `aud` contra el client ID vinculado;
- `azp` cuando corresponda;
- `exp`, `iat`, clock skew y `auth_time` cuando la policy lo requiera;
- nonce exacto de la sesión;
- `sub` presente;
- replay de token/aserción;
- `email` parseable con `xcim-email-0.1`;
- `email_verified=true`.

### Identidad y comparación

- `sub` se transforma en un provider-subject commitment con HMAC y sirve como identidad estable del proveedor.
- El email continúa siendo la dirección de entrega y puede cambiar; no reemplaza `sub` como identidad de cuenta.
- Gmail y Workspace pueden usar comparison key case-insensitive.
- v0.1 no elimina puntos ni `+tags`.
- Un mismatch exige que el usuario cambie explícitamente la dirección de entrega o complete otro método aceptado.

### Uso de assurance menor

`idp_verified_external` fue la denominación inicial para una dirección externa verificada. ADR-0016 la reemplaza por `provider_verified`; si la provider policy no la acepta, el resultado es `unsupported_identity` y no se emite receipt.

## Alternativas consideradas

### Tratar todo `email_verified=true` como autoritativo

Se rechazó porque Google documenta que una dirección externa pudo cambiar de propietario después de crear la Google Account.

### Inferir Workspace desde el dominio del email

Se rechazó porque Google exige consultar `hd` para determinar pertenencia a una organización alojada.

### Normalizar puntos y `+tags` de Gmail

Se difirió porque amplía las reglas de alias y requiere vectores específicos. El usuario puede autorizar la dirección exacta afirmada en v0.1.

## Consecuencias

- Receipts y evidencia privada registran adapter version y assurance resultante.
- Cambios futuros de política crean otra versión y no reinterpretan receipts existentes.
- Policies de ESP/receiver deben poder distinguir las tres clases aceptadas.
- Google no define por analogía el comportamiento de Microsoft, Apple o generic OIDC.

## Evidencia y pruebas requeridas

- Gmail verificado, Workspace con `hd`, cuenta externa verificada y email no verificado.
- Rechazo de `hd` tomado solo del request y ausencia en token.
- Wrong audience, nonce, issuer, key, expiry y replay.
- Case-insensitive comparison únicamente en clases autorizadas.
- Receipt conserva adapter version y assurance exactos.

## Relación con XCIM

Fija las secciones 18.7, 19.1 y 9.1 para el adapter Google inicial.
