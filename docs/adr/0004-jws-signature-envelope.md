# ADR-0004 — Envelope de firma JWS para objetos XCIM

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-004

## Contexto

El draft XCIM exige Ed25519, JSON Canonicalization Scheme y un envelope compatible con JWS, pero su ejemplo conceptual muestra `protected` y `payload` como objetos JSON. Sin una serialización exacta, implementaciones distintas pueden firmar bytes diferentes para el mismo objeto lógico.

## Decisión

XCIM v0.1 y Emabled usarán JWS Flattened JSON Serialization:

```json
{
  "protected": "<base64url(JCS(protected-header))>",
  "payload": "<base64url(JCS(payload))>",
  "signature": "<base64url(ed25519-signature)>"
}
```

### Bytes protegidos

El objeto protected header se serializa con JCS y UTF-8. Debe contener:

```json
{
  "alg": "EdDSA",
  "kid": "<key-id>",
  "typ": "<xcim-media-type>"
}
```

Puede contener `crit` y extensiones protegidas registradas. XCIM v0.1 no permite unprotected headers. `alg`, `kid`, `typ` y cualquier campo crítico nunca pueden quedar fuera del header protegido.

### Payload

El objeto XCIM se canonicaliza mediante JCS, se codifica como UTF-8 y luego como base64url sin padding. El payload transportado no es un objeto JSON directo sino el string codificado exigido por JWS.

### Signing input

El signing input es exactamente:

```text
ASCII(BASE64URL(JCS(protected-header))) ||
"." ||
ASCII(BASE64URL(JCS(payload)))
```

Ed25519/PureEdDSA firma directamente esos bytes. La aplicación no aplica SHA-256 al signing input antes de invocar Ed25519.

### Commitments del protocolo

Los hashes de receipt, manifest, event u otros objetos se calculan separadamente. Su forma general es:

```text
SHA-256(domain_separator || JCS(payload))
```

El commitment no se calcula sobre la representación externa completa del JWS, para que orden o whitespace del envelope exterior no cambien la identidad del payload firmado.

### Validación

Un verificador debe:

1. exigir exactamente los miembros `protected`, `payload` y `signature` salvo extensiones exteriores explícitamente registradas;
2. rechazar padding, base64url inválido o miembros duplicados;
3. decodificar y validar el protected header;
4. exigir `alg=EdDSA`, `kid` y `typ` compatibles con el objeto;
5. rechazar algoritmos o extensiones críticas desconocidas;
6. verificar Ed25519 sobre el signing input exacto;
7. decodificar el payload y confirmar que sus bytes ya están en forma JCS canónica;
8. validar schema, versión y semántica del objeto.

## Alternativas consideradas

### Envelope conceptual con objetos JSON directos

Se rechazó porque no define un signing input JWS interoperable y obliga a inventar reglas adicionales.

### JWS con `b64=false`

Se rechazó para v0.1 porque aumenta complejidad y diferencias de soporte sin aportar una ventaja material para los tamaños previstos.

### Prehash SHA-256 antes de Ed25519

Se rechazó porque cambiaría el algoritmo efectivo y no coincide con Ed25519/PureEdDSA ni con el signing input estándar elegido.

## Consecuencias

- Los ejemplos conceptuales del draft deberán reemplazar objetos directos por strings base64url.
- KMS/signers deben aceptar los bytes crudos del signing input.
- La canonicalización JCS se ejecuta antes de la codificación base64url.
- El envelope exterior puede serializarse con cualquier whitespace/orden permitido sin alterar la firma, pero Emabled emitirá una representación determinista.
- Cada `typ` XCIM debe quedar registrado y cubierto por test vectors.

## Evidencia y pruebas requeridas

- Vectores con protected bytes, payload bytes, segmentos base64url, signing input y firma.
- Verificación cruzada en C# y una segunda implementación independiente.
- Rechazo de padding, algoritmo distinto, `kid` inexistente, `typ` incorrecto y header sin proteger.
- Rechazo de payload JSON semánticamente equivalente pero no canonicalizado.
- Prueba con Cloud KMS `EC_SIGN_ED25519` usando el signing input completo.

## Relación con XCIM

Fija de manera interoperable las secciones 11.1, 11.3, 11.4 y 21.6 del protocolo.
