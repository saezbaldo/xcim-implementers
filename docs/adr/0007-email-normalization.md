# ADR-0007 — Parsing, canonicalización y comparación de email

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-007

## Contexto

XCIM debe vincular consentimiento a una dirección de entrega sin aplicar transformaciones universales que puedan unir buzones distintos. Aunque la mayoría de proveedores modernos ignoran el case del local part, SMTP permite que el servidor receptor lo trate como case-sensitive. Las reglas sobre puntos, `+tags` y aliases también varían por proveedor.

Al mismo tiempo, preservar únicamente la forma exacta produce falsos negativos prácticos al comparar datos de Gmail, Microsoft y otros proveedores conocidos.

## Decisión

XCIM v0.1 define el perfil `xcim-email-0.1` y separa tres representaciones.

### Dirección original

`original_address` conserva, cifrada y con acceso restringido, la dirección ingresada o afirmada. Se usa para auditoría y presentación cuando corresponde, no como índice público.

### Dirección canónica protocolaria

`canonical_address` se produce así:

1. aceptar una única dirección `addr-spec`, sin display name, comentarios ni angle brackets;
2. recortar únicamente SPACE y HTAB en los extremos;
3. rechazar controles, CR/LF y whitespace interno;
4. aceptar inicialmente local parts ASCII dot-atom;
5. rechazar punto inicial/final y puntos consecutivos;
6. preservar exactamente case, puntos y `+tags` del local part;
7. procesar el dominio con UTS #46 non-transitional, reglas STD3 y versión de implementación fijada;
8. convertir el dominio a A-label ASCII y minúsculas;
9. rechazar domain literals, underscores, trailing dot, labels o longitudes inválidas.

Resultado:

```text
exact-local-part@lowercase-idna-domain
```

Quoted local parts y SMTPUTF8 quedan fuera de `xcim-email-0.1` y requieren futuros perfiles versionados.

### Comparison key

`comparison_key` se usa para matching autorizado, deduplicación e índices privados. No aparece en objetos públicos.

Por defecto:

```text
comparison_key = canonical_address
```

Un identity-provider adapter puede aplicar una regla distinta únicamente cuando:

- el proveedor garantiza la equivalencia para esa clase concreta de cuenta/dominio;
- la regla tiene ID y versión explícitos;
- se conserva la canonical address original;
- la receipt evidencia qué adapter y regla permitieron el match;
- la regla no se reutiliza para otros proveedores.

Ejemplo permitido para un proveedor que garantiza case-insensitivity:

```text
comparison_key = lowercase(local_part) + "@" + lowercase(domain)
```

Quitar puntos, eliminar `+tags` o convertir aliases requiere otra regla específica y no forma parte del perfil universal.

### Pairwise identifiers

El pairwise recipient ID se deriva de la dirección de entrega canónica finalmente autorizada, no de una alias key genérica. Si una regla del proveedor permite vincular una identidad a otra forma de entrega, el receipt conserva el target canónico exacto y la metadata privada de comparación.

## Alternativas consideradas

### Lowercase universal de toda la dirección

Se rechazó como regla protocolaria porque puede fusionar buzones en servidores que distinguen case.

### Comparación exacta exclusivamente

Se rechazó como única estrategia operativa porque genera falsos negativos evitables con proveedores que garantizan equivalencias.

### Normalizar puntos y `+tags` universalmente

Se rechazó porque esas reglas no son comunes a todos los dominios y podrían autorizar otra dirección.

## Consecuencias

- El schema distingue original cifrado, canonical address y comparison metadata.
- Cada adapter publica y versiona sus reglas de comparación.
- Cambiar una regla no reinterpreta receipts históricos; estos conservan adapter y versión.
- UI y búsquedas pueden mostrar una forma normalizada sin modificar la evidencia firmada.
- Los índices usan HMAC/pairwise identifiers; no se publican emails ni hashes sin clave.

## Evidencia y pruebas requeridas

- Case preservado en canonical address y dominio siempre lowercase A-label.
- Rechazo de comentarios, múltiples direcciones, CRLF, local parts inválidos y domain literals.
- Vectores IDNA válidos e inválidos con librería/Unicode fijados.
- Match case-insensitive permitido para adapter conocido y rechazado para proveedor desconocido.
- Puntos y `+tags` no modificados por el perfil universal.
- Receipt vinculado a la dirección de entrega exacta aun cuando intervino una comparison key.

## Relación con XCIM

Fija las secciones 19.2, 19.3, 22.1 y 33.2 del protocolo y prepara la clasificación específica de proveedor de D-009.
