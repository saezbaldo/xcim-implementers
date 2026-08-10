# ADR-0002 — Resultado de estado indeterminado

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-002

## Contexto

El protocolo XCIM define `XCIM_STATUS_INDETERMINATE` para el caso en que un verificador no puede establecer con suficiente frescura si un permiso continúa activo. El blueprint histórico también utiliza `XCIM_INDETERMINATE`, un nombre más genérico.

Aceptar ambos produciría resultados equivalentes con nombres distintos y dificultaría políticas deterministas entre SDKs, resolvers y ESPs.

## Decisión

XCIM v0.1 y Emabled usarán exclusivamente:

```text
XCIM_STATUS_INDETERMINATE
```

Se devolverá cuando:

- el receipt y sus firmas puedan ser válidos;
- no exista prueba suficiente de revocación o fraude;
- el estado actual no pueda establecerse mediante resolver, proof reciente, mirror o fuente aceptada;
- no corresponda un resultado más específico como `XCIM_STATUS_STALE` o `XCIM_ANCHOR_UNAVAILABLE`.

El resultado es neutral. El receptor debe retirar cualquier señal positiva XCIM y continuar con su política ordinaria; no debe tratarlo como una falla criptográfica.

`XCIM_INDETERMINATE` no será emitido ni aceptado como alias v0.1.

## Alternativas consideradas

### Usar `XCIM_INDETERMINATE`

Se rechazó porque no identifica qué dimensión de la verificación es desconocida y colisiona conceptualmente con resultados específicos de issuer, anchor o parsing.

### Aceptar ambos códigos

Se rechazó porque no existe compatibilidad instalada que preservar y agregaría branching innecesario a políticas y telemetría.

## Consecuencias

- El enum compartido, OpenAPI, SDKs, resolver y métricas usarán un único código.
- Los ejemplos históricos que contengan `XCIM_INDETERMINATE` deberán corregirse al importar el blueprint.
- Las políticas deben distinguir estado indeterminado de `REVOKED`, `SIGNATURE_FAIL` y `STATUS_STALE`.

## Evidencia y pruebas requeridas

- API de issuer caída con proof fresco: puede producir `XCIM_PASS_CACHED`.
- API caída y proof fuera de frescura: produce `XCIM_STATUS_INDETERMINATE`.
- Firma inválida: nunca se degrada a indeterminado; produce `XCIM_SIGNATURE_FAIL`.
- Revocación válida: produce `XCIM_REVOKED`.
- Serialización consistente del resultado en C#, SDKs y CLI.

## Relación con XCIM

Implementa las secciones 30, 32 y 41 del protocolo y conserva la diferencia entre resultados neutrales y fallas negativas.

