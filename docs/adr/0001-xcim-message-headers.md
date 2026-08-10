# ADR-0001 — Headers de presentación XCIM por mensaje

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-001

## Contexto

`XCIM Protocol.md`, documento normativo para comportamiento interoperable, define los headers provisionales:

```text
XCIM-Reference
XCIM-Proof
```

El blueprint histórico, hoy consolidado como `Emabled Implementation.md`, utilizaba en otra sección:

```text
XCIM-Receipt
XCIM-Status
```

Mantener ambos pares produciría parsers divergentes y confundiría el receipt core inmutable con la evidencia mutable de inclusión y estado.

## Decisión

XCIM v0.1 y Emabled usarán exclusivamente:

- `XCIM-Reference`: presentación compacta, firmada y específica del mensaje. Identifica receipt, issuer, aplicación, permiso, propósito, binding del destinatario, dominio esperado y referencia/frescura de proofs.
- `XCIM-Proof`: proof bundle opcional y stapled para verificación sin consulta directa a Emabled. Puede transportar recibo, inclusión, estado actual y anchor en un encoding versionado.

`XCIM-Receipt` y `XCIM-Status` no serán aliases aceptados ni emitidos en v0.1.

Todos los headers XCIM usados para validación deben añadirse antes de DKIM y quedar cubiertos por la lista `h=` de una firma DKIM válida.

## Alternativas consideradas

### Usar `XCIM-Receipt` y `XCIM-Status`

Se rechazó porque contradice el documento normativo y sugiere una separación distinta a la del modelo receipt/proof bundle.

### Aceptar los cuatro nombres

Se rechazó porque no existe compatibilidad histórica que preservar y aumentaría ambigüedad, superficie del parser y riesgo de campos conflictivos.

## Consecuencias

- Schemas, OpenAPI, SDKs, ejemplos, fixtures y parsers utilizarán el par normativo.
- Los test vectors deben incluir headers duplicados/conflictivos y nombres alternativos como casos no válidos o no reconocidos.
- El blueprint histórico deberá corregirse cuando sea importado al repositorio.
- Los nombres siguen siendo provisionales hasta su proceso formal de estandarización, pero dentro de XCIM v0.1 son únicos.

## Evidencia y pruebas requeridas

- Round-trip determinista de `XCIM-Reference`.
- Verificación reference-only y stapled.
- Rechazo de campos críticos duplicados o conflictivos.
- Confirmación de cobertura DKIM de ambos headers.
- Prueba de que un `XCIM-Proof` copiado a otro destinatario falla por recipient binding.

## Relación con XCIM

Implementa las secciones 28.2 a 28.6 y preserva la separación definida en la sección 26 entre receipt core y proof bundle.
