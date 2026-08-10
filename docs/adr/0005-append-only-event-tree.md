# ADR-0005 — Árbol acumulativo append-only de eventos

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-005

## Contexto

El draft define hashes de hojas y nodos, pero no fija la regla para cantidades impares de hojas, si el root es acumulativo o local al batch, ni el algoritmo de consistency proof. Esas omisiones impiden reproducir roots y demostrar que una versión nueva conserva íntegramente la historia anterior.

## Decisión

XCIM v0.1 y Emabled usarán un Merkle Tree Hash acumulativo basado en la estructura de RFC 6962, manteniendo los domain separators propios de XCIM.

### Hashes

```text
MTH([]) = SHA-256("XCIM-EVENT-EMPTY-0.1\0")

leaf_hash(event) = SHA-256(
    "XCIM-EVENT-LEAF-0.1\0" || JCS(event)
)

node_hash(left, right) = SHA-256(
    "XCIM-MERKLE-NODE-0.1\0" || left || right
)
```

Para una única hoja:

```text
MTH([event]) = leaf_hash(event)
```

Para `n > 1`, sea `k` la mayor potencia de dos estrictamente menor que `n`:

```text
MTH(events[0:n]) = node_hash(
    MTH(events[0:k]),
    MTH(events[k:n])
)
```

No se duplican hojas impares y no se promueve una hoja mediante una regla adicional. La descomposición anterior determina un único root para cualquier `tree_size`.

### Secuencia e índices

- `sequence_number` es global, monotónico y comienza en 1.
- `leaf_index = sequence_number - 1` y comienza en 0.
- Un event root cubre exactamente las hojas `[0, tree_size)`.
- Los commits asignan secuencia de forma transaccional y nunca reutilizan un número.

### Batches

Cada batch manifest incluye como mínimo:

- `tree_size`: total acumulado de eventos;
- `first_sequence` y `last_sequence` incorporadas por el batch;
- `batch_event_count`: eventos nuevos del batch;
- `event_root`: root acumulativo a `tree_size`;
- `previous_tree_size` y `previous_event_root`;
- `previous_anchor_hash`.

El campo ambiguo `event_count` debe reemplazarse o definirse explícitamente como `batch_event_count`; nunca se usará indistintamente para total acumulado y delta.

### Proofs

- Inclusion proof: `leaf_index`, `tree_size`, sibling path y `event_root`.
- Consistency proof: prueba tipo RFC 6962 entre `(old_tree_size, old_root)` y `(new_tree_size, new_root)`.
- `old_tree_size = 0` tiene una consistency proof vacía válida únicamente contra el empty root normativo.
- Un proof para tamaños o índices distintos no puede reutilizarse silenciosamente.
- El verificador no confía en `tree_size` ni `event_root` porque aparezcan dentro del proof: debe vincular ese par al batch manifest firmado y al anchor o trust source aceptado. El path demuestra inclusión respecto de un root; no autentica por sí solo la metadata que identifica ese root.
- ADR-0013 fija inclusion paths en orden hoja-a-root, consistency paths en orden `SUBPROOF` RFC6962 y hashes de 32 bytes en base64url sin padding.

### Construcción incremental

El log builder conserva un compact range/frontier de subárboles perfectos. Al agregar hojas combina roots del mismo nivel y persiste nodos inmutables suficientes para generar inclusion y consistency proofs sin reconstruir toda la historia.

El estado del frontier se guarda transaccionalmente con el batch sellado y puede reconstruirse desde las hojas/eventos inmutables.

## Alternativas consideradas

### Árbol independiente por batch

Se rechazó porque prueba inclusión dentro de un batch, pero no que la historia completa anterior sea prefijo de la nueva.

### Duplicar la última hoja cuando el nivel es impar

Se rechazó porque produce una construcción distinta a Certificate Transparency, complica consistency proofs y agrega ambigüedad entre implementaciones.

### Recalcular todo el árbol en cada batch

Se rechazó por costo operativo. El compact range produce el mismo root incrementalmente.

## Consecuencias

- Los batches anclan roots acumulativos, no roots aislados.
- Monitores pueden detectar truncamiento, inserción retroactiva y forks mediante consistency proofs y anchors.
- El schema de batch debe distinguir tamaño acumulado de cantidad nueva.
- Retener hojas y nodos necesarios es parte de la política de continuidad del log.

## Evidencia y pruebas requeridas

- Vectores para 0, 1, 2, 3, 4, 5, 7, 8 y 9 hojas.
- Roots idénticos mediante construcción completa e incremental.
- Inclusion proofs para primera, intermedia y última hoja.
- Consistency proofs entre múltiples pares de tamaños, incluidos límites de potencia de dos.
- Rechazo de sibling alterado, `tree_size` incorrecto, índice fuera de rango y root anterior falso.
- Reconstrucción del frontier desde eventos persistidos.

## Relación con XCIM

Fija las secciones 23.3 a 23.5 y aclara la semántica acumulativa de los roots publicados en las secciones 25 y 26.
