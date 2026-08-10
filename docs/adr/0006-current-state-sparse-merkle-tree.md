# ADR-0006 — Sparse Merkle Tree para estado actual

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-006

## Contexto

El event tree append-only prueba que una concesión o revocación ocurrió, pero no permite demostrar eficientemente el estado actual. El draft admite un sparse Merkle tree o estructura equivalente sin fijar profundidad, orden de bits, hashes vacíos, encoding de hojas ni compresión de proofs.

## Decisión

XCIM v0.1 y Emabled usarán un Sparse Merkle Tree binario de profundidad fija 256.

### State key

```text
state_key = SHA-256(
    "XCIM-STATE-KEY-0.1\0" ||
    UTF8(object_type) || 0x00 || UTF8(object_id)
)
```

Los bits se recorren desde el bit más significativo del primer byte hasta el menos significativo del último. `0` selecciona izquierda y `1` derecha.

### State value y hoja

```text
value_hash = SHA-256(
    "XCIM-STATE-VALUE-0.1\0" || JCS(state_value)
)

leaf_hash = SHA-256(
    "XCIM-STATE-LEAF-0.1\0" || state_key || value_hash
)
```

Incluir `state_key` en la hoja impide trasladar un valor válido a otra posición.

### Nodos internos y vacíos

```text
node_hash(left, right) = SHA-256(
    "XCIM-STATE-NODE-0.1\0" || left || right
)

empty[256] = SHA-256("XCIM-STATE-EMPTY-LEAF-0.1\0")

empty[d] = node_hash(empty[d + 1], empty[d + 1])
            para d = 255 ... 0
```

`empty[0]` es el root normativo del mapa vacío.

### State value mínimo

```json
{
  "effective_at": "2026-08-05T00:03:59Z",
  "latest_event_commitment": "<base64url>",
  "object_id": "urn:xcim:permission:...",
  "status": "active",
  "status_epoch": 1
}
```

Schema, orden JCS y enums se versionan. El `latest_event_commitment` vincula el estado con el evento append-only que lo produjo.

### Proof comprimido

Un proof contiene:

- `state_key`;
- state value canónico o ausencia explícita;
- `tree_depth = 256`;
- bitmap de 256 bits, codificado como 32 bytes base64url sin padding;
- hashes de siblings no vacíos, ordenados de raíz a hoja;
- `state_root`, batch y datos de frescura.

El bit `d` del bitmap indica si se transporta un sibling no vacío a profundidad `d`. Cuando es cero, el verificador usa `empty[d + 1]`. La cantidad de bits activos debe coincidir exactamente con la cantidad de hashes transportados.

ADR-0010 completa el encoding: el bitmap usa orden MSB-first, de modo que profundidad `d` ocupa `bitmap[floor(d / 8)]` con máscara `0x80 >> (d mod 8)`.

Presence proof usa el `leaf_hash` del state value. Absence proof comienza con `empty[256]` en la posición solicitada. Ambos reconstruyen el root desde hoja hacia raíz.

### Ciclo de vida

Los objetos protocolarios no se borran del mapa. Cambian a estados explícitos como:

- `revoked`;
- `expired`;
- `suspended`;
- `erased` cuando se destruyó el vínculo privado por una solicitud válida.

La ausencia conserva el significado “esta clave nunca fue registrada”. Re-consent crea una permission con un nuevo ID y state key.

### Atomicidad

Al sellar un batch:

1. se fijan los eventos y su rango de secuencia;
2. se aplican sus transiciones al state tree en el mismo orden;
3. se obtiene el nuevo `state_root`;
4. se crea el batch manifest que contiene event root y state root;
5. se publica como una única transición sellada.

Un estado sin evento correspondiente o un evento omitido del state root invalida el batch.

El state tree es mutable y no usa consistency proofs. El event tree acumulativo proporciona la explicación append-only de cada transición.

## Alternativas consideradas

### Árbol Merkle ordenado solo con claves presentes

Se rechazó porque las pruebas de ausencia y las actualizaciones requieren reglas adicionales y son menos uniformes.

### Profundidad variable

Se rechazó porque introduce ambigüedad y posibles colisiones estructurales entre implementaciones.

### Proof con los 256 siblings completos

Se rechazó como encoding normal porque agrega aproximadamente 8 KiB antes de metadata incluso cuando casi todos los siblings son vacíos.

### Eliminar entries revocadas

Se rechazó porque confundiría “revocado” con “nunca existió” y debilitaría verificación y auditoría.

## Consecuencias

- Los hashes vacíos son constantes públicas que deben incluirse en test vectors.
- El almacenamiento interno puede optimizar nodos vacíos, pero el root observable debe coincidir exactamente.
- El verifier debe validar bitmap, orden, longitud y canonicalización antes de reconstruir el root.
- La privacidad puede borrar mappings sensibles sin borrar el tombstone protocolario.

## Evidencia y pruebas requeridas

- Root vacío y tabla completa de `empty[0..256]` reproducibles.
- Inserción, actualización y proof de presencia para claves con prefijos compartidos.
- Proof de ausencia antes y después de insertar claves vecinas.
- Compresión y descompresión deterministas del bitmap.
- Rechazo por orden incorrecto, bitmap inconsistente, sibling alterado, key distinta y value no canónico.
- Root idéntico al aplicar un batch desde cero o desde snapshot previo.

## Relación con XCIM

Fija las secciones 24.2 a 24.6 y la parte de current status del proof bundle de la sección 26.
