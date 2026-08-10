# ADR-0008 — Receipts inmutables y proyecciones de estado

**Estado:** accepted  
**Fecha:** 2026-08-05  
**Decisión relacionada:** D-008

## Contexto

El blueprint histórico incluye `current_status` dentro de la entidad XCIM Receipt. El receipt core se firma una vez y debe conservar exactamente la observación original. Revocación, expiración y suspensión ocurren después, por lo que no pueden modificar el objeto firmado.

## Decisión

Emabled separará persistencia y modelo de dominio en cuatro estructuras conceptuales.

### `receipt_cores`

Contiene el payload firmado y sus identificadores estables:

- canonical payload bytes;
- payload hash/commitment;
- JWS protected segment y signature;
- issuer key ID;
- timestamps originales;
- referencias inmutables a manifest, identity assertion y app epoch.

Después de firmarse no admite `UPDATE` ni `DELETE` mediante APIs o roles ordinarios de aplicación.

### `permissions`

Contiene cada decisión original incluida en el receipt:

- permission ID;
- receipt ID;
- purpose y authorization kind;
- decisión original `active` o `declined`;
- required flag;
- granted time y expiry originalmente declarada.

La decisión original no cambia. Re-consent crea una permission nueva vinculada a la anterior.

### `permission_events`

Historial append-only de transiciones, por ejemplo:

- `permission_granted`;
- `permission_revoked`;
- `permission_expired`;
- `permission_suspended`;
- `permission_erased`;
- vínculo `permission_regranted` hacia un nuevo ID.

Cada evento tiene secuencia, epoch, effective time y commitment. Nunca se sobrescribe un evento adverso.

### `permission_status`

Proyección materializada del último evento válido:

```text
permission_id
status
status_epoch
effective_at
latest_event_id
latest_event_commitment
projection_updated_at
```

Es mutable por diseño, pero no es fuente histórica. Debe poder reconstruirse determinísticamente desde `permissions + permission_events`.

### Transacciones

Emisión:

1. persistir receipt core y permissions;
2. insertar eventos iniciales;
3. crear proyecciones iniciales;
4. insertar outbox/transparency work;
5. confirmar atómicamente.

Revocación:

1. validar estado y scope;
2. insertar el evento append-only idempotente;
3. avanzar `permission_status` mediante compare-and-swap de `status_epoch`;
4. insertar outbox/transparency work;
5. confirmar atómicamente.

Una revocación concurrente repetida devuelve el resultado idempotente y no crea epochs contradictorios.

### APIs y proofs

Una respuesta puede componer:

```json
{
  "receipt": {},
  "current_status": {},
  "status_proof": {}
}
```

Solo `receipt` pertenece al JWS original. `current_status` y `status_proof` identifican batch, root y frescura propios.

El Sparse Merkle Tree se construye desde la proyección verificada. Antes de sellar un batch, el worker confirma que cada cambio de proyección corresponde a un evento incluido.

## Alternativas consideradas

### Actualizar `current_status` dentro del receipt

Se rechazó porque mezcla hechos observados en momentos distintos y rompe la identidad del objeto firmado.

### Calcular todo el estado reproduciendo eventos en cada consulta

Se rechazó para operación normal por costo y latencia. Sigue siendo el mecanismo de reconstrucción y auditoría.

### Un único estado por receipt

Se rechazó porque un receipt puede incluir múltiples propósitos con decisiones y revocaciones independientes.

## Consecuencias

- Las migraciones y permisos de DB deben proteger tablas inmutables.
- El rol que actualiza proyecciones no puede alterar receipts ni eventos.
- Backups, mirrors y verifier distinguen claramente core histórico y current state.
- Un estado derivado corrupto puede descartarse y reconstruirse.

## Evidencia y pruebas requeridas

- Intentos de modificar o borrar un receipt firmado fallan.
- Revocación cambia proyección sin cambiar un byte del receipt o permission original.
- Reconstrucción completa produce exactamente los mismos estados y state root.
- Revocaciones concurrentes son idempotentes y monotónicas.
- Re-consent genera una permission nueva y mantiene revocada la anterior.
- API y JWS demuestran que `current_status` no pertenece al receipt core.

## Relación con XCIM

Implementa las secciones 21.1, 24, 26.1 y 27, preservando la separación entre receipt core, proof bundle e historial de revocación.
