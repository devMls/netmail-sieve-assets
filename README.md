# netmail-sieve-assets

Runtime C-ABI para [NetMail](https://gitlab.com/mls_dev/netmail), basado en
`mailrs-sieve-core 0.3.0` (MIT OR Apache-2.0). Versión del adaptador: **0.2.0**;
ABI y esquema JSON: **2**. El motor no realiza I/O, publica scripts ni envía correo.

## Uso de la referencia

Se reutilizan directamente las APIs de `mailrs-sieve-core`:

| Capacidad | API utilizada |
| --- | --- |
| Léxico y decodificación de cadenas | `tokenize_spanned` → `tokenize` |
| Gramática y AST, incluidos tests anidados | `parse_script`, `Command`, `Argument`, `Test` |
| Parámetros de ausencia, MIME, identidad e intervalos | `parse_vacation_args`, `VacationAction`, `VacationPeriod` |
| Comprobación de extensiones del evaluador | `validate` |
| Evaluación con flags y sobre SMTP | `eval_script_with_envelope`, `Envelope`, `Action` |

Documentación: [API de la referencia](https://docs.rs/mailrs-sieve-core/0.3.0/mailrs_sieve_core/),
[código publicado y procedencia del parche](vendor/UPSTREAM.md).

El adaptador solo alinea el AST con los rangos del tokenizer, define qué
estructuras pueden representarse como ajustes de ausencia y construye ediciones
verificables. No mantiene un segundo parser de Sieve ni reimplementa el evaluador.
No usa el wrapper `mailrs-sieve 2.0.1`: ese wrapper convierte algunos errores de
evaluación en `Keep`, mientras que este contrato debe devolver el error al cliente.

La copia de referencia conserva sus fuentes y pruebas, con un parche acotado para
exponer rangos de tokens, corregir `text:` (UTF-8, puntos, dot stuffing y cabecera),
normalizar identificadores/tags y exigir consumo completo del script. No se
presenta como una nueva versión publicada por el proveedor.

## Construcción y validación

Rust está fijado en `rust-toolchain.toml`. El desarrollo cotidiano de NetMail usa
los binarios precompilados y no requiere Rust.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --manifest-path vendor/mailrs-sieve-core-0.3.0/Cargo.toml --tests
python -m unittest discover -s tests -p "test_*.py"
cargo build --locked --release
python tools/smoke_abi.py target/release/netmail_sieve.dll
```

En Linux/macOS, usar el nombre `.so`/`.dylib` de la plataforma en la última línea.
El perfil Release permite unwinding para que `catch_unwind` funcione también en
los binarios distribuidos; no contiene accesos a memoria inválidos del llamante,
abortos del proceso ni falta de memoria.

## Contrato C y JSON

Las firmas completas están en [include/netmail_sieve.h](include/netmail_sieve.h).
Entradas: cadenas UTF-8 terminadas en NUL, no nulas; mensaje binario con longitud
explícita (`size_t`/`nuint`). Salidas: punteros a JSON que se liberan **una sola
vez** con `sieve_free_string` de la misma DLL. Nunca liberar con el allocator de
.NET. `sieve_free_string(NULL)` es válido. Un puntero de salida nulo indica fallo
de asignación; `success:false` indica una operación rechazada y no incluye script.

Límites: 256 KiB por script/entrada JSON, 32 MiB por mensaje y 64 niveles de
anidamiento. Los rangos son **bytes UTF-8**, con fin exclusivo; no son índices
UTF-16 de C#. El cliente comprueba `abi_version` antes de habilitar la edición.

| Export | Resultado |
| --- | --- |
| `sieve_runtime_info_json()` | Versiones, parche de referencia, arquitectura, SO, revisión de fuente y límites |
| `sieve_validate(script)` | `0` sintaxis válida; `1` entrada inválida; `2` fallo de sintaxis/límite |
| `sieve_validate_detail_json(script)` | `valid` sintáctico y validación separada de capacidades locales |
| `sieve_parse_ast_json(script)` | AST compatible con el contrato anterior; añade `typed_args` y rangos |
| `sieve_analyze_script_json(script)` | AST tipado, capacidades declaradas, todos los `vacation`, contextos y diagnósticos |
| `sieve_extract_vacation_json(script)` | Ajustes de un respondedor representable o un error explícito |
| `sieve_merge_vacation(original, snippet)` | Merge conservador de compatibilidad con plan de cambios |
| `sieve_edit_vacation_json(script, request)` | Edición explícita de un objetivo con precondición de contenido |
| `sieve_eval_actions_json(script, bytes, len)` | Acciones del evaluador de referencia sin sobre SMTP |
| `sieve_eval_actions_with_envelope_json(script, bytes, len, envelope)` | Lo mismo con `from`, `to[]` y `auth` SMTP explícitos |

La validación sintáctica no garantiza soporte semántico de una extensión ni que
el servidor admita un script. El evaluador local de la referencia tiene un
subconjunto de extensiones; por ejemplo, `date`/`relational` pueden analizarse para
edición remota, pero no evaluarse localmente. Se conservan los errores, sin
degradarlos a una entrega o a un estado «ausencia desactivada». La compatibilidad
de cada operador/tag para ejecución local debe verificarse por separado; el
resultado `local_capability_validation` solo comprueba declaraciones de extensiones.

## Edición de ausencia

`sieve_merge_vacation` sustituye el comando existente **en su posición**, conserva
sus condiciones, acciones vecinas, ramas, comentarios, `keep` explícitos y demás
bytes. Un contenedor aislado con el calendario UTC `ge`/`lt` de NetMail puede
sustituirse como unidad; un bloque mixto se edita a nivel de comando. Nunca se
elimina un `if` completo solo por contener un `vacation`.

El snippet solo puede contener un respondedor aislado, opcionalmente con un
calendario soportado y declaraciones `require`. Un snippet vacío o un template
desactivado formado por `keep;` elimina el objetivo; no añade un `keep` nuevo a
scripts ajenos. Las extensiones ausentes se añaden antes del código ejecutable;
las declaraciones y el formato existentes se conservan. Una regla y un `require`
en la misma línea se procesan por rangos, sin eliminar líneas.

Con varios respondedores, el merge implícito devuelve `AmbiguousVacation`.
Para seleccionar uno, analizar primero el script y enviar:

```json
{
  "operation": "replace",
  "target_index": 0,
  "expected_source": "vacation \"Respuesta anterior\";",
  "snippet": "require \"vacation\"; vacation \"Respuesta nueva\";",
  "scope": "command"
}
```

- `replace`/`remove` requieren índice y texto anterior exactos; `remove` requiere
  snippet vacío. `command` conserva todos los contenedores; `settings` solo admite
  contenedores aislados representables como ajustes.
- `append` requiere que no haya ningún respondedor. Si hay `stop`, `discard`,
  `reject` o `redirect`, se rechaza por defecto. La opción explícita
  `allow_append_after_control_flow:true` produce un aviso de revisión de alcance;
  no mueve ni elimina esas instrucciones.
- Las respuestas incluyen `script`, `changed` y `edits[{start,end,expected,replacement}]`.
  El consumidor puede reconstruir el candidato aplicando las ediciones de atrás
  hacia delante y presentar el diff antes de publicarlo.
- Un comentario de propiedad es informativo. La adopción de reglas externas, su
  titularidad y la elección de alcance pertenecen a `SieveScriptManager`.

La extracción de ajustes rechaza varios respondedores, audiencias arbitrarias,
ramas ambiguas, fechas no representables, dependencias de variables e includes
externos. El análisis tipado permite inspeccionarlos sin declararlos editables.
`enabled` describe configuración, no prueba que todos los mensajes alcancen la
acción. El cliente mantiene el control de concurrencia, validación remota,
recuperación y confirmación de publicación; ManageSieve no ofrece compare-and-swap.

El evaluador únicamente devuelve acciones. La supresión de respuestas, la
deduplicación RFC 5230, la identidad y el envío pertenecen al servidor. NetMail no
debe usar esta API para emular respuestas de ausencia en local.

## Assets y empaquetado

CI ejecuta pruebas y smoke C-ABI en hosts nativos para `win-x64`, `linux-x64`,
`osx-arm64` y `osx-x64`. Los dos macOS usan hosts de su propia arquitectura. Cada
artefacto conserva su ruta RID, incluso cuando las bibliotecas comparten nombre.
El paquete se rechaza si mezcla arquitectura, ABI, versión o revisión de fuente.

El zip incluye `manifest.json` con SHA-256 y metadatos por binario. Se extrae en
**`runtimes/sieve/` de la raíz de NetMail**; MSBuild lo enlaza como
`runtimes/{rid}/native/` en la salida .NET. No mezclar DLLs de esta versión con
assets anteriores: importar y validar el conjunto completo antes de habilitar
las nuevas funciones. Windows/Linux ARM64 quedan fuera de la matriz actual.

La compilación Linux usa Ubuntu 22.04 (baseline glibc 2.35); macOS usa deployment
target 11.0. La compatibilidad con otras bases requiere un build y pruebas
específicos. No se promete portabilidad universal ni intercambiabilidad glibc/musl.

## Licencia

Adaptador y referencia: MIT OR Apache-2.0. Se conservan los autores, fuentes,
metadatos y procedencia publicados de la dependencia en `vendor/`.
