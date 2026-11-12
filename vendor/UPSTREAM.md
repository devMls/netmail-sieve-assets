# Referencia y parche local

- Crate original: `mailrs-sieve-core 0.3.0`, autores GOLIA K.K., MIT OR Apache-2.0.
- Publicación: https://static.crates.io/crates/mailrs-sieve-core/mailrs-sieve-core-0.3.0.crate
- SHA-256 del `.crate`: `04acd7bdde8b0f199f6353eb1318a61ca6a5cc6639ad4e3e08fe5531be492b68`.
- Revisión declarada por `.cargo_vcs_info.json`: `2bd546744e77478a4810878d7dca6d773a546164`.
- Fuente: https://github.com/goliajp/mailrs/tree/2bd546744e77478a4810878d7dca6d773a546164/crates/sieve-core
- Identificadores del parche: `netmail-source-spans-1` y `netmail-rules-1`.

`[patch.crates-io]` selecciona esta copia fijada. Se conservan el AST, parser,
validación de capacidades, parser de parámetros de ausencia, evaluador, pruebas
unitarias y corpus originales. No existe una dependencia de Stalwart/AGPL.

Cambios locales de `netmail-source-spans-1`, limitados a cuatro archivos:

1. `src/lex/mod.rs`: `SpannedToken` y `tokenize_spanned` exponen rangos UTF-8; el
   API previo `tokenize` sigue devolviendo los mismos tipos. Identificadores y
   tags se normalizan a ASCII minúscula según Sieve; las cadenas conservan caso.
2. `src/lex/string.rs`: recorrer líneas completas en `text:` evita confundir el
   punto final de una frase con el terminador. Se conservan UTF-8 y finales de
   línea, se elimina dot stuffing solo al principio de línea, y se admiten
   cabeceras `text:` con mayúsculas, espacio horizontal y comentario.
3. `src/parse.rs`: exigir consumo completo impide aceptar silenciosamente texto
   después de una llave de cierre extra.
4. `src/lib.rs`: reexportar las dos APIs de posiciones.

### Parche `netmail-rules-1` (adaptador 0.3.0)

Corrige divergencias semánticas detectadas al usar el evaluador como referencia
de reglas. Nuevos archivos: `src/compare.rs`, `src/encoded_word.rs`,
`src/eval/netmail_tests.rs`. Modificados: `src/eval/test_engine.rs`,
`src/eval/mod.rs`, `src/eval/context.rs`, `src/match_str.rs`,
`src/capabilities.rs`, `src/address.rs`, `src/lib.rs` y `Cargo.toml`
(`encoding_rs`).

1. `:comparator` consumía el primer argumento como nombre de cabecera y se
   ignoraba. Ahora se aplica `i;ascii-casemap` o `i;octet`; cualquier otro
   comparador es `UnsupportedComparator`.
2. Tags desconocidos (`:regex`, `:count`, `:value`, `:create`…) o repetidos ya no
   se evalúan como `:is`: devuelven `UnsupportedTag`/`BadArg`.
3. `:matches`: `?` consume un carácter UTF-8 y `\` escapa `*`, `?` y `\`.
4. El test `header` compara valores con encoded-words RFC 2047 decodificados
   (RFC 5228 §2.7.2); `address` conserva el valor bruto.
5. `copy` (RFC 3894) en `fileinto`/`redirect`; `first_string` ya no salta el
   argumento posterior a `:copy`.
6. Reexporta `Comparator`, `match_value`, `escape_glob`, `AddressPart`,
   `scope_to_part`, `extract_addresses` y `decode_encoded_words` para que el IR
   de reglas use el mismo código. Proponer upstream los puntos 1–5.

Las reglas de edición de NetMail viven en `src/source.rs`, `analysis.rs` y
`edit.rs` del adaptador. El alineado consume los tokens y nodos producidos por la
referencia; no reinterpreta expresiones ni decodifica parámetros con otro parser.

Antes de actualizar la referencia: revisar estos cuatro cambios, ejecutar sus
pruebas y corpus congelado sin regenerarlo para ocultar fallos, ejecutar las
regresiones del adaptador y el smoke C-ABI en todos los RIDs. Si upstream incorpora
estas capacidades, retirar el parche en favor de su API publicada. No atribuir
estos cambios a una versión oficial de la referencia.
