# Referencia y parche local

- Crate original: `mailrs-sieve-core 0.3.0`, autores GOLIA K.K., MIT OR Apache-2.0.
- Publicación: https://static.crates.io/crates/mailrs-sieve-core/mailrs-sieve-core-0.3.0.crate
- SHA-256 del `.crate`: `04acd7bdde8b0f199f6353eb1318a61ca6a5cc6639ad4e3e08fe5531be492b68`.
- Revisión declarada por `.cargo_vcs_info.json`: `2bd546744e77478a4810878d7dca6d773a546164`.
- Fuente: https://github.com/goliajp/mailrs/tree/2bd546744e77478a4810878d7dca6d773a546164/crates/sieve-core
- Identificador del parche: `netmail-source-spans-1`.

`[patch.crates-io]` selecciona esta copia fijada. Se conservan el AST, parser,
validación de capacidades, parser de parámetros de ausencia, evaluador, pruebas
unitarias y corpus originales. No existe una dependencia de Stalwart/AGPL.

Cambios locales, limitados a cuatro archivos:

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

Las reglas de edición de NetMail viven en `src/source.rs`, `analysis.rs` y
`edit.rs` del adaptador. El alineado consume los tokens y nodos producidos por la
referencia; no reinterpreta expresiones ni decodifica parámetros con otro parser.

Antes de actualizar la referencia: revisar estos cuatro cambios, ejecutar sus
pruebas y corpus congelado sin regenerarlo para ocultar fallos, ejecutar las
regresiones del adaptador y el smoke C-ABI en todos los RIDs. Si upstream incorpora
estas capacidades, retirar el parche en favor de su API publicada. No atribuir
estos cambios a una versión oficial de la referencia.
