#ifndef NETMAIL_SIEVE_H
#define NETMAIL_SIEVE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* C calling convention. Strings are valid NUL-terminated UTF-8, never NULL.
 * Inputs remain caller-owned; JSON outputs are library-owned until freed once
 * with sieve_free_string from the SAME loaded library. NULL output = allocation
 * failure. Never pass an arbitrary pointer or double-free a result.
 * Script/JSON limit: 256 KiB; message limit: 32 MiB. Offsets: UTF-8 bytes [start,end).
 * JSON success=false never includes a candidate script. Syntax validation does
 * not prove semantic support by the local evaluator or a remote Sieve server.
 */
char *sieve_runtime_info_json(void);
int32_t sieve_validate(const char *script);
char *sieve_validate_detail_json(const char *script);
char *sieve_parse_ast_json(const char *script);
char *sieve_analyze_script_json(const char *script);
char *sieve_extract_vacation_json(const char *script);
char *sieve_merge_vacation(const char *original, const char *snippet);
char *sieve_edit_vacation_json(const char *script, const char *request_json);
char *sieve_eval_actions_json(const char *script, const uint8_t *message, size_t message_len);
char *sieve_eval_actions_with_envelope_json(const char *script, const uint8_t *message,
                                         size_t message_len, const char *envelope_json);
/* Rule IR netmail.rules/1 (feature "rules_ir_v1"). Rule sets and requests: 256 KiB;
 * message snapshot batches: 16 MiB, at most 1000 messages. No I/O. */
char *rules_catalog_json(void);
char *rules_validate_json(const char *rules_json);
char *rules_compile_sieve_json(const char *request_json);
char *rules_import_sieve_json(const char *script);
char *rules_apply_region_json(const char *script, const char *request_json);
char *rules_evaluate_batch_json(const char *rules_json, const char *messages_json);
void sieve_free_string(char *result);
#ifdef __cplusplus
}
#endif
#endif
