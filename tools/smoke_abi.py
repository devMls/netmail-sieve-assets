"""Exercise the actual cdylib, its architecture, JSON contract and free function."""
import argparse
import ctypes
import json
from pathlib import Path
import platform


def smoke(path, expected_arch=None):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    lib.sieve_free_string.argtypes = [ctypes.c_void_p]
    lib.sieve_free_string.restype = None
    signatures = {
        "sieve_runtime_info_json": [],
        "sieve_validate_detail_json": [ctypes.c_char_p],
        "sieve_parse_ast_json": [ctypes.c_char_p],
        "sieve_analyze_script_json": [ctypes.c_char_p],
        "sieve_extract_vacation_json": [ctypes.c_char_p],
        "sieve_merge_vacation": [ctypes.c_char_p, ctypes.c_char_p],
        "sieve_edit_vacation_json": [ctypes.c_char_p, ctypes.c_char_p],
        "sieve_eval_actions_json": [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t],
        "sieve_eval_actions_with_envelope_json": [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p],
    }
    for name, arguments in signatures.items():
        getattr(lib, name).argtypes = arguments
        getattr(lib, name).restype = ctypes.c_void_p
    lib.sieve_validate.argtypes = [ctypes.c_char_p]
    lib.sieve_validate.restype = ctypes.c_int32

    def call(name, *args):
        pointer = getattr(lib, name)(*args)
        assert pointer, f"{name}: null result"
        try:
            return json.loads(ctypes.string_at(pointer).decode("utf-8"))
        finally:
            lib.sieve_free_string(pointer)

    info = call("sieve_runtime_info_json")
    host = {"AMD64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}[platform.machine()]
    assert info["abi_version"] == 2 and info["arch"] == (expected_arch or host), info
    old = b'require ["fileinto", "vacation"]; if header :is "Subject" "Invoice" { fileinto "Invoices"; vacation "old"; } else { keep; }'
    new = b'require "vacation"; vacation :days 7 "new";'
    merged = call("sieve_merge_vacation", old, new)
    assert merged["success"] and 'fileinto "Invoices";' in merged["script"], merged
    assert 'vacation :days 7 "new";' in merged["script"] and '} else { keep; }' in merged["script"]
    candidate = merged["script"].encode()
    assert lib.sieve_validate(candidate) == 0
    assert call("sieve_validate_detail_json", candidate)["valid"]
    assert call("sieve_parse_ast_json", candidate)["commands"]
    assert call("sieve_analyze_script_json", candidate)["vacations"][0]["can_read_as_settings"] is False
    assert call("sieve_extract_vacation_json", candidate)["success"] is False
    request = json.dumps({"operation": "remove", "target_index": 0, "expected_source": 'vacation :days 7 "new";'}).encode()
    assert call("sieve_edit_vacation_json", candidate, request)["success"]
    for message in [b"Subject: Invoice\r\n\r\n", b"Subject: Other\r\n\r\n"]:
        original_actions = call("sieve_eval_actions_json", old, message, len(message))
        changed_actions = call("sieve_eval_actions_json", candidate, message, len(message))
        assert original_actions["success"] and changed_actions["success"]
        delivery = lambda value: [action for action in value["actions"] if action["type"] != "vacation"]
        assert delivery(original_actions) == delivery(changed_actions)
    text = 'REQUIRE "vacation"; VACATION TEXT: # comment\nEstoy fuera.\n..Punto ñ 🚀.\n.\n;'.encode()
    assert call("sieve_extract_vacation_json", text)["reason"] == "Estoy fuera.\n.Punto ñ 🚀.\n"
    script = b'require "envelope"; if envelope :is "to" "actual@example.test" { discard; }'
    msg = b"To: other@example.test\r\n\r\n"
    env = b'{"to":["actual@example.test"]}'
    assert call("sieve_eval_actions_with_envelope_json", script, msg, len(msg), env)["actions"][0]["type"] == "discard"
    assert call("sieve_merge_vacation", old, b"\xff")["success"] is False
    assert call("sieve_merge_vacation", None, new)["success"] is False
    lib.sieve_free_string(None)
    return info


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("library")
    parser.add_argument("--expected-arch")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = smoke(args.library, args.expected_arch)
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"abi_smoke": "passed", "runtime": result}))
