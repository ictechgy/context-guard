from __future__ import annotations

import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import (  # noqa: E402
    CANONICAL_KEY_ORDER,
    CANONICAL_UNICODE_PROFILE,
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    framed_sha256_hex,
    parse_canonical_json_bytes,
)


class G002CanonicalJSONTests(unittest.TestCase):
    def assert_canonical_error(self, code: str, operation) -> CanonicalJSONError:
        with self.assertRaises(CanonicalJSONError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("0x", str(caught.exception))
        return caught.exception

    def test_default_limits_are_the_frozen_bounded_profile(self) -> None:
        """Break caught: an unbounded or silently widened default profile."""
        limits = JSONLimits()
        self.assertEqual(limits.max_document_bytes, 64 * 1024)
        self.assertEqual(limits.max_depth, 32)
        self.assertEqual(limits.max_total_values, 1024)
        self.assertEqual(limits.max_object_members, 256)
        self.assertEqual(limits.max_string_bytes, 16 * 1024)
        self.assertEqual(CANONICAL_UNICODE_PROFILE, "ucd-3.2.0-nfc")
        self.assertEqual(CANONICAL_KEY_ORDER, "unicode-scalar-value")

    def test_encoder_emits_sorted_compact_utf8_with_exactly_one_final_lf(self) -> None:
        """Break caught: platform-dependent escaping, ordering, spacing, or framing."""
        value = {
            "z": "caf\u00e9",
            "line": "one\ntwo",
            "a": [None, True, False, -(2**63), 2**63 - 1],
        }
        self.assertEqual(
            canonical_json_bytes(value),
            b'{"a":[null,true,false,-9223372036854775808,9223372036854775807],'
            b'"line":"one\\ntwo","z":"caf\xc3\xa9"}\n',
        )

    def test_parser_accepts_only_the_exact_encoder_bytes(self) -> None:
        """Break caught: parser and encoder accepting different canonical identities."""
        raw = b'{"a":[null,true,false,-7],"z":"caf\xc3\xa9"}\n'
        value = parse_canonical_json_bytes(raw)
        self.assertEqual(value, {"a": [None, True, False, -7], "z": "caf\u00e9"})
        self.assertEqual(canonical_json_bytes(value), raw)

    def test_encoder_rejects_every_nonportable_json_value(self) -> None:
        """Break caught: Python-only values entering a cross-language identity."""
        cases = (
            ("float_not_allowed", 0.0),
            ("float_not_allowed", float("nan")),
            ("float_not_allowed", float("inf")),
            ("float_not_allowed", float("-inf")),
            ("non_string_key", {1: "value"}),
            ("unsupported_type", (1, 2)),
            ("unsupported_type", {1, 2}),
            ("unsupported_type", b"bytes"),
            ("unsupported_type", object()),
            ("integer_out_of_range", -(2**63) - 1),
            ("integer_out_of_range", 2**63),
        )
        for code, value in cases:
            with self.subTest(code=code, value_type=type(value).__name__):
                self.assert_canonical_error(code, lambda value=value: canonical_json_bytes(value))

    def test_encoder_rejects_non_nfc_and_lone_surrogates_in_values_and_keys(self) -> None:
        """Break caught: normalizing rather than rejecting ambiguous Unicode identity."""
        cases = (
            ("non_nfc", "e\u0301"),
            ("non_nfc", {"e\u0301": 1}),
            ("invalid_unicode", "\ud800"),
            ("invalid_unicode", {"\udfff": 1}),
        )
        for code, value in cases:
            with self.subTest(code=code):
                self.assert_canonical_error(code, lambda value=value: canonical_json_bytes(value))

    def test_unicode_profile_rejects_codepoints_unassigned_in_the_frozen_ucd(self) -> None:
        """Break caught: receipt identity changing with CPython's bundled Unicode version."""
        unstable_across_supported_runtimes = "\u0897\u0323"
        self.assert_canonical_error(
            "unsupported_unicode_repertoire",
            lambda: canonical_json_bytes(unstable_across_supported_runtimes),
        )
        self.assert_canonical_error(
            "unsupported_unicode_repertoire",
            lambda: parse_canonical_json_bytes(
                ('"' + unstable_across_supported_runtimes + '"\n').encode("utf-8")
            ),
        )

    def test_key_order_is_unicode_scalar_value_not_utf16_code_unit_order(self) -> None:
        """Break caught: independent implementations choosing incompatible key ordering."""
        value = {"\U00010300": 2, "\ue000": 1}
        expected = b'{"\xee\x80\x80":1,"\xf0\x90\x8c\x80":2}\n'
        self.assertEqual(canonical_json_bytes(value), expected)
        self.assertEqual(parse_canonical_json_bytes(expected), value)

    def test_parser_rejects_duplicate_keys_floats_and_nonfinite_numbers(self) -> None:
        """Break caught: lossy object parsing or runtime-specific number handling."""
        cases = (
            ("duplicate_key", b'{"a":1,"a":2}\n'),
            ("float_not_allowed", b"1.0\n"),
            ("float_not_allowed", b"1e0\n"),
            ("float_not_allowed", b"NaN\n"),
            ("float_not_allowed", b"Infinity\n"),
            ("float_not_allowed", b"-Infinity\n"),
            ("integer_out_of_range", b"9223372036854775808\n"),
            ("integer_out_of_range", b"-9223372036854775809\n"),
        )
        for code, raw in cases:
            with self.subTest(code=code, raw=raw):
                self.assert_canonical_error(
                    code, lambda raw=raw: parse_canonical_json_bytes(raw)
                )

    def test_huge_integer_error_is_independent_of_process_global_digit_limit(self) -> None:
        """Break caught: Python process settings changing the stable rejection code."""
        raw = (b"9" * 5000) + b"\n"
        previous = sys.get_int_max_str_digits()
        try:
            for digit_limit in (4300, 0):
                with self.subTest(digit_limit=digit_limit):
                    sys.set_int_max_str_digits(digit_limit)
                    self.assert_canonical_error(
                        "integer_out_of_range",
                        lambda: parse_canonical_json_bytes(raw),
                    )
        finally:
            sys.set_int_max_str_digits(previous)

    def test_parser_rejects_malformed_non_utf8_and_ambiguous_unicode(self) -> None:
        """Break caught: malformed or ambiguous text acquiring an identity."""
        cases = (
            ("malformed_json", b'{"a":]\n'),
            ("invalid_utf8", b'"\xff"\n'),
            ("invalid_unicode", b'"\\ud800"\n'),
            ("non_nfc", '"e\u0301"\n'.encode("utf-8")),
        )
        for code, raw in cases:
            with self.subTest(code=code):
                self.assert_canonical_error(
                    code, lambda raw=raw: parse_canonical_json_bytes(raw)
                )

    def test_parser_rejects_every_noncanonical_byte_framing(self) -> None:
        """Break caught: alternate bytes comparing equal to one canonical document."""
        cases = (
            ("invalid_framing", b'{"a":1}'),
            ("invalid_framing", b'{"a":1}\n\n'),
            ("invalid_framing", b'{"a":\n1}\n'),
            ("invalid_framing", b'{"a":1}\r\n'),
            ("invalid_framing", b'\xef\xbb\xbf{"a":1}\n'),
            ("noncanonical_json", b'{ "a":1}\n'),
            ("noncanonical_json", b'{"z":0,"a":1}\n'),
            ("noncanonical_json", b'"\\u00e9"\n'),
            ("noncanonical_json", b"-0\n"),
        )
        for code, raw in cases:
            with self.subTest(code=code, raw=raw):
                self.assert_canonical_error(
                    code, lambda raw=raw: parse_canonical_json_bytes(raw)
                )
        self.assert_canonical_error(
            "invalid_raw_type", lambda: parse_canonical_json_bytes(bytearray(b"null\n"))
        )

    def test_document_limit_counts_the_final_lf_on_encode_and_parse(self) -> None:
        """Break caught: encoder/parser disagreeing at the exact byte boundary."""
        limits = JSONLimits(max_document_bytes=5, max_string_bytes=10)
        self.assertEqual(canonical_json_bytes("ab", limits), b'"ab"\n')
        self.assertEqual(parse_canonical_json_bytes(b'"ab"\n', limits), "ab")
        self.assert_canonical_error(
            "document_too_large", lambda: canonical_json_bytes("abc", limits)
        )
        self.assert_canonical_error(
            "document_too_large", lambda: parse_canonical_json_bytes(b'"abc"\n', limits)
        )

    def test_default_document_limit_accepts_65536_bytes_and_rejects_65537(self) -> None:
        """Break caught: an off-by-one in the frozen 64 KiB document maximum."""
        limits = JSONLimits(max_string_bytes=64 * 1024)
        accepted = b'"' + (b"a" * 65533) + b'"\n'
        rejected = b'"' + (b"a" * 65534) + b'"\n'
        self.assertEqual(len(canonical_json_bytes("a" * 65533, limits)), 65536)
        self.assertEqual(parse_canonical_json_bytes(accepted, limits), "a" * 65533)
        self.assert_canonical_error(
            "document_too_large", lambda: canonical_json_bytes("a" * 65534, limits)
        )
        self.assert_canonical_error(
            "document_too_large", lambda: parse_canonical_json_bytes(rejected, limits)
        )

    def test_depth_limit_accepts_32_nested_containers_and_rejects_33(self) -> None:
        """Break caught: recursion beyond the frozen nesting boundary."""
        accepted: object = 0
        for _ in range(32):
            accepted = [accepted]
        accepted_raw = (b"[" * 32) + b"0" + (b"]" * 32) + b"\n"
        rejected: object = [accepted]
        rejected_raw = (b"[" * 33) + b"0" + (b"]" * 33) + b"\n"
        self.assertEqual(canonical_json_bytes(accepted), accepted_raw)
        self.assertEqual(parse_canonical_json_bytes(accepted_raw), accepted)
        self.assert_canonical_error(
            "max_depth_exceeded", lambda: canonical_json_bytes(rejected)
        )
        self.assert_canonical_error(
            "max_depth_exceeded", lambda: parse_canonical_json_bytes(rejected_raw)
        )

    def test_total_value_limit_counts_root_and_nested_values(self) -> None:
        """Break caught: aggregate item fan-out bypassing a local container bound."""
        limits = JSONLimits(max_total_values=3)
        self.assertEqual(canonical_json_bytes([0, 1], limits), b"[0,1]\n")
        self.assertEqual(parse_canonical_json_bytes(b"[0,1]\n", limits), [0, 1])
        self.assert_canonical_error(
            "max_total_values_exceeded", lambda: canonical_json_bytes([0, 1, 2], limits)
        )
        self.assert_canonical_error(
            "max_total_values_exceeded",
            lambda: parse_canonical_json_bytes(b"[0,1,2]\n", limits),
        )

    def test_default_total_value_limit_accepts_1024_and_rejects_1025(self) -> None:
        """Break caught: widening the frozen aggregate value bound by one."""
        accepted = [0] * 1023
        rejected = [0] * 1024
        self.assertEqual(len(parse_canonical_json_bytes(canonical_json_bytes(accepted))), 1023)
        self.assert_canonical_error(
            "max_total_values_exceeded", lambda: canonical_json_bytes(rejected)
        )

    def test_object_member_limit_is_per_object_and_exactly_inclusive(self) -> None:
        """Break caught: oversized maps or a global member counter rejecting safe siblings."""
        limits = JSONLimits(max_object_members=2)
        accepted = {"a": {"a": 1, "b": 2}, "b": {"a": 3, "b": 4}}
        accepted_raw = b'{"a":{"a":1,"b":2},"b":{"a":3,"b":4}}\n'
        self.assertEqual(canonical_json_bytes(accepted, limits), accepted_raw)
        self.assertEqual(parse_canonical_json_bytes(accepted_raw, limits), accepted)
        self.assert_canonical_error(
            "max_object_members_exceeded",
            lambda: canonical_json_bytes({"a": 1, "b": 2, "c": 3}, limits),
        )
        self.assert_canonical_error(
            "max_object_members_exceeded",
            lambda: parse_canonical_json_bytes(b'{"a":1,"b":2,"c":3}\n', limits),
        )

    def test_default_object_member_limit_accepts_256_and_rejects_257(self) -> None:
        """Break caught: widening the frozen per-object member bound by one."""
        accepted = {f"k{index:03d}": index for index in range(256)}
        rejected = dict(accepted)
        rejected["k256"] = 256
        self.assertEqual(len(parse_canonical_json_bytes(canonical_json_bytes(accepted))), 256)
        self.assert_canonical_error(
            "max_object_members_exceeded", lambda: canonical_json_bytes(rejected)
        )

    def test_string_limit_uses_utf8_bytes_for_both_values_and_keys(self) -> None:
        """Break caught: counting Unicode code points or leaving keys unbounded."""
        limits = JSONLimits(max_string_bytes=4)
        self.assertEqual(canonical_json_bytes("\u00e9\u00e9", limits), b'"\xc3\xa9\xc3\xa9"\n')
        self.assertEqual(
            parse_canonical_json_bytes(b'{"\xc3\xa9\xc3\xa9":0}\n', limits), {"\u00e9\u00e9": 0}
        )
        for value in ("\u00e9\u00e9a", {"\u00e9\u00e9a": 0}):
            with self.subTest(value_type=type(value).__name__):
                self.assert_canonical_error(
                    "max_string_bytes_exceeded",
                    lambda value=value: canonical_json_bytes(value, limits),
                )
        self.assert_canonical_error(
            "max_string_bytes_exceeded",
            lambda: parse_canonical_json_bytes(b'"\xc3\xa9\xc3\xa9a"\n', limits),
        )

    def test_default_string_limit_accepts_16384_bytes_and_rejects_16385(self) -> None:
        """Break caught: widening the frozen string/key UTF-8 bound by one."""
        accepted = "a" * (16 * 1024)
        rejected = accepted + "a"
        self.assertEqual(parse_canonical_json_bytes(canonical_json_bytes(accepted)), accepted)
        self.assert_canonical_error(
            "max_string_bytes_exceeded", lambda: canonical_json_bytes(rejected)
        )

    def test_invalid_limits_fail_closed(self) -> None:
        """Break caught: booleans, zeroes, or foreign limit objects disabling bounds."""
        fields = (
            "max_document_bytes",
            "max_depth",
            "max_total_values",
            "max_object_members",
            "max_string_bytes",
        )
        for field in fields:
            for invalid in (0, -1, True, 1.5):
                with self.subTest(field=field, invalid=invalid):
                    arguments = {field: invalid}
                    self.assert_canonical_error("invalid_limits", lambda: JSONLimits(**arguments))
        self.assert_canonical_error(
            "invalid_limits", lambda: canonical_json_bytes(None, limits=object())
        )
        self.assert_canonical_error(
            "invalid_limits", lambda: parse_canonical_json_bytes(b"null\n", limits=object())
        )

    def test_cycles_are_rejected_without_recursing_or_reflecting_values(self) -> None:
        """Break caught: cyclic Python containers crashing or leaking their representation."""
        value: list[object] = []
        value.append(value)
        error = self.assert_canonical_error(
            "unsupported_type", lambda: canonical_json_bytes(value)
        )
        self.assertEqual(str(error), "canonical JSON rejected: unsupported_type")

    def test_hostile_input_is_never_echoed_by_errors(self) -> None:
        """Break caught: attacker-controlled values leaking through validation failures."""
        secret = "HOSTILE_SECRET_7fb60f"
        operations = (
            lambda: parse_canonical_json_bytes(
                ('{"' + secret + '":1,"' + secret + '":2}\n').encode("ascii")
            ),
            lambda: parse_canonical_json_bytes(
                ('{"' + secret + '":]\n').encode("ascii")
            ),
            lambda: canonical_json_bytes({secret: object()}),
            lambda: framed_sha256_hex(secret + "\u00e9", b"part"),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(CanonicalJSONError) as caught:
                    operation()
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn(secret, caught.exception.code)


class G002FramedHashTests(unittest.TestCase):
    def assert_canonical_error(self, code: str, operation) -> CanonicalJSONError:
        with self.assertRaises(CanonicalJSONError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_framed_hash_matches_all_frozen_literal_vectors(self) -> None:
        """Break caught: concatenation ambiguity, wrong byte order, or domain drift."""
        self.assertEqual(
            framed_sha256_hex("example/v1", b"a", b"bc"),
            "143b915b7f0eaa092fbdefa54030a9269c8a09e0fb6f4ecc15a863696592dbe4",
        )
        self.assertEqual(
            framed_sha256_hex("example/v1", b"ab", b"c"),
            "244ab6b64f32369f99d830996ddf44077921a8eee28812e693e5cc28f041c54e",
        )
        self.assertEqual(
            framed_sha256_hex("contextguard-broker/epr-read-result/v1", b"hello\n"),
            "b3cbba74e4d3a31c8425931c994d6cc5860744ddbc3a4fa3a53e0269f1f338b4",
        )

    def test_domain_boundaries_and_ascii_contract_are_enforced(self) -> None:
        """Break caught: ambiguous, non-ASCII, empty, or oversized hash domains."""
        self.assertEqual(len(framed_sha256_hex("d" * 128)), 64)
        cases = (
            ("invalid_domain", ""),
            ("invalid_domain", "has\x00nul"),
            ("invalid_domain", "domain/\u00e9"),
            ("domain_too_large", "d" * 129),
            ("invalid_domain", b"domain"),
        )
        for code, domain in cases:
            with self.subTest(code=code):
                self.assert_canonical_error(
                    code, lambda domain=domain: framed_sha256_hex(domain)  # type: ignore[arg-type]
                )

    def test_part_count_accepts_64_and_rejects_65(self) -> None:
        """Break caught: unbounded framed-part metadata fan-out."""
        self.assertEqual(len(framed_sha256_hex("parts/v1", *([b""] * 64))), 64)
        self.assert_canonical_error(
            "too_many_parts", lambda: framed_sha256_hex("parts/v1", *([b""] * 65))
        )

    def test_part_and_aggregate_byte_boundaries_are_exactly_inclusive(self) -> None:
        """Break caught: unbounded payloads or off-by-one rejection at frozen maxima."""
        mebibyte = b"x" * (1024 * 1024)
        self.assertEqual(len(framed_sha256_hex("part/v1", mebibyte)), 64)
        self.assert_canonical_error(
            "part_too_large", lambda: framed_sha256_hex("part/v1", mebibyte + b"x")
        )
        self.assertEqual(len(framed_sha256_hex("total/v1", *([mebibyte] * 4))), 64)
        self.assert_canonical_error(
            "parts_too_large", lambda: framed_sha256_hex("total/v1", *([mebibyte] * 5))
        )

    def test_parts_must_be_exact_bytes(self) -> None:
        """Break caught: mutable or implicitly coerced data changing the hash preimage."""
        for part in (bytearray(b"a"), memoryview(b"a"), "a", 1):
            with self.subTest(part_type=type(part).__name__):
                self.assert_canonical_error(
                    "invalid_part",
                    lambda part=part: framed_sha256_hex("part/v1", part),  # type: ignore[arg-type]
                )


if __name__ == "__main__":
    unittest.main()
