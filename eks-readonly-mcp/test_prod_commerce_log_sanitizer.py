"""Unit tests for prod_commerce_log_sanitizer.py (P12B).

Pure logic, zero I/O, zero credentials, zero environment dependency - no
PROD_BASTION_* setup and no paramiko patching needed for this file at all.
"""
from __future__ import annotations

import unittest

import prod_commerce_log_sanitizer as sanitizer


class ExistingPatternsStillDetectedTests(unittest.TestCase):
    def test_password_key_value_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("password=hunter2"))

    def test_passwd_key_value_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("passwd: hunter2"))

    def test_api_key_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("api_key=sk_live_abcdef123456"))

    def test_secret_or_token_key_value_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("client_secret=abc123"))

    def test_authorization_bearer_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("Authorization: Bearer eyJhbGciOi.abc.def"))

    def test_aws_akia_access_key_id_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("key=AKIAABCDEFGHIJKLMNOP"))

    def test_jdbc_embedded_password_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("jdbc:oracle:thin:@host:1521:orcl?password=secretpw"))


class NewGapPatternsDetectedTests(unittest.TestCase):
    def test_aws_secret_access_key_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("aws_secret_access_key=abcDEF123xyz456uvw789"))

    def test_aws_session_token_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("aws_session_token=FQoGZXIvYXdzEA0aDExampleTokenValue"))

    def test_vault_hvs_token_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("connecting with hvs.CAESIExampleVaultTokenValue1234567890"))

    def test_vault_legacy_s_token_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("token seen: s.abcdefghijklmnopqrstuvwx1234"))

    def test_authorization_basic_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("Authorization: Basic dXNlcjpwYXNzd29yZA=="))

    def test_postgres_connection_string_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("connecting to postgres://dbuser:sup3rSecret@dbhost:5432/commerce"))

    def test_redis_connection_string_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("redis://:sup3rSecret@redis-host:6379/0"))

    def test_amqp_connection_string_detected(self):
        self.assertTrue(sanitizer.contains_forbidden_pattern("amqp://guest:secretpw@rabbit-host:5672/vhost"))

    def test_pem_private_key_block_detected(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertTrue(sanitizer.contains_forbidden_pattern(pem))

    def test_pem_private_key_block_without_algorithm_label_detected(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END PRIVATE KEY-----"
        self.assertTrue(sanitizer.contains_forbidden_pattern(pem))


class HighEntropyHeuristicTests(unittest.TestCase):
    def test_long_mixed_case_alnum_token_flagged(self):
        self.assertTrue(sanitizer.looks_high_entropy("token value: aZ9kL2mN8pQ4rS6tU1vW3xY5zA7bC9dE"))

    def test_short_benign_word_not_flagged(self):
        self.assertFalse(sanitizer.looks_high_entropy("connection pool exhausted"))

    def test_long_lowercase_only_word_not_flagged(self):
        # Long but only ONE character class (lowercase) - below the
        # class-diversity threshold, e.g. a long English phrase with no
        # spaces is not inherently secret-shaped.
        self.assertFalse(sanitizer.looks_high_entropy("thisisaverylongwordwithnospacesatall"))

    def test_raw_uuid_is_conservatively_flagged_by_this_coarse_heuristic(self):
        # A raw UUID IS within the allowed character class (hyphens
        # included, for base64url robustness) and long enough to trip this
        # deliberately coarse, over-triggering-by-design heuristic (see
        # module docstring: false positives only ever withhold, never
        # leak). In the real pipeline this never matters in practice -
        # prod_commerce_log_tools._normalize_message() collapses UUIDs to
        # the literal "<UUID>" placeholder BEFORE the candidate ever
        # reaches sanitize_candidate(), so a real UUID never reaches this
        # heuristic as raw text.
        self.assertTrue(sanitizer.looks_high_entropy("request-id: 550e8400-e29b-41d4-a716-446655440000"))


class SanitizeCandidateGateTests(unittest.TestCase):
    def test_none_in_none_out(self):
        self.assertIsNone(sanitizer.sanitize_candidate(None))

    def test_clean_candidate_returned_unchanged(self):
        clean = "connection pool exhausted after <NUM> retries"
        self.assertEqual(sanitizer.sanitize_candidate(clean), clean)

    def test_candidate_with_password_withheld_entirely(self):
        self.assertIsNone(sanitizer.sanitize_candidate("failed login: password=hunter2"))

    def test_candidate_with_bearer_token_withheld_entirely(self):
        self.assertIsNone(sanitizer.sanitize_candidate("Authorization: Bearer abc.def.ghi"))

    def test_candidate_with_high_entropy_token_withheld_entirely(self):
        self.assertIsNone(sanitizer.sanitize_candidate("session=aZ9kL2mN8pQ4rS6tU1vW3xY5zA7bC9dE"))

    def test_never_returns_a_partially_redacted_string(self):
        # The withheld candidate must be exactly None - never a string
        # with a "<redacted>" substitution or any fragment of the original.
        result = sanitizer.sanitize_candidate("password=hunter2 and more text after it")
        self.assertIsNone(result)
        self.assertNotIsInstance(result, str)


class NoValueLeakageTests(unittest.TestCase):
    def test_forbidden_pattern_check_never_raises_on_odd_input(self):
        for candidate in ("", " ", "\n\n\n", "a" * 10000):
            # Must never raise - a malformed/oversized candidate is still
            # just checked, never causes an exception that could carry it
            # in a traceback.
            sanitizer.contains_forbidden_pattern(candidate)
            sanitizer.looks_high_entropy(candidate)
            sanitizer.sanitize_candidate(candidate)


if __name__ == "__main__":
    unittest.main()
