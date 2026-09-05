"""Unit tests for commerce_log_analyzer.py - pure logic, no SSH/network."""
from __future__ import annotations

import unittest

import commerce_log_analyzer as cla


def _categories(text: str) -> set[str]:
    return {f.category for f in cla.classify_log_text(text).findings}


class ClassifyLogTextTests(unittest.TestCase):
    def test_oom_killed(self):
        self.assertIn("oom_killed", _categories("Container ts-app was OOMKilled"))

    def test_crash_loop(self):
        self.assertIn("crash_loop", _categories("pod status: CrashLoopBackOff"))

    def test_readiness_probe_failure(self):
        self.assertIn(
            "readiness_liveness_failure", _categories("Readiness probe failed: HTTP probe failed")
        )

    def test_scheduling_failure(self):
        self.assertIn("scheduling_failure", _categories("0/3 nodes are available: Insufficient cpu."))

    def test_http_5xx(self):
        self.assertIn("http_5xx", _categories('"GET /cart HTTP/1.1" 503 128'))

    def test_http_4xx(self):
        self.assertIn("http_4xx", _categories('"GET /cart HTTP/1.1" 404 0'))

    def test_timeout(self):
        self.assertIn("timeout", _categories("Read timed out after 30000ms"))

    def test_connection_failure(self):
        self.assertIn("connection_failure", _categories("java.net.ConnectException: Connection refused"))

    def test_authentication_failure(self):
        self.assertIn("authentication_failure", _categories("Login failed: invalid credentials"))

    def test_database_error(self):
        self.assertIn("database_error", _categories("java.sql.SQLException: connection pool exhausted"))

    def test_redis_error(self):
        self.assertIn("redis_error", _categories("redis.clients.jedis.exceptions.JedisConnectionException: timeout"))

    def test_search_error(self):
        self.assertIn("search_error", _categories("SolrServerException: search request failed"))

    def test_oom_beats_generic_error(self):
        # oom_killed is a more specific/high-signal category and must win
        # over the generic ERROR catch-all for the same line.
        cats = _categories("ERROR: Container OOMKilled")
        self.assertIn("oom_killed", cats)
        self.assertNotIn("generic_error", cats)

    def test_generic_error_catch_all(self):
        self.assertIn("generic_error", _categories("ERROR something unexpected happened"))

    def test_exception_category(self):
        self.assertIn(
            "exception", _categories("com.ibm.commerce.exception.ECApplicationException: bad state")
        )

    def test_blank_lines_ignored(self):
        result = cla.classify_log_text("\n\n   \n")
        self.assertEqual(result.findings, [])

    def test_clean_log_has_no_findings(self):
        result = cla.classify_log_text("INFO server started\nINFO handling request\n")
        self.assertEqual(result.findings, [])

    def test_count_reflects_every_matching_line_not_just_sampled_evidence(self):
        text = "\n".join(["OOMKilled"] * 20)
        result = cla.classify_log_text(text)
        finding = next(f for f in result.findings if f.category == "oom_killed")
        self.assertEqual(finding.count, 20)
        self.assertLessEqual(len(finding.evidence), cla._MAX_EVIDENCE_LINES_PER_CATEGORY)

    def test_total_lines_counts_all_lines_including_blank(self):
        result = cla.classify_log_text("a\n\nb\n")
        self.assertEqual(result.total_lines, 3)


class RedactSecretsTests(unittest.TestCase):
    def test_password_redacted(self):
        out = cla.redact_secrets("connecting with password=SuperSecret123")
        self.assertNotIn("SuperSecret123", out)
        self.assertIn("<redacted>", out)

    def test_api_key_redacted(self):
        out = cla.redact_secrets("api_key=abcdef0123456789")
        self.assertNotIn("abcdef0123456789", out)

    def test_bearer_token_redacted(self):
        out = cla.redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", out)

    def test_aws_access_key_redacted(self):
        out = cla.redact_secrets("using key AKIAABCDEFGHIJKLMNOP for upload")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", out)

    def test_jdbc_password_redacted(self):
        out = cla.redact_secrets("jdbc:db2://host:50000/DB;password=hunter2")
        self.assertNotIn("hunter2", out)

    def test_non_secret_text_unchanged(self):
        text = "INFO server started on port 8080"
        self.assertEqual(cla.redact_secrets(text), text)

    def test_evidence_lines_are_redacted(self):
        result = cla.classify_log_text("ERROR login failed password=hunter2")
        finding = result.findings[0]
        joined = " ".join(finding.evidence)
        self.assertNotIn("hunter2", joined)


class DeduplicationTests(unittest.TestCase):
    def test_identical_repeated_lines_collapse_to_one_distinct_message(self):
        text = "\n".join(["ERROR Connection refused"] * 50)
        result = cla.classify_log_text(text)
        finding = result.findings[0]
        self.assertEqual(finding.count, 50)
        self.assertEqual(finding.total_occurrences, 50)
        self.assertEqual(finding.distinct_messages, 1)
        self.assertEqual(len(finding.evidence), 1)

    def test_timestamp_variation_still_collapses(self):
        lines = [
            f"2026-09-04T00:00:{i:02d}Z ERROR Connection refused to redis" for i in range(10)
        ]
        result = cla.classify_log_text("\n".join(lines))
        finding = result.findings[0]
        self.assertEqual(finding.count, 10)
        self.assertEqual(finding.distinct_messages, 1)

    def test_uuid_variation_still_collapses(self):
        lines = [
            f"ERROR request 123e4567-e89b-12d3-a456-42661417{i:04d} timed out" for i in range(5)
        ]
        result = cla.classify_log_text("\n".join(lines))
        finding = next(f for f in result.findings if f.category == "timeout")
        self.assertEqual(finding.count, 5)
        self.assertEqual(finding.distinct_messages, 1)

    def test_long_numeric_id_variation_still_collapses(self):
        lines = [f"ERROR order 1000{i} failed to process" for i in range(3)]
        result = cla.classify_log_text("\n".join(lines))
        finding = result.findings[0]
        self.assertEqual(finding.distinct_messages, 1)

    def test_three_digit_http_status_not_normalized_away(self):
        # 3-digit codes (HTTP status) must stay meaningfully distinct -
        # only 4+ digit runs are treated as noise.
        text = 'ERROR "GET /x HTTP/1.1" 404\nERROR "GET /x HTTP/1.1" 500'
        result = cla.classify_log_text(text)
        http_4xx = next((f for f in result.findings if f.category == "http_4xx"), None)
        http_5xx = next((f for f in result.findings if f.category == "http_5xx"), None)
        self.assertIsNotNone(http_4xx)
        self.assertIsNotNone(http_5xx)

    def test_genuinely_different_messages_stay_distinct(self):
        text = "ERROR Connection refused to redis\nERROR Connection refused to solr"
        result = cla.classify_log_text(text)
        finding = result.findings[0]
        self.assertEqual(finding.count, 2)
        self.assertEqual(finding.distinct_messages, 2)
        self.assertEqual(len(finding.evidence), 2)

    def test_distinct_messages_capped_at_max_evidence_lines(self):
        # Single/double-digit suffixes (not 4+ digits) are NOT normalized
        # away, so these 20 lines stay genuinely distinct - the point of
        # this test is that `evidence` still caps even though
        # `distinct_messages` reports the true (uncapped) count.
        lines = [f"ERROR unique failure kind {i}" for i in range(20)]
        result = cla.classify_log_text("\n".join(lines))
        finding = result.findings[0]
        self.assertEqual(finding.distinct_messages, 20)
        self.assertLessEqual(len(finding.evidence), cla._MAX_EVIDENCE_LINES_PER_CATEGORY)

    def test_total_occurrences_equals_count(self):
        result = cla.classify_log_text("OOMKilled\nOOMKilled")
        finding = result.findings[0]
        self.assertEqual(finding.total_occurrences, finding.count)


class SeverityTests(unittest.TestCase):
    def test_high_severity_categories(self):
        for cat in ("oom_killed", "crash_loop", "scheduling_failure", "readiness_liveness_failure",
                    "connection_failure", "database_error", "redis_error", "search_error"):
            self.assertEqual(cla.severity_of(cat), "high", cat)

    def test_medium_severity_categories(self):
        for cat in ("timeout", "authentication_failure", "upstream_downstream_failure",
                    "http_5xx", "exception", "stack_trace"):
            self.assertEqual(cla.severity_of(cat), "medium", cat)

    def test_low_severity_categories(self):
        for cat in ("generic_error", "http_4xx"):
            self.assertEqual(cla.severity_of(cat), "low", cat)

    def test_unknown_category_defaults_to_medium(self):
        self.assertEqual(cla.severity_of("some_future_category"), "medium")

    def test_severity_rank_ordering(self):
        self.assertLess(cla.severity_rank("oom_killed"), cla.severity_rank("timeout"))
        self.assertLess(cla.severity_rank("timeout"), cla.severity_rank("generic_error"))

    def test_high_severity_low_count_outranks_low_severity_high_count(self):
        text = "OOMKilled\n" + "ERROR noise\n" * 300
        result = cla.classify_log_text(text)
        self.assertEqual(result.findings[0].category, "oom_killed")

    def test_count_is_tiebreaker_within_same_severity_tier(self):
        # Both connection_failure and database_error are "high" tier;
        # the one with more matches should sort first between them.
        text = "Connection refused\n" * 3 + "SQLException occurred\n" * 10
        result = cla.classify_log_text(text)
        high_tier = [f for f in result.findings if cla.severity_of(f.category) == "high"]
        self.assertEqual(high_tier[0].category, "database_error")


class ParseTimestampTests(unittest.TestCase):
    def test_iso_t_no_millis_no_timezone(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56 INFO started")
        self.assertEqual(ts.kind, "absolute")
        self.assertFalse(ts.timezone_known)
        self.assertIsNone(ts.value.tzinfo)
        self.assertEqual((ts.value.year, ts.value.month, ts.value.day), (2026, 9, 4))
        self.assertEqual((ts.value.hour, ts.value.minute, ts.value.second), (12, 34, 56))

    def test_iso_t_millis_and_z(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56.789Z ERROR boom")
        self.assertEqual(ts.kind, "absolute")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 0)
        self.assertEqual(ts.value.microsecond, 789000)

    def test_iso_space_separator(self):
        ts = cla.parse_timestamp("2026-09-04 12:34:56 ERROR boom")
        self.assertEqual(ts.kind, "absolute")
        self.assertEqual(ts.value.hour, 12)

    def test_plus_hh_colon_mm_offset(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56+05:30 ERROR boom")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 5.5 * 3600)

    def test_plus_hhmm_offset_no_colon(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56+0530 ERROR boom")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 5.5 * 3600)

    def test_negative_offset(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56-04:00 ERROR boom")
        self.assertEqual(ts.value.utcoffset().total_seconds(), -4 * 3600)

    def test_comma_fractional_seconds(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56,500 ERROR boom")
        self.assertEqual(ts.kind, "absolute")
        self.assertEqual(ts.value.microsecond, 500000)

    def test_bracketed_time_only(self):
        ts = cla.parse_timestamp("[12:34:56] ERROR boom")
        self.assertEqual(ts.kind, "time_only")
        self.assertIsNone(ts.value)
        self.assertEqual((ts.partial_time.hour, ts.partial_time.minute, ts.partial_time.second), (12, 34, 56))

    def test_bracketed_time_only_never_gets_a_fabricated_date(self):
        ts = cla.parse_timestamp("[12:34:56] ERROR boom")
        # The whole point: no date/year/month/day is ever invented for a
        # time-only prefix - `value` (the absolute-datetime field) must
        # stay None, only `partial_time` is populated.
        self.assertIsNone(ts.value)

    def test_missing_timestamp_returns_none(self):
        self.assertIsNone(cla.parse_timestamp("ERROR no timestamp anywhere in this line"))

    def test_malformed_timestamp_returns_none_not_raises(self):
        # month=13, hour=99 etc are syntactically the right shape but not
        # a valid date/time - must degrade to None, never raise.
        self.assertIsNone(cla.parse_timestamp("2026-13-45T99:99:99 ERROR boom"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(cla.parse_timestamp(""))

    def test_never_raises_on_arbitrary_garbage(self):
        for garbage in ["----", "2026-09-04T", "[99:99:99]", "T12:34:56Z"]:
            try:
                cla.parse_timestamp(garbage)
            except Exception as exc:  # pragma: no cover - the point is that this never fires
                self.fail(f"parse_timestamp raised on {garbage!r}: {exc}")


class ParseTimestampNewFormatsTests(unittest.TestCase):
    """Focused tests for the real-world formats found in live DEV/UAT
    timestamp validation (WebSphere Liberty, nginx error/combined, Redis)
    plus timezone-abbreviation handling. See parse_timestamp()'s
    docstring / _ABSOLUTE_PARSERS for the fail-fast, never-fabricate
    contract these all still honor."""

    # -- 1. Liberty AEST --------------------------------------------------
    def test_liberty_aest_timestamp(self):
        ts = cla.parse_timestamp(
            "[9/5/26 18:42:57:144 AEST] 00000035 id= I Aries Blueprint packages not available."
        )
        self.assertEqual(ts.kind, "absolute")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 10 * 3600)
        self.assertEqual((ts.value.year, ts.value.month, ts.value.day), (2026, 9, 5))
        self.assertEqual((ts.value.hour, ts.value.minute, ts.value.second), (18, 42, 57))
        self.assertEqual(ts.value.microsecond, 144000)

    # -- 2. Liberty AEDT --------------------------------------------------
    def test_liberty_aedt_timestamp(self):
        ts = cla.parse_timestamp("[1/15/26 09:00:00:000 AEDT] some message")
        self.assertEqual(ts.kind, "absolute")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 11 * 3600)
        self.assertEqual((ts.value.year, ts.value.month, ts.value.day), (2026, 1, 15))

    # -- 3. Liberty malformed ----------------------------------------------
    def test_liberty_malformed_month_returns_none(self):
        self.assertIsNone(cla.parse_timestamp("[13/5/26 18:42:57:144 AEST] bad month"))

    def test_liberty_malformed_never_raises(self):
        for garbage in ["[99/99/99 18:42:57:144 AEST]", "[9/5/26 99:99:99:144 AEST]"]:
            try:
                cla.parse_timestamp(garbage)
            except Exception as exc:  # pragma: no cover - the point is that this never fires
                self.fail(f"parse_timestamp raised on {garbage!r}: {exc}")

    # -- 4. nginx error -----------------------------------------------------
    def test_nginx_error_timestamp(self):
        ts = cla.parse_timestamp("2026/09/05 08:43:08 [notice] 15#15: worker process 68 exited with code 0")
        self.assertEqual(ts.kind, "absolute")
        self.assertFalse(ts.timezone_known)
        self.assertIsNone(ts.value.tzinfo)
        self.assertEqual((ts.value.year, ts.value.month, ts.value.day), (2026, 9, 5))
        self.assertEqual((ts.value.hour, ts.value.minute, ts.value.second), (8, 43, 8))

    # -- 5/6. nginx combined with +0000 / -0400 ------------------------------
    def test_nginx_combined_timestamp_plus_0000(self):
        ts = cla.parse_timestamp('10.12.18.185 - - [05/Sep/2026:08:49:51 +0000] "GET / HTTP/1.1" 404 153')
        self.assertEqual(ts.kind, "absolute")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 0)
        self.assertEqual((ts.value.year, ts.value.month, ts.value.day), (2026, 9, 5))
        self.assertEqual((ts.value.hour, ts.value.minute, ts.value.second), (8, 49, 51))

    def test_nginx_combined_timestamp_minus_0400(self):
        ts = cla.parse_timestamp('10.0.0.1 - - [05/Sep/2026:08:49:51 -0400] "GET / HTTP/1.1" 200 10')
        self.assertEqual(ts.kind, "absolute")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), -4 * 3600)

    def test_nginx_combined_unknown_month_name_returns_none(self):
        self.assertIsNone(cla.parse_timestamp('1.1.1.1 - - [05/Xyz/2026:08:49:51 +0000] "GET / HTTP/1.1" 200 1'))

    # -- 7/8. Redis with/without milliseconds --------------------------------
    def test_redis_timestamp_with_milliseconds(self):
        ts = cla.parse_timestamp("1:M 05 Sep 2026 08:42:42.657 # Server initialized")
        self.assertEqual(ts.kind, "absolute")
        self.assertFalse(ts.timezone_known)
        self.assertEqual((ts.value.year, ts.value.month, ts.value.day), (2026, 9, 5))
        self.assertEqual((ts.value.hour, ts.value.minute, ts.value.second), (8, 42, 42))
        self.assertEqual(ts.value.microsecond, 657000)

    def test_redis_timestamp_without_milliseconds(self):
        ts = cla.parse_timestamp("1:C 05 Sep 2026 08:42:42 # Configuration loaded")
        self.assertEqual(ts.kind, "absolute")
        self.assertEqual(ts.value.microsecond, 0)

    # -- 9/10/11. Existing ISO formats keep working (regression) ------------
    def test_existing_iso_no_timezone_still_works(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56 INFO started")
        self.assertEqual(ts.kind, "absolute")
        self.assertFalse(ts.timezone_known)
        self.assertIsNone(ts.value.tzinfo)
        self.assertEqual((ts.value.hour, ts.value.minute, ts.value.second), (12, 34, 56))

    def test_existing_iso_with_z_still_works(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56.789Z ERROR boom")
        self.assertEqual(ts.kind, "absolute")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 0)
        self.assertEqual(ts.value.microsecond, 789000)

    def test_existing_iso_with_numeric_offset_still_works(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56+05:30 ERROR boom")
        self.assertTrue(ts.timezone_known)
        self.assertEqual(ts.value.utcoffset().total_seconds(), 5.5 * 3600)

    # -- 12. Existing bracketed time-only ------------------------------------
    def test_existing_time_only_still_works(self):
        ts = cla.parse_timestamp("[12:34:56] ERROR boom")
        self.assertEqual(ts.kind, "time_only")
        self.assertIsNone(ts.value)
        self.assertEqual((ts.partial_time.hour, ts.partial_time.minute, ts.partial_time.second), (12, 34, 56))

    # -- 13. Yearless nginx klog remains unparsed ----------------------------
    def test_nginx_klog_yearless_returns_none(self):
        # No year anywhere in this format - must never be promoted to a
        # fake absolute timestamp, and no new "kind" is introduced for it
        # in this task; it simply stays unparsed.
        ts = cla.parse_timestamp(
            "W0905 08:43:54.365747       1 controller.go:2829] Error retrieving endpoints"
        )
        self.assertIsNone(ts)

    # -- 14. Unknown timezone abbreviation -----------------------------------
    def test_unknown_tz_abbreviation_does_not_become_known(self):
        ts = cla.parse_timestamp("2026-09-04T12:34:56 PST ERROR boom")
        self.assertEqual(ts.kind, "absolute")
        self.assertFalse(ts.timezone_known)
        self.assertIsNone(ts.value.tzinfo)

    def test_unknown_tz_abbreviation_in_liberty_bracket_does_not_become_known(self):
        ts = cla.parse_timestamp("[9/5/26 18:42:57:144 PST] some message")
        self.assertEqual(ts.kind, "absolute")
        self.assertFalse(ts.timezone_known)
        self.assertIsNone(ts.value.tzinfo)

    # -- 15. Malformed input never raises (regression, extended) ------------
    def test_never_raises_on_new_format_garbage(self):
        for garbage in [
            "[/5/26 18:42:57:144 AEST]",
            "2026//05 08:43:08",
            "[05/Sep/:08:49:51 +0000]",
            "99 Sep 2026 99:99:99",
            "[9/5/26 18:42:57: AEST]",
        ]:
            try:
                cla.parse_timestamp(garbage)
            except Exception as exc:  # pragma: no cover - the point is that this never fires
                self.fail(f"parse_timestamp raised on {garbage!r}: {exc}")


class EvidenceDetailTests(unittest.TestCase):
    """CategoryFinding backward compatibility + the new evidence_detail
    field carrying parsed timestamps."""

    def test_existing_fields_unchanged(self):
        result = cla.classify_log_text("ERROR something broke")
        finding = result.findings[0]
        self.assertEqual(finding.category, "generic_error")
        self.assertEqual(finding.count, 1)
        self.assertEqual(finding.total_occurrences, 1)
        self.assertEqual(finding.distinct_messages, 1)
        self.assertEqual(finding.evidence, ["ERROR something broke"])

    def test_evidence_detail_present_and_same_length_as_evidence(self):
        result = cla.classify_log_text("ERROR one\nERROR two\nERROR three")
        finding = result.findings[0]
        self.assertEqual(len(finding.evidence_detail), len(finding.evidence))

    def test_evidence_detail_text_matches_evidence_string(self):
        result = cla.classify_log_text("2026-09-04T12:00:00Z ERROR boom")
        finding = result.findings[0]
        self.assertEqual(finding.evidence_detail[0].text, finding.evidence[0])

    def test_evidence_detail_carries_parsed_timestamp(self):
        result = cla.classify_log_text("2026-09-04T12:00:00Z ERROR boom")
        finding = result.findings[0]
        self.assertIsNotNone(finding.evidence_detail[0].timestamp)
        self.assertEqual(finding.evidence_detail[0].timestamp.kind, "absolute")

    def test_evidence_detail_timestamp_none_when_line_has_none(self):
        result = cla.classify_log_text("ERROR boom with no timestamp")
        finding = result.findings[0]
        self.assertIsNone(finding.evidence_detail[0].timestamp)

    def test_dedup_regression_lines_differing_only_by_timestamp_still_collapse(self):
        # Locks in that Phase 4A's additions did not disturb the existing
        # dedup behavior from the prior phase.
        text = "\n".join(
            f"2026-09-04T12:00:{i:02d}Z ERROR Connection refused" for i in range(10)
        )
        result = cla.classify_log_text(text)
        finding = next(f for f in result.findings if f.category == "connection_failure")
        self.assertEqual(finding.count, 10)
        self.assertEqual(finding.distinct_messages, 1)
        self.assertEqual(len(finding.evidence), 1)
        self.assertEqual(len(finding.evidence_detail), 1)

    # -- 16. evidence_detail compatible with the new formats too ------------
    def test_evidence_detail_carries_new_format_timestamp(self):
        # Same evidence_detail/EvidenceSample pipeline as the ISO case
        # above, exercised through one of the newly-supported formats
        # (Redis) - proves the new parsers plug into classify_log_text()
        # without any change to CategoryFinding/EvidenceSample shape.
        result = cla.classify_log_text("1:M 05 Sep 2026 08:42:42.657 # ERROR something broke")
        finding = result.findings[0]
        self.assertIsNotNone(finding.evidence_detail[0].timestamp)
        self.assertEqual(finding.evidence_detail[0].timestamp.kind, "absolute")
        self.assertFalse(finding.evidence_detail[0].timestamp.timezone_known)


if __name__ == "__main__":
    unittest.main()
