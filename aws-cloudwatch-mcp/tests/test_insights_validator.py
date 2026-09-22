"""Validator: allow-list of stage shapes, blocked commands, obfuscation, literal escaping, limits."""
import random
import string

import pytest

from aws_cw_mcp.insights.plans import KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS, MatchSpec, QueryPlan
from aws_cw_mcp.insights.registry import ApprovedQueryRegistry
from aws_cw_mcp.insights.validator import (ALLOWED_COMMANDS, BLOCKED_COMMANDS, Validator, check_group_name,
                                           split_stages, validate_plan, validate_query_text)
from aws_cw_mcp.utils.errors import QueryRejected
from conftest import GROUP, NOW, FakeClock, make_insights_config, plan_for

CFG = make_insights_config()
GOOD = 'filter (@message like "timeout") | stats count(*) as matches by bin(1m)'
BOUNDED = '(@message like "x")'


def rejects(query, match=None, cfg=CFG, estimate=False):
    with pytest.raises(QueryRejected, match=match):
        validate_query_text(query, cfg, estimate=estimate)


# --------------------------------------------------------------------- accepted
def test_known_good_queries_pass():
    assert validate_query_text(GOOD, CFG) == ['filter (@message like "timeout")',
                                              "stats count(*) as matches by bin(1m)"]
    validate_query_text(GOOD + " | estimate", CFG, estimate=True)


def test_allow_list_and_block_list_are_disjoint_and_cover_the_required_commands():
    assert not (ALLOWED_COMMANDS & BLOCKED_COMMANDS)
    required = {"source", "join", "lookup", "subqueries", "appendcols", "cidrlookup", "unmask"}
    assert required <= BLOCKED_COMMANDS
    assert ALLOWED_COMMANDS == {"fields", "filter", "parse", "stats", "sort", "limit", "estimate"}


# --------------------------------------------------------------------- blocked commands
@pytest.mark.parametrize("cmd", sorted(BLOCKED_COMMANDS))
def test_every_blocked_command_is_rejected_as_a_stage(cmd):
    rejects(f'filter {BOUNDED} | {cmd} something | limit 5', "blocked")


@pytest.mark.parametrize("cmd", ["SOURCE", "Join", "LoOkUp", "SUBQUERIES", "APPENDCOLS", "cidrLookup", "UNMASK",
                                 "  join", "JOIN   x"])
def test_blocked_commands_in_any_case_and_spacing(cmd):
    rejects(f'filter {BOUNDED} | {cmd} | limit 5', "blocked")


@pytest.mark.parametrize("query", [
    "SOURCE logGroups(namePrefix: ['/aws']) | filter @message like \"x\" | limit 5",
    'source = logs | where status = 500 | head 10',                              # PPL style
    "SELECT * FROM `/aws/app/one` LIMIT 5",                                      # SQL style
    'filter (@message like "x") | limit 5 | unmask @message',
])
def test_sql_ppl_and_source_forms_rejected(query):
    rejects(query)


@pytest.mark.parametrize("stage", ["foo bar", "newcommand x", "evaluate 1", "sort2 x"])
def test_unknown_future_commands_are_rejected_not_allow_listed(stage):
    rejects(f'filter {BOUNDED} | {stage} | limit 5', "not allow-listed")


def test_deferred_and_blocked_commands_cannot_hide_behind_an_allowed_first_stage():
    rejects(f'filter {BOUNDED} | stats count(*) as matches by @log | join x | limit 5')


# --------------------------------------------------------------------- obfuscation
@pytest.mark.parametrize("query", [
    'filter (@message like "x")\n| join y | limit 5',            # newline
    'filter (@message like "x")\t| limit 5',                       # tab
    'filter (@message like "x") | limit 5\r',                       # carriage return
    'filter (@message like "x") | limit 5 # join something',       # comment
    'filter (@message like "аbc") | limit 5',                # non-ASCII (Cyrillic a)
    'filter (@message like "x")  | limit 5',                  # unicode line separator
    'filter (@message like "x")|limit 5|',                          # trailing empty stage
    'filter (@message like "x") | | limit 5',                        # empty middle stage
    "",
    "   ",
])
def test_control_characters_comments_unicode_and_empty_stages_rejected(query):
    rejects(query)


@pytest.mark.parametrize("query", [
    'filter (@message like "unterminated) | limit 5',
    'filter (@message like /unterminated) | limit 5',
    'filter (@message like "a") | limit 5 "',
])
def test_unbalanced_quotes_and_regex_delimiters_rejected(query):
    rejects(query)


def test_pipe_inside_quotes_or_regex_does_not_split_but_pipe_outside_does():
    assert split_stages('filter (@message like /a|b/) | limit 5') == ['filter (@message like /a|b/)', 'limit 5']
    assert split_stages('a "x|y" | b') == ['a "x|y"', 'b']


def test_stage_shapes_must_match_exactly():
    for stage in ("stats count(*) as x by bin(5m)", "stats count(*) as matches by bin(2m)", "sort matches asc",
                  "sort other desc", "fields @timestamp, @message", "fields *", "limit five", "limit -1",
                  "parse @message /\\b(?<x>403)\\b/", 'filter @message like "no parens"'):
        rejects(f"filter {BOUNDED} | {stage}" if not stage.startswith(("stats", "limit")) else
                f"filter {BOUNDED} | {stage}", None)


# --------------------------------------------------------------------- limits
def test_length_cap():
    small = make_insights_config(insights_max_query_chars=60)
    rejects(GOOD, "exceeds 60 characters", cfg=small)


def test_stage_cap():
    two = make_insights_config(insights_max_stages=2)
    with pytest.raises(QueryRejected, match="more than 2"):
        validate_plan(plan_for(two, kind=KIND_COUNT_BY, dimension="log_group"), two)


def test_query_must_end_bounded():
    rejects('filter (@message like "x")', "bounded stage")
    rejects('fields @timestamp, @log, @message | filter (@message like "x")', "bounded stage")
    rejects('filter (@message like "x") | sort matches desc', "bounded stage")


@pytest.mark.parametrize("n", ["0", "201", "999999", "10000"])
def test_limit_bounds_enforced(n):
    rejects(f'filter (@message like "x") | limit {n}', "limit")


def test_limit_at_cap_is_allowed_and_cap_follows_config():
    validate_query_text('filter (@message like "x") | limit 200', CFG)
    smaller = make_insights_config(insights_max_rows=50)
    rejects('filter (@message like "x") | limit 51', "limit", cfg=smaller)


@pytest.mark.parametrize("query,estimate", [
    ('filter (@message like "x") | estimate | limit 5', True),
    ('filter (@message like "x") | limit 5 | estimate', False),
    ('filter (@message like "x") | limit 5', True),
    ('filter (@message like "x") | limit 5 | estimate | estimate', True),
    ('estimate', True),
    ('filter (@message like "x") | limit 5 | estimate x', True),
])
def test_estimate_only_as_single_final_system_stage(query, estimate):
    rejects(query, estimate=estimate)


# --------------------------------------------------------------------- literal fuzzing / escaping
@pytest.mark.parametrize("literal", [
    'x" or @message like "y', 'a"; drop', 'back\\slash', 'slash/inside', 'pipe|join', 'new\nline', 'tab\t',
    'quote"', "single'", 'semi;colon', 'paren)', '(paren', 'brace{', '$var', '`tick`', 'unicodeé', 'emoji\U0001F600',
    'x' * 65, '', ' ' * 0, '<script>', '*', '%', 'a,b', '#comment', '\x00', 'a‮b',
])
def test_unsafe_or_out_of_range_literals_are_rejected_at_plan_validation(literal):
    for field in ("contains", "exclude"):
        plan = plan_for(CFG, preset="errors", **{field: [literal]})
        with pytest.raises(QueryRejected):
            validate_plan(plan, CFG)


@pytest.mark.parametrize("literal", ["timeout", "connection refused", "db2:50000", "user@host", "a=b", "x-y_z.w", "A1 B2",
                                     "x" * 64])
def test_safe_literals_render_inside_quotes_and_pass(literal):
    vp = validate_plan(plan_for(CFG, preset=None, contains=[literal]), CFG)
    assert f'@message like "{literal}"' in vp.query
    assert len(split_stages(vp.query)) == 2                    # the literal cannot create another stage


def test_literal_fuzz_never_produces_an_extra_stage_or_unbalanced_query():
    rng = random.Random(1234)
    alphabet = string.printable + '"\\/|#;()[]{}<>éа'
    accepted = 0
    for _ in range(600):
        lit = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 70)))
        try:
            vp = validate_plan(plan_for(CFG, preset=None, contains=[lit], exclude=[lit[::-1]]), CFG)
        except QueryRejected:
            continue
        accepted += 1
        stages = split_stages(vp.query)
        assert len(stages) == 2 and stages[0].startswith("filter (") and vp.query.count('"') % 2 == 0
        validate_query_text(vp.query, CFG)
    assert accepted >= 1


def test_property_every_rendered_query_for_valid_plans_passes_stage_b():
    rng = random.Random(7)
    words = ["timeout", "db2", "refused", "a b", "x=1", "svc.api"]
    for _ in range(200):
        kind = rng.choice([KIND_COUNT_OVER_TIME, KIND_COUNT_BY, KIND_SAMPLE_EVENTS])
        kw = {}
        if kind == KIND_COUNT_BY:
            kw["dimension"] = rng.choice(["log_group", "log_stream"])
        if kind != KIND_COUNT_OVER_TIME:
            kw["limit"] = rng.randint(1, 20)
        plan = plan_for(CFG, kind=kind, lookback=rng.choice(["15m", "1h", "6h", "24h"]),
                        preset=rng.choice([None, "errors", "http_5xx", "timeouts"]) or None,
                        contains=rng.sample(words, rng.randint(1, 3)), exclude=rng.sample(words, rng.randint(0, 2)),
                        status_codes=rng.sample([403, 404, 502, 503, 504], rng.randint(0, 3)), **kw)
        vp = validate_plan(plan, CFG)
        validate_query_text(vp.query, CFG)
        validate_query_text(vp.estimate_query, CFG, estimate=True)


# --------------------------------------------------------------------- plan-level (Stage A)
@pytest.mark.parametrize("name", ["", "has space", "semi;colon", "a" * 513, "../x", "/aws/ünï", "/a\n/b", "x*"])
def test_bad_log_group_names_rejected(name):
    with pytest.raises(QueryRejected):
        check_group_name(name, CFG)


def test_allowlist_is_enforced_for_insights():
    allow = make_insights_config(log_group_allowlist=("/aws/eks/*",))
    check_group_name("/aws/eks/cluster", allow)
    with pytest.raises(QueryRejected, match="ALLOWLIST"):
        check_group_name("/aws/waf/x", allow)


def test_group_count_duplicates_and_empty():
    with pytest.raises(QueryRejected, match="at most 5"):
        validate_plan(plan_for(CFG, groups=tuple(f"/g{i}" for i in range(6))), CFG)
    with pytest.raises(QueryRejected, match="duplicate"):
        validate_plan(plan_for(CFG, groups=("/g", "/g")), CFG)
    with pytest.raises(QueryRejected, match="at least one"):
        validate_plan(QueryPlan(KIND_SAMPLE_EVENTS, (), NOW.replace(hour=11), NOW, MatchSpec(presets=("errors",))), CFG)


@pytest.mark.parametrize("kwargs,msg", [
    ({"preset": "nope"}, "unknown preset"),
    ({"preset": None}, "at least one match"),
    ({"contains": ["a", "b", "c", "d"]}, "at most 3"),
    ({"exclude": ["a", "b", "c", "d"]}, "at most 3"),
    ({"status_codes": [99]}, "100 to 599"), ({"status_codes": [600]}, "100 to 599"),
    ({"status_codes": list(range(400, 409))}, "at most 8"), ({"status_codes": [503, 503]}, "distinct"),
])
def test_match_vocabulary_limits(kwargs, msg):
    base = {"preset": "errors", **kwargs}
    with pytest.raises(QueryRejected, match=msg):
        validate_plan(plan_for(CFG, **base), CFG)


def test_kind_specific_rules():
    with pytest.raises(QueryRejected, match="dimension must be"):
        validate_plan(plan_for(CFG, kind=KIND_COUNT_BY, dimension="secret_field"), CFG)
    with pytest.raises(QueryRejected, match="requires status_codes"):
        validate_plan(plan_for(CFG, kind=KIND_COUNT_BY, dimension="status_code"), CFG)
    with pytest.raises(QueryRejected, match="top_n"):
        validate_plan(plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_group", limit=21), CFG)
    with pytest.raises(QueryRejected, match="limit must be"):
        validate_plan(plan_for(CFG, kind=KIND_SAMPLE_EVENTS, limit=21), CFG)
    with pytest.raises(QueryRejected, match="limit must be"):
        validate_plan(plan_for(CFG, kind=KIND_SAMPLE_EVENTS, limit=0), CFG)
    good = plan_for(CFG)
    with pytest.raises(QueryRejected, match="bin must be"):
        validate_plan(QueryPlan(**{**good.__dict__, "bin_seconds": 120}), CFG)
    with pytest.raises(QueryRejected, match="no dimension"):
        validate_plan(QueryPlan(**{**good.__dict__, "dimension": "log_group"}), CFG)
    with pytest.raises(QueryRejected, match="unknown query kind"):
        validate_plan(QueryPlan(**{**good.__dict__, "kind": "raw"}), CFG)


def test_empty_or_inverted_range_rejected():
    good = plan_for(CFG)
    with pytest.raises(QueryRejected, match="empty or inverted"):
        validate_plan(QueryPlan(**{**good.__dict__, "start": good.end}), CFG)


# --------------------------------------------------------------------- approvals (only the validator approves)
def test_validator_approve_registers_single_use_fingerprint_with_ttl():
    clock = FakeClock()
    reg = ApprovedQueryRegistry(60, clock.now)
    v = Validator(CFG, reg)
    vp = v.validate(plan_for(CFG))
    assert len(reg) == 0                                       # validation alone approves nothing
    fp = v.approve(vp, estimate=False)
    assert fp == vp.fingerprint and reg.is_approved(fp)
    assert reg.consume(fp) is True and reg.consume(fp) is False
    v.approve(vp, estimate=True)
    assert reg.is_approved(vp.estimate_fingerprint) and not reg.is_approved(vp.fingerprint)
    clock.advance(61)
    assert not reg.is_approved(vp.estimate_fingerprint)


def test_approve_rejects_a_validated_request_that_was_tampered_with():
    reg = ApprovedQueryRegistry()
    v = Validator(CFG, reg)
    vp = v.validate(plan_for(CFG))
    import dataclasses
    forged = dataclasses.replace(vp, query='filter (@message like "y") | stats count(*) as matches by bin(1m)')
    with pytest.raises(QueryRejected, match="changed after validation"):
        v.approve(forged, estimate=False)
    evil = dataclasses.replace(vp, query='filter (@message like "y") | join z | limit 5')
    with pytest.raises(QueryRejected):
        v.approve(evil, estimate=False)
    assert len(reg) == 0


def test_language_is_pinned():
    assert Validator(CFG, ApprovedQueryRegistry()).language == "CWLI"
