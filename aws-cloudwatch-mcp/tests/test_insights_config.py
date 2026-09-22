import pytest

from aws_cw_mcp.config import ConfigError, load_config

BASE = {"AWS_REGION": "us-east-1", "AWS_PROFILE": "ob-aws-cloudwatch", "AWS_ACCOUNT_ID": "926266574832"}
GIB = 1 << 30


def cfg(**extra):
    return load_config({**BASE, **extra}, require_account_id=True)


def test_insights_is_off_by_default_and_phase1_config_unchanged():
    c = load_config({"AWS_REGION": "us-east-1"})
    assert c.insights_enabled is False and c.insights_profile is None and c.insights_expected_arn is None
    assert c.aws_profile is None


def test_approved_default_limits():
    c = cfg()
    assert (c.insights_max_range_hours, c.insights_max_log_groups, c.insights_max_rows) == (24, 5, 200)
    assert c.insights_max_estimated_bytes == 2 * GIB and c.insights_session_budget_bytes == 20 * GIB
    assert (c.insights_max_concurrent, c.insights_wait_seconds, c.insights_max_query_seconds) == (2, 40, 180)
    assert (c.insights_max_query_chars, c.insights_max_stages, c.insights_cache_ttl) == (2000, 6, 120)
    assert c.insights_price_per_gb is None


def test_enabled_requires_dedicated_profile():
    with pytest.raises(ConfigError, match="requires AWS_INSIGHTS_PROFILE"):
        cfg(INSIGHTS_ENABLED="true")


def test_insights_profile_must_differ_from_phase1_profile():
    with pytest.raises(ConfigError, match="must differ"):
        cfg(INSIGHTS_ENABLED="true", AWS_INSIGHTS_PROFILE="ob-aws-cloudwatch")


def test_insights_profile_accepted_when_distinct():
    c = cfg(INSIGHTS_ENABLED="true", AWS_INSIGHTS_PROFILE="ob-aws-cloudwatch-insights")
    assert c.insights_enabled and c.insights_profile == "ob-aws-cloudwatch-insights"
    assert c.aws_profile == "ob-aws-cloudwatch"          # Phase 1 profile untouched


def test_same_profile_is_harmless_while_disabled():
    assert cfg(AWS_INSIGHTS_PROFILE="ob-aws-cloudwatch").insights_enabled is False


@pytest.mark.parametrize("var,value", [
    ("INSIGHTS_MAX_RANGE_HOURS", "169"), ("INSIGHTS_MAX_LOG_GROUPS", "21"), ("INSIGHTS_MAX_RESULT_ROWS", "2001"),
    ("INSIGHTS_MAX_ESTIMATED_BYTES", str(51 * GIB)), ("INSIGHTS_SESSION_BYTES_BUDGET", str(201 * GIB)),
    ("INSIGHTS_MAX_CONCURRENT", "6"), ("INSIGHTS_MAX_STARTS_PER_MINUTE", "21"), ("INSIGHTS_WAIT_SECONDS", "56"),
    ("INSIGHTS_MAX_QUERY_SECONDS", "901"), ("INSIGHTS_MAX_QUERY_CHARS", "4001"), ("INSIGHTS_MAX_STAGES", "9"),
    ("INSIGHTS_CACHE_TTL_SECONDS", "901"), ("INSIGHTS_CACHE_MAX_ENTRIES", "129"),
])
def test_hard_ceilings_cannot_be_exceeded(var, value):
    with pytest.raises(ConfigError, match="ceiling"):
        cfg(**{var: value})


def test_hard_range_ceiling_is_seven_days():
    assert cfg(INSIGHTS_MAX_RANGE_HOURS="168").insights_max_range_hours == 168


def test_wait_must_be_below_deadline():
    with pytest.raises(ConfigError, match="smaller"):
        cfg(INSIGHTS_WAIT_SECONDS="50", INSIGHTS_MAX_QUERY_SECONDS="40")


@pytest.mark.parametrize("value", ["maybe", "2", "enabled"])
def test_enabled_flag_must_be_boolean(value):
    with pytest.raises(ConfigError, match="true or false"):
        cfg(INSIGHTS_ENABLED=value)


@pytest.mark.parametrize("value,ok", [("0.005", 0.005), ("0", 0.0), ("", None)])
def test_price_parsing(value, ok):
    assert cfg(INSIGHTS_PRICE_PER_GB_USD=value).insights_price_per_gb == ok


@pytest.mark.parametrize("value", ["cheap", "-1", "nan", "inf"])
def test_price_rejects_garbage(value):
    with pytest.raises(ConfigError):
        cfg(INSIGHTS_PRICE_PER_GB_USD=value)


def test_expected_arn_format_validated():
    good = "arn:aws:iam::926266574832:user/cloud-watch-insights-review"
    assert cfg(AWS_INSIGHTS_EXPECTED_ARN=good).insights_expected_arn == good
    with pytest.raises(ConfigError, match="AWS_INSIGHTS_EXPECTED_ARN"):
        cfg(AWS_INSIGHTS_EXPECTED_ARN="not-an-arn")


def test_account_and_region_pin_still_required_and_unchanged():
    with pytest.raises(ConfigError, match="AWS_ACCOUNT_ID is required"):
        load_config({"AWS_REGION": "us-east-1"}, require_account_id=True)
    c = cfg(INSIGHTS_ENABLED="true", AWS_INSIGHTS_PROFILE="ob-aws-cloudwatch-insights")
    assert c.aws_account_id == "926266574832" and c.aws_region == "us-east-1"


def test_zero_cache_ttl_allowed_to_disable_caching():
    assert cfg(INSIGHTS_CACHE_TTL_SECONDS="0").insights_cache_ttl == 0
