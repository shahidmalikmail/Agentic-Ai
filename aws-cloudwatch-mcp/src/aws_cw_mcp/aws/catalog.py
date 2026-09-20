"""Name-based hints for grouping log groups into service categories.

These are HEURISTICS on log-group names only. Naming conventions differ per
environment, so a category match is a candidate, not proof of what a group holds.
Extend this table (or pass an explicit `keyword`) rather than hard-coding names.
"""
from __future__ import annotations

CATEGORY_KEYWORDS: dict = {
    "hcl_commerce": ["commerce", "ts-app", "ts-web", "ts-utils", "search-app", "query-app",
                     "crs-app", "xc-app", "hcl", "websphere", "liberty", "wcs"],
    "solr": ["solr", "search-app"],
    "redis": ["redis", "elasticache", "valkey"],
    "nginx": ["nginx", "ingress"],
    "eks": ["/aws/eks", "eks", "containerinsights", "kubernetes", "k8s"],
    "ec2": ["/aws/ec2", "ec2", "cloudwatch-agent", "/var/log"],
    "alb_nlb": ["elb", "alb", "nlb", "loadbalancer", "load-balancer"],
    "cloudfront": ["cloudfront", "cdn"],
    "waf": ["waf", "aws-waf-logs"],
    "lambda": ["/aws/lambda"],
    "rds": ["/aws/rds", "rds", "db2", "postgres", "mysql"],
    "vpc_flow": ["vpc", "flowlog", "flow-log"],
    "route53": ["route53"],
    "sns_ses": ["sns", "ses"],
}


def keywords_for(category: str) -> list:
    key = category.strip().lower().replace("-", "_").replace(" ", "_")
    if key not in CATEGORY_KEYWORDS:
        raise KeyError(key)
    return CATEGORY_KEYWORDS[key]
