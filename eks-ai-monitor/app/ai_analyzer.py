"""LLM-based analysis of a collected ClusterSnapshot.

Kept behind a small `LLMProvider` abstraction so the provider can be
swapped later without touching the analysis logic. Only Anthropic/Claude
is implemented for now, selected via LLM_PROVIDER (default "anthropic").
"""
from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import asdict
from typing import Any, Dict

from app.config import LLMConfig
from app.models import AnalysisResult, ClusterSnapshot

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an SRE assistant analyzing a read-only snapshot of an AWS EKS cluster's "
    "health. You are NOT permitted to suggest destructive commands. Only recommend "
    "read-only investigation commands (kubectl get/describe/logs/top, aws describe-*). "
    "Respond with ONLY a single JSON object, no markdown fences, no prose outside the "
    "JSON, matching exactly this schema:\n"
    "{\n"
    '  "overall_health": "HEALTHY" | "WARNING" | "CRITICAL",\n'
    '  "critical_issues": [string],\n'
    '  "warnings": [string],\n'
    '  "healthy_components": [string],\n'
    '  "affected_namespace": string,\n'
    '  "affected_resource": string,\n'
    '  "likely_reason": string,\n'
    '  "recommended_investigation": [string],\n'
    '  "ai_summary": string\n'
    "}"
)


class LLMProvider(ABC):
    @abstractmethod
    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        """Return the raw text response for the given prompts."""


class AnthropicProvider(LLMProvider):
    def __init__(self, model: str, api_key: str | None = None):
        import anthropic  # imported lazily so ssh-only workflows don't require it

        self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self._model = model

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        if response.stop_reason == "refusal":
            raise RuntimeError("LLM refused to analyze the cluster snapshot")
        for block in response.content:
            if block.type == "text":
                return block.text
        return ""


def get_llm_provider(config: LLMConfig) -> LLMProvider:
    if config.provider == "anthropic":
        return AnthropicProvider(model=config.model, api_key=config.api_key)
    raise ValueError(f"Unsupported LLM_PROVIDER: {config.provider!r}")


def _build_user_prompt(snapshot: ClusterSnapshot) -> str:
    payload = asdict(snapshot)
    return (
        "Here is the structured, read-only monitoring snapshot of the EKS cluster:\n\n"
        f"{json.dumps(payload, indent=2, default=str)}\n\n"
        "Analyze it and respond with the JSON object described in the system prompt."
    )


_JSON_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


def _extract_json(raw_text: str) -> Dict[str, Any]:
    text = raw_text.strip()
    fence_match = _JSON_FENCE_PATTERN.search(text)
    if fence_match:
        text = fence_match.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
    return json.loads(text)


def analyze_cluster_data(snapshot: ClusterSnapshot, config: LLMConfig) -> AnalysisResult:
    provider = get_llm_provider(config)
    user_prompt = _build_user_prompt(snapshot)
    raw_text = provider.analyze(_SYSTEM_PROMPT, user_prompt)

    try:
        parsed = _extract_json(raw_text)
        return AnalysisResult(
            overall_health=parsed.get("overall_health", "UNKNOWN"),
            critical_issues=list(parsed.get("critical_issues", [])),
            warnings=list(parsed.get("warnings", [])),
            healthy_components=list(parsed.get("healthy_components", [])),
            affected_namespace=parsed.get("affected_namespace", ""),
            affected_resource=parsed.get("affected_resource", ""),
            likely_reason=parsed.get("likely_reason", ""),
            recommended_investigation=list(parsed.get("recommended_investigation", [])),
            ai_summary=parsed.get("ai_summary", ""),
            raw_response=raw_text,
        )
    except (json.JSONDecodeError, AttributeError, TypeError) as exc:
        logger.error(f"[AI] Malformed LLM response, falling back to raw text summary: {exc}")
        fallback_health = "CRITICAL" if snapshot.critical_issues else ("WARNING" if snapshot.warnings else "HEALTHY")
        return AnalysisResult(
            overall_health=fallback_health,
            critical_issues=snapshot.critical_issues,
            warnings=snapshot.warnings,
            healthy_components=snapshot.healthy_components,
            ai_summary="LLM response could not be parsed as JSON; showing collected data only. "
            f"Raw response: {raw_text[:500]}",
            raw_response=raw_text,
        )
