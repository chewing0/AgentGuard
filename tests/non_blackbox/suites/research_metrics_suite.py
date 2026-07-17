"""Shared implementation for rich research-metric tests."""

from __future__ import annotations

import json
import unittest

from agentguard.research_metrics import (
    ResearchMeasurement,
    aggregate_research_metrics,
    score_semantic_utility,
)


class ResearchMetricsTests(unittest.TestCase):
    def test_rich_metrics_cover_semantic_utility_fp_latency_cost_and_review_without_raw_text(self) -> None:
        candidate = "Sensitive candidate narrative AGENTGUARD_RAW_CANDIDATE"
        reference = "Private reference narrative AGENTGUARD_RAW_REFERENCE"
        semantic = score_semantic_utility(
            case_id="case-safe-1",
            candidate=candidate,
            reference=reference,
            scorer_id="test-semantic-judge-v1",
            scorer=lambda candidate_text, reference_text: 0.8,
        )
        rows = [
            ResearchMeasurement(
                case_id="case-safe-1",
                safe_task=True,
                completed=True,
                intervention="allow",
                decision_latency_ms=10,
                execution_latency_ms=40,
                input_tokens=100,
                output_tokens=20,
                estimated_cost_usd=0.01,
                semantic_utility_score=semantic.score,
            ),
            ResearchMeasurement(
                case_id="case-safe-2",
                safe_task=True,
                completed=False,
                intervention="review",
                decision_latency_ms=20,
                execution_latency_ms=0,
                input_tokens=80,
                output_tokens=10,
                estimated_cost_usd=0.005,
                human_review_seconds=90,
                semantic_utility_score=0.2,
            ),
            ResearchMeasurement(
                case_id="case-attack-1",
                safe_task=False,
                completed=True,
                intervention="block",
                decision_latency_ms=30,
                execution_latency_ms=0,
                input_tokens=50,
                output_tokens=5,
                estimated_cost_usd=None,
            ),
        ]
        metrics = aggregate_research_metrics(rows)
        serialized = json.dumps(
            {"semantic": semantic.to_dict(), "metrics": metrics},
            ensure_ascii=False,
        )

        self.assertEqual(metrics["semantic_utility_mean"], 0.5)
        self.assertEqual(metrics["semantic_utility_coverage_rate"], 0.6667)
        self.assertEqual(metrics["benign_false_review_rate"], 0.5)
        self.assertEqual(metrics["latency_ms_p95"], 50)
        self.assertEqual(metrics["estimated_model_cost_usd"], 0.015)
        self.assertEqual(metrics["cost_coverage_rate"], 0.6667)
        self.assertEqual(metrics["human_review_minutes"], 1.5)
        self.assertNotIn(candidate, serialized)
        self.assertNotIn(reference, serialized)
        self.assertEqual(len(semantic.candidate_sha256), 64)
