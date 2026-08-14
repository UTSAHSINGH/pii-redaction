"""
test_evaluation.py
------------------
Tests for evaluation metrics, negative candidate set verification, and
residual scanner exclusion logic.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evaluator import (
    compute_metrics,
    compute_overall_metrics,
    evaluate_negative_candidates,
    ENTITY_TYPES,
)


class TestEvaluationMetrics:
    def test_perfect_precision_and_recall(self):
        gold = [
            {"entity_type": "EMAIL", "text": "cs.connect@kshinternational.com", "verified": True},
            {"entity_type": "EMAIL", "text": "ksh.ipo@nuvama.com", "verified": True},
        ]
        pred = [
            {"entity_type": "EMAIL", "text": "cs.connect@kshinternational.com"},
            {"entity_type": "EMAIL", "text": "ksh.ipo@nuvama.com"},
        ]

        metrics = compute_metrics(gold, pred)
        email_m = metrics["EMAIL"]
        assert email_m["TP"] == 2
        assert email_m["FP"] == 0
        assert email_m["FN"] == 0
        assert email_m["precision"] == 1.0
        assert email_m["recall"] == 1.0
        assert email_m["f1"] == 1.0
        assert email_m["accuracy"] == 1.0

    def test_absent_entity_category_returns_na(self):
        gold = [
            {"entity_type": "SSN", "text": "ABSENT", "verified": True, "exclude_from_metrics": True}
        ]
        pred = []

        metrics = compute_metrics(gold, pred)
        ssn_m = metrics["SSN"]
        assert ssn_m["precision"] == "N/A"
        assert ssn_m["recall"] == "N/A"
        assert "N/A" in ssn_m.get("note", "")

    def test_overall_metrics_aggregation(self):
        per_type = {
            "EMAIL": {"TP": 10, "FP": 0, "FN": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0, "accuracy": 1.0},
            "PHONE": {"TP": 5, "FP": 1, "FN": 0, "precision": 0.8333, "recall": 1.0, "f1": 0.9091, "accuracy": 0.8333},
            "SSN": {"TP": 0, "FP": 0, "FN": 0, "precision": "N/A", "recall": "N/A", "f1": "N/A", "accuracy": "N/A"},
        }
        overall = compute_overall_metrics(per_type)
        assert overall["total_TP"] == 15
        assert overall["total_FP"] == 1
        assert overall["total_FN"] == 0
        assert overall["micro"]["recall"] == 1.0
        assert overall["micro"]["precision"] > 0.9


class TestNegativeCandidatesEvaluation:
    def test_negative_candidates_pass_when_not_in_predictions(self):
        negatives = [
            {"text": "Companies Act, 1956", "category": "LEGAL_PHRASE"},
            {"text": "Capital Structure", "category": "FINANCIAL_PHRASE"},
            {"text": "Dated December 10, 2025", "category": "PROSPECTUS_DATE"},
        ]
        pred = [
            {"entity_type": "EMAIL", "text": "cs.connect@kshinternational.com"},
            {"entity_type": "PERSON", "text": "Sarthak Malvadkar"},
        ]

        eval_res = evaluate_negative_candidates(negatives, pred)
        assert eval_res["total_tested"] == 3
        assert eval_res["passed"] == 3
        assert eval_res["failed"] == 0
        assert eval_res["pass_rate"] == 1.0

    def test_negative_candidates_fail_if_falsely_redacted(self):
        negatives = [
            {"text": "Companies Act, 1956", "category": "LEGAL_PHRASE"},
        ]
        pred = [
            {"entity_type": "PERSON", "text": "Companies Act, 1956"},
        ]

        eval_res = evaluate_negative_candidates(negatives, pred)
        assert eval_res["failed"] == 1
        assert eval_res["pass_rate"] == 0.0
