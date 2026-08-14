"""
run.py
------
Production CLI entry point for the PII Redaction Tool.

Usage:
    python run.py --input "input/Red Herring Prospectus(1).docx" --output "output/redacted_output.docx"
    python run.py --input ... --output ... --evaluation
    python run.py --help
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure src/ is importable
SRC = Path(__file__).parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from docx import Document

from evaluator import (
    ENTITY_TYPES,
    compute_metrics,
    compute_overall_metrics,
    evaluate_negative_candidates,
    generate_markdown_report,
    run_residual_scan,
)
from pii_redactor import PIIRedactor
from utils import save_json, setup_logger

log = setup_logger("pii_redactor")

DEFAULT_INPUT  = "input/Red Herring Prospectus(1).docx"
DEFAULT_OUTPUT = "output/redacted_output.docx"
EVAL_DIR       = Path("evaluation")
GOLD_PATH      = EVAL_DIR / "gold_annotations.json"
PRED_PATH      = EVAL_DIR / "predictions.json"
REPORT_PATH    = EVAL_DIR / "evaluation_report.md"
METRICS_PATH   = EVAL_DIR / "metrics.json"
RESIDUAL_PATH  = EVAL_DIR / "residual_pii_scan.json"


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="PII Redaction Tool — High-precision, zero-corruption PII redaction for DOCX documents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--input", "-i", default=DEFAULT_INPUT, help="Path to input DOCX file.")
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="Path to output redacted DOCX file.")
    p.add_argument(
        "--evaluation", "-e",
        action="store_true",
        default=True,
        help="Run evaluation pipeline after redaction (default: True).",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity level.",
    )
    return p


# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.getLogger("pii_redactor").setLevel(getattr(logging, args.log_level))

    input_path = Path(args.input)
    output_path = Path(args.output)

    # 1. Execute Redaction Pipeline with Integrated Integrity Gate
    log.info("STEP 1: Executing PII Redaction Pipeline...")
    redactor = PIIRedactor(
        input_path=input_path,
        output_path=output_path,
        log_path=output_path.parent / "PII_REDACTION_LOG.json",
    )
    summary = redactor.run()
    output_path = Path(summary["output"])
    integrity_report = summary.get("integrity_report", {})
    log.info("Redaction completed successfully → %s", output_path)

    # 2. Extract Predictions for Evaluation
    log.info("STEP 2: Exporting predictions for evaluation...")
    with open(output_path.parent / "PII_REDACTION_LOG.json", encoding="utf-8") as f:
        log_data = json.load(f)

    # Predictions format for evaluation
    predictions = [
        {
            "segment_id": item["segment_id"],
            "entity_type": item["entity_type"],
            "text": item.get("text", ""),
            "start": item["start"],
            "end": item["end"],
            "confidence": item["confidence"],
            "source": item["source"],
            "replacement": item["replacement"],
        }
        for item in log_data
    ]
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    save_json(predictions, PRED_PATH)

    # 3. Residual PII Scan (with synthetic replacement exclusion)
    log.info("STEP 3: Running residual PII scan on output document...")
    residual_findings = run_residual_scan(output_path, RESIDUAL_PATH)
    log.info("Residual scan complete: %d residual original PII instances found.", len(residual_findings))

    # 4. Evaluation against Gold Ground Truth & Negative Candidate Sets
    if args.evaluation and GOLD_PATH.exists():
        log.info("STEP 4: Running statistical evaluation against gold ground truth...")
        with open(GOLD_PATH, encoding="utf-8") as f:
            gold_data = json.load(f)

        gold_annotations = gold_data.get("annotations", [])
        negative_candidates = gold_data.get("negative_candidates", [])

        # Compute per-type and aggregate metrics
        per_type = compute_metrics(gold_annotations, predictions, negative_candidates)
        overall = compute_overall_metrics(per_type)

        # Test negative candidate set
        negative_eval = evaluate_negative_candidates(negative_candidates, predictions)

        # Save metrics JSON
        save_json(
            {
                "per_type": per_type,
                "overall": overall,
                "negative_preservation": negative_eval,
                "integrity_report": integrity_report,
            },
            METRICS_PATH,
        )

        # Generate comprehensive Markdown report
        generate_markdown_report(
            per_type=per_type,
            overall=overall,
            output_path=REPORT_PATH,
            doc_stats=summary.get("document_stats"),
            negative_eval=negative_eval,
            residual_count=len(residual_findings),
            integrity_report=integrity_report,
        )

        # Print Evaluation Summary to Console
        print("\n" + "=" * 60)
        print("PER-TYPE EVALUATION METRICS")
        print("=" * 60)
        for et in ENTITY_TYPES:
            m = per_type.get(et, {})
            note = m.get("note", "")
            if note:
                print(f"  {et:<12}: {note}")
            else:
                p_val = f"{m.get('precision', 0):.4f}" if isinstance(m.get('precision'), float) else str(m.get('precision'))
                r_val = f"{m.get('recall', 0):.4f}" if isinstance(m.get('recall'), float) else str(m.get('recall'))
                f1_val = f"{m.get('f1', 0):.4f}" if isinstance(m.get('f1'), float) else str(m.get('f1'))
                acc_val = f"{m.get('accuracy', 0):.4f}" if isinstance(m.get('accuracy'), float) else str(m.get('accuracy'))
                print(
                    f"  {et:<12}: Gold={m.get('gold', 0):<3} Pred={m.get('predicted', 0):<4} "
                    f"TP={m.get('TP', 0):<3} FP={m.get('FP', 0):<3} FN={m.get('FN', 0):<3} "
                    f"P={p_val} R={r_val} F1={f1_val} Acc={acc_val}"
                )

        mi = overall.get("micro", {})
        ma = overall.get("macro", {})
        print("\n" + "=" * 60)
        print("OVERALL AGGREGATE METRICS")
        print("=" * 60)
        print(f"  Micro Precision: {mi.get('precision', 0):.4f}")
        print(f"  Micro Recall:    {mi.get('recall', 0):.4f}")
        print(f"  Micro F1:        {mi.get('f1', 0):.4f}")
        print(f"  Micro Accuracy:  {mi.get('accuracy', 0):.4f}")
        print(f"  Macro Precision: {ma.get('precision', 0):.4f}")
        print(f"  Macro Recall:    {ma.get('recall', 0):.4f}")
        print(f"  Macro F1:        {ma.get('f1', 0):.4f}")
        print(f"  Total TP: {overall.get('total_TP', 0)}  FP: {overall.get('total_FP', 0)}  FN: {overall.get('total_FN', 0)}")
        print(f"  Non-PII Protection Pass Rate: {negative_eval.get('pass_rate', 1.0) * 100:.1f}% ({negative_eval.get('passed', 0)}/{negative_eval.get('total_tested', 0)} preserved)")
        print(f"  Residual Original PII Remaining: {len(residual_findings)}")

    print("\n" + "=" * 60)
    print("DOCUMENT INTEGRITY REPORT")
    print("=" * 60)
    print(f"  Integrity Status:               {integrity_report.get('status', 'N/A')}")
    print(f"  Segments Checked:               {integrity_report.get('segments_checked', 0)}")
    print(f"  Approved PII Spans Replaced:    {integrity_report.get('total_approved_spans', 0)}")
    print(f"  Unauthorized Changed Segments:  {integrity_report.get('segments_with_unexpected_changes', 0)}")
    print(f"  Unauthorized Changed Characters:{integrity_report.get('unauthorized_changed_characters', 0)}")
    print(f"  UNAUTHORIZED_CHANGE_RATE:       {integrity_report.get('unauthorized_change_rate', 0.0):.6f}")
    print(f"  Non-PII Preservation Rate:      {integrity_report.get('non_pii_preservation_rate', 1.0) * 100:.4f}%")

    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    print(f"Input:            {input_path}")
    print(f"Output:           {output_path}")
    print(f"Total Redactions: {summary['total_redactions']}")
    print(f"By Type:          {summary['by_entity_type']}")
    print(f"Predictions:      {PRED_PATH}")
    print(f"Metrics:          {METRICS_PATH}")
    print(f"Eval Report:      {REPORT_PATH}")
    print(f"Residual Scan:    {RESIDUAL_PATH}")
    print()


if __name__ == "__main__":
    main()
