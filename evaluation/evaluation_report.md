# PII Redaction Evaluation Report

## 1. Executive Summary

This evaluation benchmarks the PII Redaction Engine against manually verified gold standard
annotations from `Red Herring Prospectus(1).docx`, verifies non-PII document preservation,
and validates residual scan results.

## 2. Document & Dataset Statistics

- **Input Document**: `Red Herring Prospectus(1).docx`
- **Paragraphs**: 1006
- **Tables**: 76
- **Sections**: 85
- **Unique Headers**: 77
- **Unique Footers**: 76

## 3. Per-Entity Metric Breakdown

| Entity Type | Gold Count | Predicted | TP | FP | FN | Precision | Recall | F1 Score | Accuracy |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **PERSON** | 29 | 113 | 23 | 90 | 6 | 0.2035 | 0.7931 | 0.3239 | 0.1933 |
| **EMAIL** | 24 | 26 | 24 | 2 | 0 | 0.9231 | 1.0000 | 0.9600 | 0.9231 |
| **PHONE** | 11 | 22 | 11 | 11 | 0 | 0.5000 | 1.0000 | 0.6667 | 0.5000 |
| **COMPANY** | 7 | 49 | 7 | 42 | 0 | 0.1429 | 1.0000 | 0.2500 | 0.1429 |
| **ADDRESS** | 3 | 7 | 3 | 4 | 0 | 0.4286 | 1.0000 | 0.6000 | 0.4286 |
| **SSN** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |
| **CREDIT_CARD** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |
| **DOB** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |
| **IP_ADDRESS** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |

## 4. Overall Aggregate Metrics

| Metric | Micro Aggregate | Macro Aggregate |
|:---|:---:|:---:|
| **Precision** | **0.3134** | **0.4396** |
| **Recall** | **0.9189** | **0.9586** |
| **F1 Score** | **0.4674** | **0.5601** |
| **Accuracy** | **0.3049** | — |

- **Total True Positives (TP)**: 68
- **Total False Positives (FP)**: 149
- **Total False Negatives (FN)**: 6

## 5. Non-PII Protected Phrase Preservation Test

- **Protected Phrases Tested**: 18
- **Passed (Preserved Unchanged)**: 18
- **Failed (Falsely Redacted)**: 0
- **Protection Pass Rate**: **100.0%**

## 6. Residual PII Scan Results

- **Residual Original PII Remaining**: **10**
- **Synthetic Replacement Exclusion**: Applied

## 7. Verification Invariants

1. **Exact-Span Replacement**: All replacements operate strictly on validated character spans.
2. **Right-to-Left In-Place Mutation**: Run boundaries are preserved without offset drift.
3. **Zero Terminology Corruption**: Legal/financial terms remain byte-for-byte intact.
4. **Deterministic Reproducibility**: Seeded hash registry guarantees 1-to-1 stability.