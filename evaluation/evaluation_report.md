# PII Redaction Evaluation & Document Integrity Report

## 1. Executive Summary

This evaluation report documents the performance of the PII Redaction Engine on `Red Herring Prospectus(1).docx`.
It includes per-entity precision and recall, independent cryptographic document integrity verification,
non-PII preservation rates, and residual PII scan findings.

## 2. Document & Integrity Verification

- **Input Document**: `Red Herring Prospectus(1).docx`
- **Paragraphs**: 1006
- **Tables**: 76
- **Sections**: 85
- **Unique Headers**: 77
- **Unique Footers**: 76
- **Unique Segments Processed**: 4639

### Document Integrity Invariant

- **Integrity Verification Status**: ✅ **PASS**
- **Segments Checked**: 4639
- **Segments with Expected Redactions**: 184
- **Segments with Unexpected Changes**: **0**
- **Unauthorized Changed Characters**: **0**
- **Unauthorized Change Rate (UNAUTHORIZED_CHANGE_RATE)**: **0.000000**
- **Non-PII Preservation Rate**: **100.0000%**

## 3. Per-Entity Metric Breakdown

| Entity Type | Gold Count | Predicted | TP | FP | FN | Precision | Recall | F1 Score | Accuracy |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **PERSON** | 29 | 40 | 23 | 17 | 6 | 0.5750 | 0.7931 | 0.6667 | 0.5000 |
| **EMAIL** | 24 | 26 | 24 | 2 | 0 | 0.9231 | 1.0000 | 0.9600 | 0.9231 |
| **PHONE** | 11 | 22 | 11 | 11 | 0 | 0.5000 | 1.0000 | 0.6667 | 0.5000 |
| **COMPANY** | 7 | 51 | 7 | 44 | 0 | 0.1373 | 1.0000 | 0.2414 | 0.1373 |
| **ADDRESS** | 3 | 0 | 0 | 0 | 3 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| **SSN** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |
| **CREDIT_CARD** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |
| **DOB** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |
| **IP_ADDRESS** | 0 | 0 | 0 | 0 | 0 | *N/A* | *N/A* | *N/A* | *N/A* |

## 4. Overall Aggregate Metrics

| Metric | Micro Aggregate | Macro Aggregate |
|:---|:---:|:---:|
| **Precision** | **0.4676** | **0.4271** |
| **Recall** | **0.8784** | **0.7586** |
| **F1 Score** | **0.6103** | **0.5070** |
| **Accuracy** | **0.4392** | — |

- **Total True Positives (TP)**: 65
- **Total False Positives (FP)**: 74
- **Total False Negatives (FN)**: 9

## 5. Non-PII Protected Phrase Preservation Test

- **Protected Phrases Tested**: 18
- **Passed (Preserved Unchanged)**: 18
- **Failed (Falsely Redacted)**: 0
- **Protection Pass Rate**: **100.0%**

## 6. Residual PII Scan Results

- **Residual Original PII Remaining**: **0**
- **Synthetic Replacement Exclusion**: Applied

## 7. Verification Invariants

1. **Exact-Span Replacement**: All replacements operate strictly on validated character spans.
2. **Right-to-Left In-Place Mutation**: Run boundaries are preserved without offset drift.
3. **Zero Terminology Corruption**: Legal/financial terms remain byte-for-byte intact.
4. **Deterministic Reproducibility**: Seeded hash registry guarantees 1-to-1 stability.