# PII Redaction Tool

A production-quality Python tool that reads a DOCX document and produces a **redacted DOCX** in which personally identifiable information (PII) and other sensitive entity types are replaced with realistic, deterministic fake alternatives.

---

## Overview

This tool implements a **hybrid PII detection pipeline** combining:
- **Regex-based detectors** for structured PII (emails, phone numbers, SSNs, credit cards, IP addresses, DOBs)
- **NLP/NER detectors** using spaCy for person names and organization names
- **Context-aware heuristics** for addresses, roles, and DOB labels
- **Overlap resolution** to handle entities spanning multiple DOCX runs
- **Deterministic synthetic replacement** using seeded Faker instances

---

## Supported PII Types (Mandatory)

| # | Type | Detection Method |
|---|------|-----------------|
| 1 | Full Names | spaCy NER (`PERSON`) + salutation/role context |
| 2 | Email Addresses | RFC-compliant regex |
| 3 | Phone Numbers | Regex + `phonenumbers` library validation |
| 4 | Company Names | spaCy NER (`ORG`) + legal-suffix patterns |
| 5 | Physical/Mailing Addresses | Context label + address component heuristics |
| 6 | Social Security Numbers (SSN) | Formatted regex + context label boosting |
| 7 | Credit Card Numbers | Regex + Luhn checksum + major card prefix |
| 8 | Dates of Birth | Context-gated date pattern (DOB label required) |
| 9 | IP Addresses | IPv4 regex with valid-octet validation |

---

## Optional PII Types

The following additional detectors are **enabled by default** (configurable via flags in `src/detectors.py`):

| Type | Flag | Status |
|------|------|--------|
| Indian PAN Card | `REDACT_OPTIONAL_PAN = True` | ✅ Enabled |
| UPI ID | `REDACT_OPTIONAL_UPI = True` | ✅ Enabled |
| Company Names | `REDACT_COMPANY_NAMES = True` | ✅ Enabled |

Bank account numbers, Client IDs, and DP IDs are **not enabled** because no confirmed instances were found in the supplied prospectus beyond conceptual mentions.

---

## Approach

```
DOCX Input
   │
   ▼
Document Extraction
   (paragraphs + tables + headers + footers + hyperlinks, all with character offsets)
   │
   ▼
Text Normalization
   │
   ┌──────────────────────┬─────────────────────┐
   │                      │                     │
   ▼                      ▼                     ▼
Regex Detectors      NER Detector        Context Heuristics
(Email, Phone,     (PERSON, ORG         (role labels →
 SSN, CC, IP,       via spaCy)           names; DOB label
 DOB, PAN, UPI)                          → dates; addr
                                          patterns)
   └──────────────────────┴─────────────────────┘
                          │
                          ▼
              Candidate Entity Pool
                          │
                          ▼
           Overlap Resolution / Ranking
           (confidence DESC, length DESC, start ASC)
                          │
                          ▼
         Stable Deterministic Replacement Map
         (SHA-256-seeded Faker, one-to-one, collision-free)
                          │
                          ▼
           DOCX Reconstruction (format-preserving)
           - single-run PII: direct replacement
           - multi-run PII: first-run replacement + clear remaining
           - hyperlink targets: mailto: patched
                          │
                          ▼
         Redacted DOCX Output + PII_REDACTION_LOG.json
                          │
                          ▼
              Evaluation Engine + Residual Scan
```

---

## Installation

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

---

## Execution

```bash
# Basic redaction
python run.py --input "input/Red Herring Prospectus(1).docx" --output "output/redacted_output.docx"

# Redaction + evaluation
python run.py --input "input/Red Herring Prospectus(1).docx" --output "output/redacted_output.docx" --evaluation

# Help
python run.py --help
```

---

## Replacement Strategy

Replacements are **deterministic** and **collision-free**:

1. Each (original_text, entity_type) pair generates a **SHA-256 seed**.
2. The seed drives a `random.Random` instance that selects from curated word lists.
3. The result is stored in a global `replacement_map` dict on first access.
4. Subsequent calls for the same original text return the cached replacement.
5. Faker is globally seeded with `12345` for reproducibility.

Example mappings (illustrative, not hard-coded):
```
"Sarthak Malvadkar"       → "Michael Parker"
"cs.connect@ksh..."       → "alex.smith@example.com"
"+91 20 4505 3237"        → "+91 91234xxxxx"
```

Replacement values use safe ranges:
- Emails: `@example.com` domain only
- SSNs: 900–999 area code range (unassigned by SSA)
- IPs: 192.0.2.x (RFC 5737 TEST-NET)
- Credit cards: test prefixes (4111111..., 5500000...)

---

## DOCX Handling

| Feature | Implementation |
|---------|---------------|
| Body paragraphs | Processed run-by-run with offset tracking |
| Tables | All cells in all rows processed |
| Headers | All 75 section headers processed |
| Footers | All 74 section footers processed |
| Multi-run PII | First overlapping run gets replacement; subsequent runs cleared |
| Hyperlinks | Text nodes in `w:hyperlink` elements processed; `mailto:` targets patched |
| Formatting | Bold/italic/underline preserved (run-level attributes untouched) |

---

## Confidence Scores

> **Note**: These are heuristic scores, **not** statistically calibrated probabilities. They reflect the relative reliability of each detection method.

| Method | Score |
|--------|-------|
| Email regex | 0.99 |
| Phone (regex only) | 0.95 |
| Phone (phonenumbers validated) | 0.98 |
| Credit card (regex + Luhn) | 0.99 |
| IP address | 0.99 |
| DOB (with context label) | 0.98 |
| SSN (formatted) | 0.95 |
| SSN (with context label) | 0.98 |
| PERSON (spaCy NER) | 0.90 |
| ORG (spaCy NER) | 0.85 |
| ADDRESS (context heuristics) | 0.88 |
| PAN | 0.97 |
| UPI ID | 0.97 |

---

## Evaluation

### Gold Standard
Gold annotations were created by:
1. Running all detectors independently.
2. Unioning candidates.
3. Manually reviewing against the original document paragraphs.
4. Recording confirmed instances in `evaluation/gold_annotations.json`.

### Metrics
- **Exact text match** (whitespace-normalised) for TP/FP/FN assignment.
- `Accuracy = TP / (TP + FP + FN)` at the span level (no TN at span level).
- Micro: aggregate TP/FP/FN across all types.
- Macro: average per-type precision/recall/F1.

---

## Tradeoffs / Known Limitations

| Challenge | Approach / Tradeoff |
|-----------|---------------------|
| Company names | Conservative: only NER `ORG` + legal-suffix entities; single generic words skipped |
| Dates | **Only** flagged when a DOB label is present; all other dates preserved |
| Financial numbers | Credit cards require Luhn + major-card prefix; share counts not flagged |
| Registration numbers | Not flagged; no dedicated SEBI/CIN detector |
| Geographic names | Cities/states not flagged standalone; only inside address blocks |
| Names vs. organizations | Heuristic FP filter: <2-word NER PERSON results skipped |
| Run-spanning PII | Handled but NER may not span across DOCX run boundaries |
| Encoding artifacts | DOCX with unicode replacement chars (?) may cause partial misses |
| False positives (ORG) | Regulatory body names (SEBI, RBI) may be flagged with `ORG` label |

---

## Project Structure

```
pii-redaction/
├── input/
│   └── Red Herring Prospectus(1).docx
├── output/
│   └── redacted_output.docx
├── src/
│   ├── pii_redactor.py       # Main orchestration
│   ├── detectors.py          # All PII detector classes
│   ├── replacement_generator.py  # Deterministic fake data
│   ├── document_processor.py # DOCX extraction + replacement
│   ├── evaluator.py          # Metrics + report generation
│   └── utils.py              # Shared utilities
├── evaluation/
│   ├── gold_annotations.json
│   ├── predictions.json
│   └── evaluation_report.md
├── tests/
│   ├── test_detectors.py
│   └── test_redaction.py
├── README.md
├── requirements.txt
└── run.py
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## License

For evaluation purposes only.
