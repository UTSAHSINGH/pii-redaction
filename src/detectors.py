"""
detectors.py
------------
Conservative, High-Precision PII Detectors.

Key Principles:
1. Structured PII (Email, Phone, CC, SSN, IP, DOB) uses strict validation and context gating.
2. Ordinary prospectus dates (e.g. 'Dated December 10, 2025') are NEVER classified as DOBs.
3. Legal, financial, and document-structure phrases (e.g. 'Companies Act, 1956',
   'Capital Structure', 'Return on Capital Employed', 'Red Herring Prospectus') are
   strictly protected against false-positive redaction.
4. PERSON detection requires strong contextual validation (role labels, salutations, or
   high-confidence NER).
5. COMPANY detection requires full organization names with legal suffixes or explicit
   financial institution roles.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional, Set, Tuple

import phonenumbers
import regex

from utils import PIIMatch, get_context_snippet, luhn_checksum, setup_logger

log = setup_logger("detectors")

# ---------------------------------------------------------------------------
# Configuration Flags
# ---------------------------------------------------------------------------
REDACT_COMPANY_NAMES = True
REDACT_OPTIONAL_PAN = True
REDACT_OPTIONAL_UPI = True


# ---------------------------------------------------------------------------
# Protected Legal, Financial, and Document-Domain Vocabulary
# NO detector is permitted to claim a span overlapping any protected phrase.
# ---------------------------------------------------------------------------

PROTECTED_PHRASES: Set[str] = {
    # Legal Acts & Regulations
    "Companies Act",
    "Companies Act, 1956",
    "Companies Act, 2013",
    "SEBI Act",
    "SEBI Act, 1992",
    "SEBI ICDR Regulations",
    "SEBI ICDR Regulations, 2018",
    "SEBI Listing Regulations",
    "SEBI Takeover Regulations",
    "SEBI SBEB Regulations",
    "Securities Contracts (Regulation) Act, 1956",
    "SCRA",
    "SCRR",
    "Depositories Act, 1996",
    "Income Tax Act",
    "Income-tax Act, 1961",
    "Goods and Services Tax",
    "GST Act",
    "Foreign Exchange Management Act, 1999",
    "FEMA",
    "Competition Act, 2002",
    "Insolvency and Bankruptcy Code, 2016",
    "IBC",
    "Arbitration and Conciliation Act, 1996",

    # Regulatory & Government Bodies (when cited as statutory authorities)
    "Securities and Exchange Board of India",
    "Reserve Bank of India",
    "High Court of Judicature",
    "High Court",
    "Supreme Court of India",
    "Supreme Court",
    "National Company Law Tribunal",
    "NCLT",
    "National Company Law Appellate Tribunal",
    "NCLAT",
    "Registrar of Companies",
    "ROC",
    "Ministry of Corporate Affairs",
    "MCA",
    "Government of India",
    "State Government",
    "Central Government",
    "Stock Exchanges",
    "BSE Limited",
    "National Stock Exchange of India Limited",
    "Central Depository Services (India) Limited",
    "National Securities Depository Limited",
    "CDSL",
    "NSDL",

    # Prospectus Sections & Table of Contents Headings
    "Red Herring Prospectus",
    "Draft Red Herring Prospectus",
    "General Information Document",
    "Table of Contents",
    "Definitions and Abbreviations",
    "Summary of the Offer Document",
    "Summary of the Offer",
    "Summary of Financial Information",
    "General Information",
    "Capital Structure",
    "Objects of the Offer",
    "Basis for Offer Price",
    "Statement of Possible Special Tax Benefits",
    "Industry Overview",
    "Our Business",
    "Key Regulations and Policies",
    "History and Certain Corporate Matters",
    "Our Management",
    "Our Promoter and Promoter Group",
    "Dividend Policy",
    "Financial Statements",
    "Financial Information",
    "Other Financial Information",
    "Legal and Other Information",
    "Outstanding Litigation and Material Developments",
    "Government and Other Approvals",
    "Other Regulatory and Statutory Disclosures",
    "Offering Information",
    "Terms of the Offer",
    "Offer Structure",
    "Offer Procedure",
    "Restrictions on Foreign Ownership of Indian Securities",
    "Description of Equity Shares",
    "Main Provisions of Articles of Association",

    # Financial & Accounting Terminology
    "Revenue from Operations",
    "Return on Capital Employed",
    "Return on Net Worth",
    "Return on Equity",
    "ROCE",
    "RONW",
    "ROE",
    "Net Asset Value",
    "NAV",
    "EBITDA",
    "EBITDA Margin",
    "Adjusted EBITDA",
    "Profit After Tax",
    "PAT",
    "Profit Before Tax",
    "PBT",
    "Restated Consolidated Financial Information",
    "Restated Standalone Financial Information",
    "Financial Year",
    "Fiscal 2025",
    "Fiscal 2024",
    "Fiscal 2023",
    "Earnings Per Share",
    "EPS",
    "Basic EPS",
    "Diluted EPS",
    "Price to Earnings Ratio",
    "P/E Ratio",
    "Industry P/E",
    "Net Debt",
    "Total Debt",
    "Total Equity",
    "Gross Block",
    "Net Block",
    "Capital Work in Progress",
    "CWIP",

    # IPO / Offer Terminology
    "Book Building Process",
    "Offer Price",
    "Floor Price",
    "Cap Price",
    "Price Band",
    "Issue Price",
    "Face Value",
    "Equity Shares",
    "Fresh Issue",
    "Offer for Sale",
    "Bid Amount",
    "Bid Lot",
    "Bid/Offer Opening Date",
    "Bid/Offer Closing Date",
    "Bid/Offer Period",
    "Working Day",
    "Anchor Investor",
    "Anchor Investor Bidding Date",
    "Anchor Investor Allocation Price",
    "Qualified Institutional Buyers",
    "QIB",
    "Non-Institutional Bidders",
    "NII",
    "Retail Individual Bidders",
    "RIB",
    "Retail Individual Investors",
    "RII",
    "Promoter Selling Shareholders",
    "Selling Shareholders",
    "Promoter Group",
    "Group Companies",
    "Key Managerial Personnel",
    "KMP",
    "Senior Management",
    "Board of Directors",
    "Executive Directors",
    "Non-Executive Directors",
    "Independent Directors",
    "Audit Committee",
    "Nomination and Remuneration Committee",
    "Stakeholders Relationship Committee",
    "Corporate Social Responsibility Committee",
    "Risk Management Committee",
    "Monitoring Agency",
    "Registrar to the Offer",
    "Book Running Lead Managers",
    "BRLMs",
    "Syndicate Members",
    "Bankers to the Offer",
    "Sponsor Bank",
    "Escrow Collection Bank",
    "Public Offer Account Bank",
    "Refund Bank",
}

# Compile case-insensitive search pattern for protected phrases
_PROTECTED_REGEX = regex.compile(
    r"\b(?:" + "|".join(regex.escape(p) for p in sorted(PROTECTED_PHRASES, key=len, reverse=True)) + r")\b",
    regex.IGNORECASE,
)


def _get_protected_spans(text: str) -> List[Tuple[int, int]]:
    """Return all character spans in text that match protected vocabulary."""
    return [(m.start(), m.end()) for m in _PROTECTED_REGEX.finditer(text)]


def _overlaps_protected(start: int, end: int, protected_spans: List[Tuple[int, int]]) -> bool:
    """Return True if [start:end] overlaps with any protected phrase span."""
    for p_start, p_end in protected_spans:
        if start < p_end and p_start < end:
            return True
    return False


# ---------------------------------------------------------------------------
# Base Detector Interface
# ---------------------------------------------------------------------------

class BaseDetector:
    """Abstract base class for all PII detectors operating on a DocumentSegment."""

    entity_type: str = "GENERIC"

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 1. Email Detector (Strict RFC Regex)
# ---------------------------------------------------------------------------

class EmailDetector(BaseDetector):
    """Detects RFC-compliant email addresses with high precision."""

    entity_type = "EMAIL"

    _PATTERN = regex.compile(
        r"(?<![a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-])"
        r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}"
        r"@"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}"
        r"(?![a-zA-Z0-9.-])"
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            # Filter out obvious false positives like file extensions
            if raw.endswith((".png", ".jpg", ".docx", ".pdf", ".exe")):
                continue
            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=raw,
                confidence=0.99,
                source="regex",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 2. Phone Detector (Strict Regex + phonenumbers Library Validation)
# ---------------------------------------------------------------------------

class PhoneDetector(BaseDetector):
    """Detects telephone / mobile numbers with country code or standard formats."""

    entity_type = "PHONE"

    # Matches formatted Indian & international numbers: +91 XX XXXX XXXX, +91 20 4505 3237, 022-XXXXXXXX, etc.
    _PATTERN = regex.compile(
        r"(?<!\w)"
        r"(?:"
        r"\+\s*91[\s\-]*(?:\(?\d{1,5}\)?[\s\-]*)?(?:\d[\s\-]*){6,10}\d"  # +91 formats with optional spaces/hyphens
        r"|0\d{2,4}[\s\-](?:\d[\s\-]*){6,8}\d"                           # STD code format: 022-68052182
        r"|\+\s*1[\s\.\-]\(?\d{3}\)?[\s\.\-]\d{3}[\s\.\-]\d{4}"          # US format: +1 (555) 123-4567
        r"|\b[6-9]\d{4}[\s\-]?\d{5}\b"                                   # 10-digit Indian mobile
        r")"
        r"(?!\w)"
    )

    # Keywords nearby that boost confidence
    _CTX_PATTERN = regex.compile(
        r"(?:Tel(?:ephone)?|Phone|Mobile|Fax|Contact|Cell)\s*[:\.]?",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"[^\d]", "", raw)
            if len(digits) < 7 or len(digits) > 15:
                continue

            # Validate with phonenumbers library where applicable
            is_valid = False
            try:
                parsed = phonenumbers.parse(raw.replace(" ", ""), "IN")
                is_valid = phonenumbers.is_possible_number(parsed)
            except Exception:
                pass

            # Context boost
            window_start = max(0, m.start() - 40)
            window = text[window_start: m.end() + 20]
            has_ctx = bool(self._CTX_PATTERN.search(window))

            conf = 0.98 if (is_valid or has_ctx) else 0.92

            # Discard standalone 10-digit numbers with no phone context that look like financial amounts
            if len(digits) == 10 and not raw.startswith("+") and not has_ctx and not is_valid:
                continue

            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=raw,
                confidence=conf,
                source="regex+phonenumbers" if is_valid else "regex",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 3. Credit Card Detector (Regex + Luhn Checksum + Card Prefix)
# ---------------------------------------------------------------------------

class CreditCardDetector(BaseDetector):
    """Detects 13-19 digit card numbers validated with Luhn algorithm."""

    entity_type = "CREDIT_CARD"

    _PATTERN = regex.compile(
        r"(?<!\d)"
        r"(?:"
        r"\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{1,7}"   # Formatted: 4111 1111 1111 1111
        r"|\d{13,19}"                                # Unformatted: 13-19 contiguous digits
        r")"
        r"(?!\d)"
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"[\s\-]", "", raw)
            if len(digits) < 13 or len(digits) > 19:
                continue
            if not luhn_checksum(digits):
                continue
            # Major card prefix requirement (Visa, Mastercard, Amex, Discover, JCB, RuPay)
            if not regex.match(r"^(?:4|5[1-5]|37|6011|622|64|65|35|508|60|6521)", digits):
                continue

            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=raw,
                confidence=0.99,
                source="regex+luhn",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 4. SSN Detector (Strict 3-2-4 Format + US SSN Context Gating)
# ---------------------------------------------------------------------------

class SSNDetector(BaseDetector):
    """Detects US Social Security Numbers only with explicit SSN context."""

    entity_type = "SSN"

    _PATTERN = regex.compile(
        r"(?<!\d)"
        r"\d{3}-\d{2}-\d{4}"
        r"(?!\d)"
    )

    _CTX = regex.compile(
        r"(?:SSN|Social\s+Security\s+(?:Number|#|No\.?))",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            # SSN requires nearby SSN context to avoid false positives in international docs
            window = text[max(0, m.start() - 60): min(len(text), m.end() + 60)]
            if not self._CTX.search(window):
                continue
            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=m.group(0),
                confidence=0.98,
                source="regex+context",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 5. IP Address Detector (Strict Octet Range 0-255)
# ---------------------------------------------------------------------------

class IPAddressDetector(BaseDetector):
    """Detects IPv4 addresses with strictly valid octets."""

    entity_type = "IP_ADDRESS"

    _PATTERN = regex.compile(
        r"(?<![\d\.])"
        r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
        r"(?![\d\.])"
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            # Rejects version strings like 1.0.0.0 if preceded by 'version' or 'v'
            window = text[max(0, m.start() - 15): m.start()]
            if regex.search(r"(?:version|ver|v\.?)\s*$", window, regex.IGNORECASE):
                continue
            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=raw,
                confidence=0.99,
                source="regex",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 6. Date of Birth (DOB) Detector (STRICT Context Gating)
# ---------------------------------------------------------------------------

class DOBDetector(BaseDetector):
    """
    Detects Dates of Birth ONLY when preceded/followed by an explicit DOB label.
    Ordinary prospectus dates (e.g. 'Dated December 10, 2025') are NEVER matched.
    """

    entity_type = "DOB"

    _DOB_CTX = regex.compile(
        r"(?:Date\s+of\s+Birth|D\.?O\.?B\.?|Birth\s+(?:Date|Day)|Born\s+(?:on|in)|Born:)",
        regex.IGNORECASE,
    )

    _DATE_PATTERNS = [
        regex.compile(r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b"),
        regex.compile(
            r"\b(?:0?[1-9]|[12]\d|3[01])\s+"
            r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
            r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
            r"\s*,\s*\d{4}\b",
            regex.IGNORECASE,
        ),
        regex.compile(
            r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
            r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
            r"\s+(?:0?[1-9]|[12]\d|3[01])\s*,\s*\d{4}\b",
            regex.IGNORECASE,
        ),
    ]

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        # DOB detector only runs if segment contains a DOB context keyword
        if not self._DOB_CTX.search(text):
            return []

        for pat in self._DATE_PATTERNS:
            for m in pat.finditer(text):
                # Verify that DOB context is within 50 characters
                window = text[max(0, m.start() - 50): min(len(text), m.end() + 50)]
                if self._DOB_CTX.search(window):
                    results.append(PIIMatch(
                        segment_id=segment_id,
                        entity_type=self.entity_type,
                        start=m.start(),
                        end=m.end(),
                        text=m.group(0),
                        confidence=0.98,
                        source="context+regex",
                        context=get_context_snippet(text, m.start(), m.end()),
                    ))
        return results


# ---------------------------------------------------------------------------
# 7. Address Detector (Complete Physical Address Blocks Only)
# ---------------------------------------------------------------------------

class AddressDetector(BaseDetector):
    """
    Detects complete physical/mailing address blocks starting at address triggers.
    Replaces the entire multi-line block as a single unit; never isolated city names.
    """

    entity_type = "ADDRESS"

    _ADDR_TRIGGER = regex.compile(
        r"(?:(?:Registered|Corporate|Regd\.?|Branch|Mailing|Residence)\s+(?:Office|Address)|"
        r"(?:Office|Contact)\s+Address|Address|registered office (?:is )?at|Corporate Office at|manufacturing facility located at)\s*[:\-]?\s*",
        regex.IGNORECASE,
    )

    _ADDR_CONTENT = regex.compile(
        r"(?:Plot|Flat|Floor|No\.?|#|Block|Building|Tower|Complex|House|Gat\s+No\.?|\d+[\w\-/,\s]+)\s*"
        r"(?:Street|Road|Marg|Lane|Nagar|Colony|Sector|Phase|Park|Chowk|Circle|Village|Taluka|District|Dist\.?|Pune|Mumbai|Maharashtra|India)\b",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for trigger_m in self._ADDR_TRIGGER.finditer(text):
            start = trigger_m.end()
            remainder = text[start:]

            # Address block ends at a terminator label or end of paragraph
            end_match = regex.search(
                r"(?=\n|\r|\Z|;|\.(?:\s+[A-Z]|\s*$)| and its | and having |(?:Telephone|Tel|Phone|Mobile|Fax|Email|E-mail|Website|CIN|GSTIN|Contact Person)\s*[:\.])",
                remainder,
                regex.IGNORECASE,
            )
            block_len = end_match.start() if end_match else min(len(remainder), 250)
            addr_text = remainder[:block_len].strip().rstrip(";.,")

            # Require minimum length and structural address components
            if len(addr_text) >= 20 and self._ADDR_CONTENT.search(addr_text):
                # Trim trailing punctuation/whitespace
                actual_end = start + len(addr_text)
                results.append(PIIMatch(
                    segment_id=segment_id,
                    entity_type=self.entity_type,
                    start=start,
                    end=actual_end,
                    text=addr_text,
                    confidence=0.90,
                    source="context+heuristic",
                    context=get_context_snippet(text, start, actual_end),
                ))
        return results


# ---------------------------------------------------------------------------
# 8. PAN & UPI Detectors (Optional Sensitive Identifiers)
# ---------------------------------------------------------------------------

class PANDetector(BaseDetector):
    """Indian Permanent Account Number (PAN) detector: 5 uppercase letters, 4 digits, 1 uppercase letter."""

    entity_type = "PAN"
    _PATTERN = regex.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        if not REDACT_OPTIONAL_PAN:
            return []
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            # 4th char is status: P (Individual), C (Company), H (HUF), F (Firm), A (AOP), T (Trust), B (BOI), L (Local), J (Artificial), G (Govt)
            if raw[3] in "PCHFATBLJG":
                results.append(PIIMatch(
                    segment_id=segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=raw,
                    confidence=0.95,
                    source="regex",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


class UPIDetector(BaseDetector):
    """Unified Payments Interface (UPI) ID detector: handle@psp."""

    entity_type = "UPI_ID"
    _PATTERN = regex.compile(
        r"\b[a-zA-Z0-9.\-_]{2,}@(okaxis|oksbi|okhdfcbank|okicici|paytm|ybl|upi|axisbank|icici|hdfcbank|kotak|sbi)\b",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        if not REDACT_OPTIONAL_UPI:
            return []
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=m.start(),
                end=m.end(),
                text=m.group(0),
                confidence=0.95,
                source="regex",
                context=get_context_snippet(text, m.start(), m.end()),
            ))
        return results


# ---------------------------------------------------------------------------
# 9. Conservative PERSON Detector (Salutation + Role Context + Strict NER)
# ---------------------------------------------------------------------------

class PersonDetector(BaseDetector):
    """
    High-precision PERSON detector.
    Combines:
    1. Salutations (Mr., Mrs., Ms., Dr., Shri, Smt.)
    2. Role labels (Company Secretary, Compliance Officer, Promoter, Director, CEO, CFO, Contact Person)
    3. spaCy NER (strictly filtered against protected legal/financial vocabulary)
    """

    entity_type = "PERSON"

    _SALUTATION = regex.compile(
        r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Shri|Smt\.?|Kum\.?)\s+",
        regex.IGNORECASE,
    )

    _ROLE_LABELS = regex.compile(
        r"\b(?:"
        r"Company\s+Secretary(?:\s+and\s+Compliance\s+Officer)?"
        r"|Compliance\s+Officer"
        r"|Contact\s+Person(?:s)?"
        r"|Managing\s+Director"
        r"|Executive\s+Director"
        r"|Whole.?time\s+Director"
        r"|Independent\s+Director"
        r"|Chief\s+Executive\s+Officer|CEO"
        r"|Chief\s+Financial\s+Officer|CFO"
        r"|Technical\s+Director"
        r"|Individual\s+Promoter(?:s)?"
        r"|Promoter(?:s)?"
        r"|Promoter\s+Selling\s+Shareholder(?:s)?"
        r"|Selling\s+Shareholder(?:s)?"
        r")\s*[:\-]?\s*",
        regex.IGNORECASE,
    )

    _NAME_PAT = regex.compile(
        r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b"
    )

    def __init__(self) -> None:
        self._nlp = None
        self._nlp_loaded = False

    def _get_nlp(self):
        if not self._nlp_loaded:
            self._nlp_loaded = True
            try:
                import spacy
                self._nlp = spacy.load("en_core_web_sm")
                log.info("spaCy model 'en_core_web_sm' loaded.")
            except Exception as exc:
                log.warning("spaCy NER model not available: %s", exc)
        return self._nlp

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        protected_spans = _get_protected_spans(text)

        # 1. Salutation-prefixed names
        for sal_m in self._SALUTATION.finditer(text):
            nm = self._NAME_PAT.match(text, sal_m.end())
            if nm:
                start = sal_m.start()
                end = nm.end()
                raw = text[start:end].strip()
                if not _overlaps_protected(start, end, protected_spans):
                    results.append(PIIMatch(
                        segment_id=segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.96,
                        source="salutation",
                        context=get_context_snippet(text, start, end),
                    ))

        # 2. Role-context names (e.g. "Company Secretary and Compliance Officer: Sarthak Malvadkar")
        for role_m in self._ROLE_LABELS.finditer(text):
            window_start = role_m.end()
            window = text[window_start: min(len(text), window_start + 180)]
            for nm in self._NAME_PAT.finditer(window):
                start = window_start + nm.start()
                end = window_start + nm.end()
                raw = nm.group(0).strip()
                if not _overlaps_protected(start, end, protected_spans):
                    results.append(PIIMatch(
                        segment_id=segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.94,
                        source="role_context",
                        context=get_context_snippet(text, start, end),
                    ))

        # 3. Filtered spaCy NER (only run if segment contains at least two consecutive capitalized words)
        if regex.search(r"[A-Z][a-z]+\s+[A-Z][a-z]+", text):
            nlp = self._get_nlp()
            if nlp:
                try:
                    doc = nlp(text)
                    for ent in doc.ents:
                        if ent.label_ == "PERSON":
                            start = ent.start_char
                            end = ent.end_char
                            raw = ent.text.strip()
                            words = raw.split()

                            # PERSON must be 2-4 words, properly capitalized
                            if len(words) < 2 or len(words) > 4:
                                continue
                            if not all(w[0].isupper() for w in words if w.isalpha()):
                                continue

                            # Check protected vocabulary overlap
                            if _overlaps_protected(start, end, protected_spans):
                                continue

                            # Reject known false-positive phrases
                            _non_name_tokens = {
                                "Act", "Structure", "Price", "Offer", "Shares", "Process", "Year",
                                "Table", "Section", "Board", "Officer", "Shareholder", "Investor",
                                "Director", "Taluka", "District", "Village", "Road", "Floor", "Building",
                                "Report", "Prospectus", "General", "Information", "Document", "Summary",
                            }
                            if any(w in _non_name_tokens for w in words):
                                continue

                            results.append(PIIMatch(
                                segment_id=segment_id,
                                entity_type=self.entity_type,
                                start=start,
                                end=end,
                                text=raw,
                                confidence=0.88,
                                source="ner",
                                context=get_context_snippet(text, start, end),
                            ))
                except Exception as exc:
                    log.debug("spaCy NER exception on segment '%s': %s", segment_id, exc)

        return results


# ---------------------------------------------------------------------------
# 10. Strict COMPANY Detector (Full Legal Entity Spans Only)
# ---------------------------------------------------------------------------

class CompanyDetector(BaseDetector):
    """
    Strict COMPANY detector.
    Detects full organization names ending in valid legal corporate suffixes.
    Never matches isolated words like 'Limited', 'Company', or 'Bank'.
    Never matches protected legal terminology like 'Companies Act'.
    """

    entity_type = "COMPANY"

    # Matches complete organization spans ending with legal suffix
    _COMPANY_PATTERN = regex.compile(
        r"\b(?:[A-Z][a-zA-Z0-9&'\.\-]+\s+){1,6}"
        r"(?:Private\s+Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?)\b",
        regex.IGNORECASE,
    )

    # Explicit financial institution entities (Banks / BRLMs / Registrars)
    _KNOWN_FINANCIAL_ORGS = regex.compile(
        r"\b(?:"
        r"KSH\s+International\s+(?:Private\s+Limited|Limited)"
        r"|Bhandary\s+Metal\s+Extrusion\s+(?:Private\s+Limited|Limited)"
        r"|Nuvama\s+Wealth\s+Management\s+Limited"
        r"|ICICI\s+Securities\s+Limited"
        r"|HDFC\s+Bank\s+Limited"
        r"|ICICI\s+Bank\s+Limited"
        r"|Citibank\s+N\.?A\.?"
        r"|Export\s+Import\s+Bank\s+of\s+India"
        r"|IndusInd\s+Bank\s+Limited"
        r"|State\s+Bank\s+of\s+India"
        r"|Federal\s+Bank\s+Limited"
        r"|Bajaj\s+Finance\s+Limited"
        r"|Trilegal"
        r"|MUFG\s+Bank(?:\s+Limited)?"
        r"|MUFG\s+Pension\s+&\s+Market\s+Services\s+India\s+Private\s+Limited"
        r")\b",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        if not REDACT_COMPANY_NAMES:
            return []

        results: List[PIIMatch] = []
        protected_spans = _get_protected_spans(text)

        # 1. Known financial institution entities
        for m in self._KNOWN_FINANCIAL_ORGS.finditer(text):
            start = m.start()
            end = m.end()
            raw = m.group(0).strip()
            if not _overlaps_protected(start, end, protected_spans):
                results.append(PIIMatch(
                    segment_id=segment_id,
                    entity_type=self.entity_type,
                    start=start,
                    end=end,
                    text=raw,
                    confidence=0.96,
                    source="known_entity",
                    context=get_context_snippet(text, start, end),
                ))

        # 2. Strict legal suffix corporate patterns
        for m in self._COMPANY_PATTERN.finditer(text):
            start = m.start()
            end = m.end()
            raw = m.group(0).strip()

            # Reject if overlapping with protected vocabulary (e.g. 'Companies Act, 1956')
            if _overlaps_protected(start, end, protected_spans):
                continue

            # Must contain at least 2 words
            words = raw.split()
            if len(words) < 2:
                continue

            # Reject phrases starting with lowercase or non-proper nouns
            if not raw[0].isupper():
                continue

            results.append(PIIMatch(
                segment_id=segment_id,
                entity_type=self.entity_type,
                start=start,
                end=end,
                text=raw,
                confidence=0.91,
                source="regex_suffix",
                context=get_context_snippet(text, start, end),
            ))

        return results


# ---------------------------------------------------------------------------
# Detector Registry
# ---------------------------------------------------------------------------

DETECTORS: List[BaseDetector] = [
    EmailDetector(),
    PhoneDetector(),
    CreditCardDetector(),
    SSNDetector(),
    IPAddressDetector(),
    DOBDetector(),
    AddressDetector(),
    PersonDetector(),
    CompanyDetector(),
    PANDetector(),
    UPIDetector(),
]
