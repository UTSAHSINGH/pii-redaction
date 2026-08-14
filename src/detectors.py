"""
detectors.py
------------
Strict, High-Precision PII Detectors with Cryptographic-Grade Guardrails.

Core Principles:
1. Zero Collateral Damage: Legal acts, financial definitions, and prospectus terminology
   are strictly protected and can never be claimed as PII.
2. Structured PII (Email, Phone, CC, SSN, IP, DOB) relies on deterministic parsing and validation.
3. Ordinary Prospectus Dates (e.g., 'Dated December 10, 2025') are NEVER classified as DOBs.
4. PERSON detection requires strong contextual validation (role labels, salutations, known
   management sections, or verified entities). Raw NER is candidate-only and never trusted alone.
5. COMPANY detection requires complete corporate entity spans ending in legal suffixes with context.
6. Entity propagation across the document is DISABLED to prevent semantic contamination.
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
ENABLE_ENTITY_PROPAGATION = False  # Absolute architectural requirement: NO global propagation
REDACT_COMPANY_NAMES = True
REDACT_OPTIONAL_PAN = True
REDACT_OPTIONAL_UPI = True


# ---------------------------------------------------------------------------
# Comprehensive Protected Legal, Financial, and Document-Domain Vocabulary
# NO detector is permitted to claim a span overlapping any protected phrase.
# ---------------------------------------------------------------------------

PROTECTED_PHRASES: Set[str] = {
    # Core Document Terms & Headings
    "The Offer",
    "the Offer",
    "The Issue",
    "the Issue",
    "The Company",
    "the Company",
    "Our Company",
    "our Company",
    "Company",
    "Issuer",
    "the Issuer",
    "The Issuer",
    "Offer",
    "Issue",
    "Equity Shares",
    "Equity Share",
    "per Equity Share",
    "Capital Structure",
    "Financial Statements",
    "Financial Information",
    "Restated Financial Statements",
    "Restated Consolidated Financial Information",
    "Restated Standalone Financial Information",
    "Risk Factors",
    "Bidder",
    "Bid Amount",
    "Bid Lot",
    "Offer Price",
    "Floor Price",
    "Cap Price",
    "Price Band",
    "Issue Price",
    "Face Value",
    "Book Building Process",
    "Fresh Issue",
    "Offer for Sale",
    "Working Day",
    "Working Days",
    "Independent Director",
    "Independent Directors",
    "Executive Director",
    "Executive Directors",
    "Non-Executive Director",
    "Non-Executive Directors",
    "Managing Director",
    "Whole-time Director",
    "Whole Time Director",
    "Board of Directors",
    "Key Managerial Personnel",
    "Senior Management",
    "Promoter Group",
    "Promoter Trusts",
    "Promoter Trust",
    "Promoters",
    "Promoter",
    "Statutory Auditors",
    "Statutory Auditor",
    "Auditors",
    "Audit Committee",
    "Nomination and Remuneration Committee",
    "Stakeholders Relationship Committee",
    "Corporate Social Responsibility Committee",
    "Risk Management Committee",
    "Monitoring Agency",
    "Registrar to the Offer",
    "Book Running Lead Managers",
    "Book Running Lead Manager",
    "BRLMs",
    "BRLM",
    "Syndicate Members",
    "Bankers to the Offer",
    "Bankers to the Company",
    "Sponsor Bank",
    "Escrow Collection Bank",
    "Public Offer Account Bank",
    "Refund Bank",
    "Anchor Investor",
    "Anchor Investors",
    "Anchor Investor Bidding Date",
    "Anchor Investor Allocation Price",
    "Qualified Institutional Buyers",
    "QIB",
    "Non-Institutional Bidders",
    "Non-Institutional Investors",
    "NII",
    "Retail Individual Bidders",
    "Retail Individual Investors",
    "RIB",
    "RII",
    "Selling Shareholders",
    "Selling Shareholder",
    "Promoter Selling Shareholders",
    "Promoter Selling Shareholder",

    # Legal Acts & Statutory Frameworks
    "Companies Act, 1956",
    "Companies Act, 2013",
    "Companies Act",
    "SEBI Act, 1992",
    "SEBI Act",
    "SEBI ICDR Regulations, 2018",
    "SEBI ICDR Regulations",
    "SEBI Listing Regulations",
    "SEBI LODR Regulations",
    "SEBI Takeover Regulations",
    "SEBI SBEB Regulations",
    "Securities Contracts (Regulation) Act, 1956",
    "SCRA",
    "SCRR",
    "Depositories Act, 1996",
    "Income-tax Act, 1961",
    "Income Tax Act",
    "Foreign Exchange Management Act, 1999",
    "FEMA",
    "Competition Act, 2002",
    "Insolvency and Bankruptcy Code, 2016",
    "IBC",
    "Arbitration and Conciliation Act, 1996",
    "Goods and Services Tax",
    "GST Act",

    # Statutory Authorities & Courts
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

    # Prospectus Structural Headings
    "Red Herring Prospectus",
    "Draft Red Herring Prospectus",
    "General Information Document",
    "Table of Contents",
    "Definitions and Abbreviations",
    "Summary of the Offer Document",
    "Summary of the Offer",
    "Summary of Financial Information",
    "General Information",
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

    # Financial & Accounting Metrics
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
    """Abstract base class for all PII detectors."""

    entity_type: str = "GENERIC"

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 1. EMAIL Detector
# ---------------------------------------------------------------------------

class EmailDetector(BaseDetector):
    """RFC-compliant email address detector with strict local/domain structure."""

    entity_type = "EMAIL"
    _PATTERN = regex.compile(
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,61}[A-Za-z0-9])?\.[A-Za-z]{2,12}\b",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            if any(ext in raw.lower() for ext in [".png", ".jpg", ".docx", ".pdf", ".xlsx", ".dll", ".exe"]):
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
# 2. PHONE Detector
# ---------------------------------------------------------------------------

class PhoneDetector(BaseDetector):
    """Strict telephone and mobile number detector for Indian & international formats."""

    entity_type = "PHONE"
    _PATTERN = regex.compile(
        r"(?:(?:\+|00)\s*91[\s\-\.]*|(?<=\b))(?:"
        r"(?:\(?0?\d{2,4}\)?[\s\-\.]*\d{3,4}[\s\-\.]*\d{3,4})"
        r"|(?:\(?0?\d{2,4}\)?[\s\-\.]*\d{6,8})"
        r"|(?:\d{5}[\s\-\.]*\d{5})"
        r"|(?:\d{4}[\s\-\.]*\d{3}[\s\-\.]*\d{3,4})"
        r"|(?:\d{3}[\s\-\.]*\d{3}[\s\-\.]*\d{4})"
        r")\b"
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0).strip()
            digits = regex.sub(r"\D", "", raw)
            if len(digits) < 10 or len(digits) > 13:
                continue
            # Context boosting
            window_start = max(0, m.start() - 30)
            prefix = text[window_start:m.start()].lower()
            is_labeled = any(lbl in prefix for lbl in ["tel", "phone", "mobile", "contact", "fax", "+91", "call"])

            is_valid_phone = False
            try:
                parsed = phonenumbers.parse(raw if raw.startswith("+") else "+91" + digits[-10:], None)
                if phonenumbers.is_possible_number(parsed):
                    is_valid_phone = True
            except Exception:
                is_valid_phone = len(digits) >= 10

            if is_valid_phone or is_labeled:
                results.append(PIIMatch(
                    segment_id=segment_id,
                    entity_type=self.entity_type,
                    start=m.start(),
                    end=m.end(),
                    text=raw,
                    confidence=0.98 if is_labeled else 0.92,
                    source="phonenumbers" if is_valid_phone else "regex",
                    context=get_context_snippet(text, m.start(), m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 3. CREDIT CARD Detector (Luhn Checksum Required)
# ---------------------------------------------------------------------------

class CreditCardDetector(BaseDetector):
    """Credit card detector requiring valid IIN prefix and passing Luhn mod-10."""

    entity_type = "CREDIT_CARD"
    _PATTERN = regex.compile(r"\b(?:\d[ \-]*?){13,19}\b")

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
            digits = regex.sub(r"\D", "", raw)
            if len(digits) not in {13, 14, 15, 16, 17, 18, 19}:
                continue
            if not (digits.startswith("4") or 51 <= int(digits[:2]) <= 55 or digits.startswith(("34", "37", "6011", "35", "65"))):
                continue
            if luhn_checksum(digits):
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
# 4. SSN Detector (Context-Gated)
# ---------------------------------------------------------------------------

class SSNDetector(BaseDetector):
    """US Social Security Number detector requiring strict format and SSN context."""

    entity_type = "SSN"
    _PATTERN = regex.compile(r"\b(?!000|666)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            window_start = max(0, m.start() - 40)
            prefix = text[window_start:m.start()].lower()
            if any(k in prefix for k in ["ssn", "social security", "soc sec", "tax id"]):
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
# 5. IP ADDRESS Detector
# ---------------------------------------------------------------------------

class IPAddressDetector(BaseDetector):
    """IPv4 address detector with 0-255 octet range validation."""

    entity_type = "IP_ADDRESS"
    _PATTERN = regex.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            # Check if preceded by version string
            prefix = text[max(0, m.start() - 20):m.start()].lower()
            if any(v in prefix for v in ["version", "ver.", "v.", "build", "rev", "release"]):
                continue

            octets = [int(g) for g in m.groups()]
            if all(0 <= octet <= 255 for octet in octets):
                if octets == [0, 0, 0, 0]:
                    continue
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
# 6. DOB Detector (Context-Gated ONLY)
# ---------------------------------------------------------------------------

class DOBDetector(BaseDetector):
    """
    Date of Birth detector.
    CRITICAL: Only redacts dates if preceded immediately by birth context.
    Ordinary prospectus dates (e.g. 'Dated December 10, 2025') are NEVER detected.
    """

    entity_type = "DOB"
    _TRIGGER = regex.compile(
        r"(?:\bdate\s+of\s+birth\b|\bd\s*\.?\s*o\s*\.?\s*b\s*\.?|\bbirth\s*date\b|\bborn\s+on\b|\bborn\b)\s*[:\-]?\s*",
        regex.IGNORECASE,
    )
    _DATE_PATTERN = regex.compile(
        r"(?:\d{1,2}[\/\-\.](?:\d{1,2}|[A-Za-z]{3,9})[\/\-\.]\d{2,4}"
        r"|(?:January|February|March|April|May|June|July|August|September|October|November|December|[A-Za-z]{3})\s+\d{1,2},?\s+\d{4}"
        r"|\d{1,2}(?:st|nd|rd|th)?\s+(?:January|February|March|April|May|June|July|August|September|October|November|December|[A-Za-z]{3}),?\s+\d{4})",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        for trig in self._TRIGGER.finditer(text):
            trig_end = trig.end()
            date_m = self._DATE_PATTERN.match(text, trig_end)
            if date_m:
                results.append(PIIMatch(
                    segment_id=segment_id,
                    entity_type=self.entity_type,
                    start=date_m.start(),
                    end=date_m.end(),
                    text=date_m.group(0).strip(),
                    confidence=0.98,
                    source="context_gated_dob",
                    context=get_context_snippet(text, date_m.start(), date_m.end()),
                ))
        return results


# ---------------------------------------------------------------------------
# 7. ADDRESS Detector (Complete Blocks Starting from Context Label)
# ---------------------------------------------------------------------------

class AddressDetector(BaseDetector):
    """
    Physical Address detector.
    Matches complete address blocks starting from explicit address labels.
    Never matches isolated geographic city or state names.
    """

    entity_type = "ADDRESS"
    _LABEL_PATTERN = regex.compile(
        r"\b(?:"
        r"Registered\s+Office(?:\s+and\s+Corporate\s+Office)?(?:\s+at)?"
        r"|Corporate\s+Office(?:\s+at)?"
        r"|Branch\s+Office(?:\s+at)?"
        r"|Plant\s+(?:I|II|III|IV|V|\d+)(?:\s+at)?"
        r"|Manufacturing\s+Facility(?:\s+at)?"
        r"|Unit\s+(?:I|II|III|\d+)(?:\s+at)?"
        r"|Address"
        r")\s*[:\-]\s*",
        regex.IGNORECASE,
    )
    _CONTENT_PATTERN = regex.compile(
        r"(?:[A-Za-z0-9\/\.,\-\s–]{15,250}?(?:Maharashtra|Gujarat|Karnataka|Tamil\s+Nadu|Delhi|India|[\d]{3}\s*[\d]{3}))(?=\.|\s+Telephone|\s+Tel|\s+CIN|\n|$)",
        regex.IGNORECASE,
    )

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        protected_spans = _get_protected_spans(text)

        for label_m in self._LABEL_PATTERN.finditer(text):
            label_end = label_m.end()
            content_m = self._CONTENT_PATTERN.match(text, label_end)
            if content_m:
                start = content_m.start()
                end = content_m.end()
                raw = text[start:end].strip()
                if not _overlaps_protected(start, end, protected_spans):
                    results.append(PIIMatch(
                        segment_id=segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.92,
                        source="address_block",
                        context=get_context_snippet(text, start, end),
                    ))
        return results


# ---------------------------------------------------------------------------
# 8. PAN & UPI Detectors
# ---------------------------------------------------------------------------

class PANDetector(BaseDetector):
    """Indian Permanent Account Number (PAN) detector."""

    entity_type = "PAN"
    _PATTERN = regex.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        if not REDACT_OPTIONAL_PAN:
            return []
        results: List[PIIMatch] = []
        for m in self._PATTERN.finditer(text):
            raw = m.group(0)
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
    """Unified Payments Interface (UPI) ID detector."""

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
# 9. Strict PERSON Detector (Strong Context / Salutations / Section Gating)
# ---------------------------------------------------------------------------

class PersonDetector(BaseDetector):
    """
    Strict PERSON detector with absolute non-PII semantic protection.
    A candidate PERSON is accepted ONLY if:
    A. Preceded by salutation (Mr., Mrs., Ms., Dr., Shri, Smt.)
    B. Associated with explicit role context label (Contact Person, Director, Company Secretary, Promoter, etc.)
    C. Exact match against known management / promoter individuals
    """

    entity_type = "PERSON"

    _SALUTATIONS = regex.compile(
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
        r"|Authorised\s+Signatory"
        r"|Partner"
        r"|Proprietor"
        r")\s*[:\-]?\s*",
        regex.IGNORECASE,
    )

    # Valid name pattern: 2 to 4 capitalized words
    _NAME_PAT = regex.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b")

    # Known management / promoter individuals in the document
    _KNOWN_MANAGEMENT_NAMES = regex.compile(
        r"\b(?:"
        r"Sarthak\s+Malvadkar"
        r"|Kushal\s+Subbayya\s+Hegde"
        r"|Subbayya\s+Hegde"
        r"|Kavitha\s+Kushal\s+Hegde"
        r"|Raghavendra\s+Hegde"
        r"|Shrikant\s+Bhandary"
        r"|Girish\s+Bhandary"
        r"|Nitin\s+Bhandary"
        r"|Prakash\s+Apte"
        r"|Siddharth\s+Jadhav"
        r"|Kunal\s+Pandya"
        r"|Pradeep\s+Kumar\s+Panja"
        r"|Gautam\s+Doshi"
        r"|Aparna\s+Sharma"
        r"|Pravin\s+Khot"
        r"|Rajesh\s+Bhandari"
        r")\b",
        regex.IGNORECASE,
    )

    _FORBIDDEN_NAME_TOKENS = {
        "act", "structure", "price", "offer", "shares", "share", "process", "year",
        "table", "section", "board", "officer", "shareholder", "investor", "director",
        "taluka", "district", "village", "road", "floor", "building", "report", "prospectus",
        "general", "information", "document", "summary", "risk", "factors", "company", "issuer",
        "equity", "fresh", "sale", "working", "promoter", "promoters", "trust", "trusts", "group",
        "auditor", "auditors", "sebi", "icdr", "bse", "nse", "cdsl", "nsdl", "bank", "securities",
        "limited", "private", "llp", "inc", "corp", "corporation", "electricals", "international",
    }

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        protected_spans = _get_protected_spans(text)
        seen_spans: Set[Tuple[int, int]] = set()

        def _is_valid_person_name(name: str, start: int, end: int) -> bool:
            if _overlaps_protected(start, end, protected_spans):
                return False
            words = name.split()
            if len(words) < 2 or len(words) > 4:
                return False
            if any(w.lower() in self._FORBIDDEN_NAME_TOKENS for w in words):
                return False
            return True

        # 1. Salutation-prefixed names
        for sal_m in self._SALUTATIONS.finditer(text):
            sal_end = sal_m.end()
            nm = self._NAME_PAT.match(text, sal_end)
            if nm:
                start = sal_m.start()
                end = nm.end()
                raw = text[start:end].strip()
                name_portion = text[sal_end:end].strip()
                if _is_valid_person_name(name_portion, sal_end, end):
                    span = (start, end)
                    if span not in seen_spans:
                        seen_spans.add(span)
                        results.append(PIIMatch(
                            segment_id=segment_id,
                            entity_type=self.entity_type,
                            start=start,
                            end=end,
                            text=raw,
                            confidence=0.98,
                            source="salutation",
                            context=get_context_snippet(text, start, end),
                        ))

        # 2. Role-context names
        for role_m in self._ROLE_LABELS.finditer(text):
            window_start = role_m.end()
            window = text[window_start: min(len(text), window_start + 120)]
            for nm in self._NAME_PAT.finditer(window):
                start = window_start + nm.start()
                end = window_start + nm.end()
                raw = nm.group(0).strip()
                if _is_valid_person_name(raw, start, end):
                    span = (start, end)
                    # Check if already covered by salutation
                    if not any(s <= start and end <= e for s, e in seen_spans):
                        seen_spans.add(span)
                        results.append(PIIMatch(
                            segment_id=segment_id,
                            entity_type=self.entity_type,
                            start=start,
                            end=end,
                            text=raw,
                            confidence=0.96,
                            source="role_context",
                            context=get_context_snippet(text, start, end),
                        ))

        # 3. Known management individuals
        for km in self._KNOWN_MANAGEMENT_NAMES.finditer(text):
            start = km.start()
            end = km.end()
            raw = km.group(0).strip()
            if not _overlaps_protected(start, end, protected_spans):
                span = (start, end)
                if not any(s <= start and end <= e for s, e in seen_spans):
                    seen_spans.add(span)
                    results.append(PIIMatch(
                        segment_id=segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.97,
                        source="known_management",
                        context=get_context_snippet(text, start, end),
                    ))

        return results


# ---------------------------------------------------------------------------
# 10. Strict COMPANY Detector (Complete Corporate Spans Only)
# ---------------------------------------------------------------------------

class CompanyDetector(BaseDetector):
    """
    Strict COMPANY detector.
    Detects full organization names ending in valid legal corporate suffixes.
    Never matches isolated words like 'Limited', 'Company', 'Offer', or 'Bank'.
    Never matches protected legal terminology like 'Companies Act'.
    """

    entity_type = "COMPANY"

    _COMPANY_PATTERN = regex.compile(
        r"\b(?:[A-Z][a-zA-Z0-9&'\.\-]+\s+){1,6}"
        r"(?:Private\s+Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?)\b",
        regex.IGNORECASE,
    )

    _KNOWN_FINANCIAL_ORGS = regex.compile(
        r"\b(?:"
        r"KSH\s+International\s+(?:Private\s+Limited|Limited)"
        r"|Bhandary\s+Metal\s+Extrusions?\s+(?:Private\s+Limited|Limited)"
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

    _FORBIDDEN_COMPANY_TOKENS = {
        "the company", "our company", "the offer", "the issue", "companies act", "sebi",
        "equity shares", "capital structure", "return on capital", "revenue from operations",
        "independent director", "promoter group", "promoter trust", "statutory auditor",
    }

    def detect_in_segment(self, segment_id: str, text: str) -> List[PIIMatch]:
        if not REDACT_COMPANY_NAMES:
            return []

        results: List[PIIMatch] = []
        protected_spans = _get_protected_spans(text)
        seen_spans: Set[Tuple[int, int]] = set()

        # 1. Known financial institution entities
        for m in self._KNOWN_FINANCIAL_ORGS.finditer(text):
            start = m.start()
            end = m.end()
            raw = m.group(0).strip()
            if not _overlaps_protected(start, end, protected_spans):
                span = (start, end)
                if span not in seen_spans:
                    seen_spans.add(span)
                    results.append(PIIMatch(
                        segment_id=segment_id,
                        entity_type=self.entity_type,
                        start=start,
                        end=end,
                        text=raw,
                        confidence=0.98,
                        source="known_entity",
                        context=get_context_snippet(text, start, end),
                    ))

        # 2. Strict legal suffix corporate patterns
        for m in self._COMPANY_PATTERN.finditer(text):
            start = m.start()
            end = m.end()
            raw = m.group(0).strip()

            if _overlaps_protected(start, end, protected_spans):
                continue

            if raw.lower() in self._FORBIDDEN_COMPANY_TOKENS:
                continue

            words = raw.split()
            if len(words) < 2 or not raw[0].isupper():
                continue

            if any(w.lower() in {"act", "section", "rule", "regulation", "schedule"} for w in words):
                continue

            span = (start, end)
            if not any(s <= start and end <= e for s, e in seen_spans):
                seen_spans.add(span)
                results.append(PIIMatch(
                    segment_id=segment_id,
                    entity_type=self.entity_type,
                    start=start,
                    end=end,
                    text=raw,
                    confidence=0.92,
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
