"""
domain_packs.py
---------------
Configurable domain protected vocabulary packs for PII Shield.
Prevents false-positive redaction of standard legal, financial, healthcare,
and corporate terminology without hardcoding document-specific names.
"""

from __future__ import annotations

from typing import Dict, List, Set
import regex

# ---------------------------------------------------------------------------
# Domain Vocabulary Definitions
# ---------------------------------------------------------------------------

DOMAIN_PACKS: Dict[str, Set[str]] = {
    "generic": {
        "Terms and Conditions",
        "Privacy Policy",
        "User Agreement",
        "Table of Contents",
        "Executive Summary",
        "Introduction",
        "Appendix",
        "Customer Support",
        "General Information",
        "Frequently Asked Questions",
        "FAQ",
        "Overview",
        "Summary",
        "Conclusion",
        "Contact Information",
        "All Rights Reserved",
        "Confidential",
    },
    "legal": {
        "Companies Act",
        "Companies Act, 1956",
        "Companies Act, 2013",
        "Securities and Exchange Board of India",
        "SEBI Act",
        "SEBI Act, 1992",
        "SEBI ICDR Regulations",
        "SEBI LODR Regulations",
        "SEBI Listing Regulations",
        "Depositories Act, 1996",
        "Income-tax Act, 1961",
        "Income Tax Act",
        "Foreign Exchange Management Act, 1999",
        "FEMA",
        "Insolvency and Bankruptcy Code, 2016",
        "IBC",
        "Competition Act, 2002",
        "High Court",
        "Supreme Court",
        "National Company Law Tribunal",
        "NCLT",
        "Registrar of Companies",
        "ROC",
        "Ministry of Corporate Affairs",
        "MCA",
        "Articles of Association",
        "Memorandum of Association",
        "Non-Disclosure Agreement",
        "Power of Attorney",
        "Independent Director",
        "Executive Director",
        "Managing Director",
        "Board of Directors",
        "Audit Committee",
        "Arbitration and Conciliation Act",
    },
    "finance": {
        "Revenue from Operations",
        "Return on Capital Employed",
        "ROCE",
        "Return on Net Worth",
        "RONW",
        "Return on Equity",
        "ROE",
        "Earnings Per Share",
        "EPS",
        "Basic EPS",
        "Diluted EPS",
        "Net Asset Value",
        "NAV",
        "EBITDA",
        "Adjusted EBITDA",
        "Profit After Tax",
        "PAT",
        "Profit Before Tax",
        "PBT",
        "Price to Earnings Ratio",
        "P/E Ratio",
        "Capital Structure",
        "Financial Statements",
        "Financial Information",
        "Restated Financial Statements",
        "Financial Year",
        "Fiscal Year",
        "Cash Flow Statement",
        "Balance Sheet",
        "Profit and Loss",
        "The Offer",
        "Offer for Sale",
        "Fresh Issue",
        "Equity Shares",
        "Face Value",
        "Offer Price",
        "Floor Price",
        "Cap Price",
        "Price Band",
        "Book Building Process",
        "Qualified Institutional Buyers",
        "QIB",
        "Anchor Investor",
        "Non-Institutional Bidders",
        "Retail Individual Bidders",
        "Statutory Auditors",
        "Book Running Lead Manager",
        "BRLM",
    },
    "healthcare": {
        "Medical History",
        "Clinical Summary",
        "Electronic Health Record",
        "EHR",
        "Treatment Plan",
        "Discharge Summary",
        "Patient Intake",
        "Emergency Contact",
        "Prescription Information",
        "Diagnostic Report",
        "Laboratory Findings",
        "Vital Signs",
        "Insurance Provider",
        "Policy Number",
        "Chief Complaint",
    },
}


def get_combined_protected_phrases(enabled_packs: List[str], custom_terms: List[str] = None) -> Set[str]:
    """Combine phrases from selected domain packs along with any user custom terms."""
    combined = set()
    for pack in enabled_packs:
        if pack in DOMAIN_PACKS:
            combined.update(DOMAIN_PACKS[pack])
    if custom_terms:
        combined.update(custom_terms)
    return combined


def build_protected_regex(phrases: Set[str]) -> regex.Pattern:
    """Compile optimized regex pattern from protected phrases."""
    if not phrases:
        return regex.compile(r"(?!)")  # Matches nothing
    sorted_phrases = sorted(phrases, key=len, reverse=True)
    pattern = r"\b(?:" + "|".join(regex.escape(p) for p in sorted_phrases) + r")\b"
    return regex.compile(pattern, regex.IGNORECASE)
