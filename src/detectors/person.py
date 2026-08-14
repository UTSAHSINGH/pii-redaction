"""
person.py
---------
General-Purpose, Multi-Stage PERSON Detector.
Combines:
1. Honorific salutations (Mr., Mrs., Ms., Dr., Prof., Shri, Smt., Sir, Madam)
2. Generic organizational role labels (Contact, Name, Employee, Manager, Director, CEO, etc.)
3. spaCy Named Entity Recognition (NER) filtered against non-name vocabulary
4. Confidence tiering: High confidence (role/salutation) vs Medium confidence (standalone NER)
Zero hardcoded person names.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Set, Tuple
import uuid

import regex

from detectors.base import DetectionContext, PIIDetector, get_context_snippet
from models import ConfidenceTier, DocumentSegment, PIIMatch

log = logging.getLogger("pii_shield")


class PersonDetector(PIIDetector):
    """General-purpose PERSON entity detector."""

    entity_type = "PERSON"

    _SALUTATIONS = regex.compile(
        r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Shri|Smt\.?|Kum\.?|Sir|Madam)\s+",
        regex.IGNORECASE,
    )

    _ROLE_LABELS = regex.compile(
        r"\b(?:"
        r"Contact\s+Person(?:s)?"
        r"|Contact"
        r"|Full\s+Name"
        r"|Name"
        r"|Employee(?:\s+Name)?"
        r"|Customer(?:\s+Name)?"
        r"|Applicant(?:\s+Name)?"
        r"|Candidate(?:\s+Name)?"
        r"|Manager(?:\s+Name)?"
        r"|Managing\s+Director"
        r"|Executive\s+Director"
        r"|Independent\s+Director"
        r"|Director(?:\s+Name)?"
        r"|Chief\s+Executive\s+Officer|CEO"
        r"|Chief\s+Financial\s+Officer|CFO"
        r"|Chief\s+Technology\s+Officer|CTO"
        r"|Company\s+Secretary(?:\s+and\s+Compliance\s+Officer)?"
        r"|Compliance\s+Officer"
        r"|Authorised\s+Signatory"
        r"|Promoter(?:\s+Selling\s+Shareholder)?"
        r"|Selling\s+Shareholder"
        r"|Promoter"
        r"|Partner"
        r"|Proprietor"
        r"|Patient(?:\s+Name)?"
        r"|Physician(?:\s+Name)?"
        r"|Doctor(?:\s+Name)?"
        r"|Client(?:\s+Name)?"
        r"|Representative"
        r"|Officer"
        r"|Author"
        r")\s*[:\-]?\s*",
        regex.IGNORECASE,
    )

    _NAME_PAT = regex.compile(r"\b[A-Z][a-z]+(?:[^\S\r\n]+[A-Z][a-z]+){1,3}\b")

    _FORBIDDEN_NAME_TOKENS = {
        "act", "structure", "price", "offer", "shares", "share", "process", "year",
        "table", "section", "board", "officer", "shareholder", "investor", "director",
        "taluka", "district", "village", "road", "floor", "building", "report", "prospectus",
        "general", "information", "document", "summary", "risk", "factors", "company", "issuer",
        "equity", "fresh", "sale", "working", "promoter", "promoters", "trust", "trusts", "group",
        "auditor", "auditors", "sebi", "icdr", "bse", "nse", "cdsl", "nsdl", "bank", "securities",
        "limited", "private", "llp", "inc", "corp", "corporation", "department", "team", "overview",
        "policy", "agreement", "notice", "circular", "manual", "statement", "index", "schedule",
    }

    def __init__(self) -> None:
        self._nlp = None
        self._nlp_loaded = False

    def _get_nlp(self):
        if not self._nlp_loaded:
            self._nlp_loaded = True
            try:
                import spacy
                self._nlp = spacy.load("en_core_web_sm")
            except Exception as exc:
                log.warning("spaCy NER model not available: %s", exc)
        return self._nlp

    def detect(self, segment: DocumentSegment, context: DetectionContext) -> List[PIIMatch]:
        results: List[PIIMatch] = []
        text = segment.text
        seen_spans: Set[Tuple[int, int]] = set()

        def _is_valid_person_name(name: str, start: int, end: int) -> bool:
            if context.is_protected(text, start, end):
                return False
            words = name.split()
            if len(words) < 2 or len(words) > 4:
                return False
            if any(w.lower() in self._FORBIDDEN_NAME_TOKENS for w in words):
                return False
            return True

        # 1. Salutation-prefixed names (HIGH confidence: 0.98)
        for sal_m in self._SALUTATIONS.finditer(text):
            sal_end = sal_m.end()
            nm = self._NAME_PAT.match(text, sal_end)
            if nm:
                start = sal_m.start()
                raw = text[start:sal_end + len(nm.group(0))].strip()
                end = start + len(raw)
                name_portion = text[sal_end:end].strip()
                if _is_valid_person_name(name_portion, sal_end, end):
                    span = (start, end)
                    if span not in seen_spans:
                        seen_spans.add(span)
                        results.append(PIIMatch(
                            match_id=str(uuid.uuid4()),
                            segment_id=segment.segment_id,
                            entity_type=self.entity_type,
                            start=start,
                            end=end,
                            text=raw,
                            confidence=0.98,
                            confidence_tier=ConfidenceTier.HIGH,
                            source="salutation_prefix",
                            context=get_context_snippet(text, start, end),
                        ))

        # 2. Role-context names (HIGH confidence: 0.96)
        for role_m in self._ROLE_LABELS.finditer(text):
            window_start = role_m.end()
            window = text[window_start: min(len(text), window_start + 120)]
            for nm in self._NAME_PAT.finditer(window):
                raw = nm.group(0).strip()
                start = window_start + nm.start()
                end = start + len(raw)
                if _is_valid_person_name(raw, start, end):
                    span = (start, end)
                    if not any(s <= start and end <= e for s, e in seen_spans):
                        seen_spans.add(span)
                        results.append(PIIMatch(
                            match_id=str(uuid.uuid4()),
                            segment_id=segment.segment_id,
                            entity_type=self.entity_type,
                            start=start,
                            end=end,
                            text=raw,
                            confidence=0.96,
                            confidence_tier=ConfidenceTier.HIGH,
                            source="role_context",
                            context=get_context_snippet(text, start, end),
                        ))

        # 3. Filtered spaCy NER (Candidate Generation, MEDIUM confidence: 0.75)
        # Allows human review without blindly corrupting plain document text
        if regex.search(r"[A-Z][a-z]+\s+[A-Z][a-z]+", text):
            nlp = self._get_nlp()
            if nlp:
                try:
                    doc = nlp(text)
                    for ent in doc.ents:
                        if ent.label_ == "PERSON":
                            raw = ent.text.strip()
                            start = ent.start_char
                            end = start + len(raw)
                            if _is_valid_person_name(raw, start, end):
                                span = (start, end)
                                if not any(s <= start and end <= e for s, e in seen_spans):
                                    seen_spans.add(span)
                                    results.append(PIIMatch(
                                        match_id=str(uuid.uuid4()),
                                        segment_id=segment.segment_id,
                                        entity_type=self.entity_type,
                                        start=start,
                                        end=end,
                                        text=raw,
                                        confidence=0.75,
                                        confidence_tier=ConfidenceTier.MEDIUM,
                                        source="ner_candidate",
                                        context=get_context_snippet(text, start, end),
                                    ))
                except Exception as exc:
                    log.debug("spaCy NER exception on %s: %s", segment.segment_id, exc)

        return results
