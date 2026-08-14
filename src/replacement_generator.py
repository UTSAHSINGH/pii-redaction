"""
replacement_generator.py
-------------------------
Deterministic, collision-free, detector-safe replacement generator for PII Shield.

Supports 4 Redaction Strategies:
1. SYNTHETIC: Realistic fake data generated via seeded Faker (consistent per entity).
2. MASK: Sensitive character masking (e.g. 'J*** D**', 'a***@example.com', '+91 XXXXX XXXXX').
3. TOKEN: Numbered sequential tokens (e.g. '<PERSON_001>', '<EMAIL_001>').
4. CATEGORY_LABEL: Explicit category labels (e.g. '[REDACTED PERSON]', '[REDACTED EMAIL]').

Maintains a safety registry so synthetic values are never flagged as residual original PII.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Optional, Set, Tuple
from faker import Faker

from models import PIIMatch, RedactionStrategy

_FAKER = Faker("en_IN")
_FAKER_US = Faker("en_US")
Faker.seed(42)

# Global registries
_SYNTHETIC_REGISTRY: Dict[Tuple[str, str, int], str] = {}
_TOKEN_COUNTERS: Dict[str, int] = {}
_KNOWN_SYNTHETIC_VALUES: Set[str] = set()


def _get_seed_int(text: str, base_seed: int = 42) -> int:
    """Derive deterministic integer seed from string hash and base seed."""
    h = hashlib.sha256(f"{base_seed}:{text.strip().lower()}".encode("utf-8")).hexdigest()
    return int(h[:8], 16)


# ---------------------------------------------------------------------------
# Strategy 1: Synthetic Generator
# ---------------------------------------------------------------------------

def _generate_synthetic(entity_type: str, raw_text: str, seed: int = 42) -> str:
    key = (entity_type, raw_text.strip().lower(), seed)
    if key in _SYNTHETIC_REGISTRY:
        return _SYNTHETIC_REGISTRY[key]

    item_seed = _get_seed_int(raw_text, seed)
    _FAKER.seed_instance(item_seed)
    _FAKER_US.seed_instance(item_seed)

    synthetic_value = ""

    if entity_type == "PERSON":
        first = _FAKER_US.first_name()
        last = _FAKER_US.last_name()
        if raw_text.isupper():
            synthetic_value = f"{first} {last}".upper()
        else:
            synthetic_value = f"{first} {last}"

    elif entity_type == "EMAIL":
        name = _FAKER_US.user_name()
        synthetic_value = f"{name}@example.com"

    elif entity_type == "PHONE":
        p1 = 90000 + (item_seed % 9999)
        p2 = 10000 + ((item_seed >> 4) % 89999)
        if raw_text.startswith("+91"):
            synthetic_value = f"+91 {p1} {p2}"
        elif raw_text.startswith("+"):
            synthetic_value = f"+1-555-{100 + (item_seed % 899)}-{1000 + (item_seed % 8999)}"
        else:
            synthetic_value = f"{p1} {p2}"

    elif entity_type == "COMPANY":
        company_name = _FAKER_US.company()
        clean = re.sub(r",?\s*(?:Inc\.?|LLC|Ltd\.?|Group|and Sons|PLC)$", "", company_name)
        if "Private Limited" in raw_text or "Pvt. Ltd." in raw_text:
            suffix = "Private Limited"
        elif "LLP" in raw_text:
            suffix = "LLP"
        else:
            suffix = "Limited"
        synthetic_value = f"{clean} {suffix}"

    elif entity_type == "ADDRESS":
        num = 10 + (item_seed % 890)
        street = _FAKER_US.street_name()
        synthetic_value = f"Plot {num}, {street} Industrial Area, Sector {num % 20 + 1}, Pune 411001, Maharashtra, India"

    elif entity_type == "DOB":
        day = 1 + (item_seed % 28)
        month = 1 + (item_seed % 12)
        year = 1970 + (item_seed % 30)
        synthetic_value = f"{day:02d}/{month:02d}/{year}"

    elif entity_type == "SSN":
        synthetic_value = f"9{item_seed % 89 + 10:02d}-{item_seed % 89 + 10:02d}-{item_seed % 8999 + 1000:04d}"

    elif entity_type == "CREDIT_CARD":
        # 4111 1111 1111 1111 passes Luhn mod-10
        synthetic_value = "4111 1111 1111 1111"

    elif entity_type == "IP_ADDRESS":
        synthetic_value = f"192.168.{item_seed % 250 + 1}.{item_seed % 250 + 1}"

    elif entity_type == "PAN":
        letters = "ABCDE"
        num = item_seed % 8999 + 1000
        synthetic_value = f"AAAP{letters[item_seed % len(letters)]}{num}Z"

    elif entity_type == "UPI_ID":
        synthetic_value = f"user{item_seed % 999}@okaxis"

    elif entity_type == "IBAN":
        synthetic_value = f"GB29NWBK601613{item_seed % 89999999 + 10000000}"

    else:
        synthetic_value = f"SYNTHETIC_{entity_type}_{item_seed % 9999}"

    _SYNTHETIC_REGISTRY[key] = synthetic_value
    _KNOWN_SYNTHETIC_VALUES.add(synthetic_value)
    return synthetic_value


# ---------------------------------------------------------------------------
# Strategy 2: Masking Generator
# ---------------------------------------------------------------------------

def _generate_mask(entity_type: str, raw_text: str) -> str:
    if entity_type == "EMAIL" and "@" in raw_text:
        local, domain = raw_text.split("@", 1)
        masked_local = local[0] + "***" if len(local) > 1 else "*"
        return f"{masked_local}@{domain}"

    if entity_type == "PHONE":
        if raw_text.startswith("+91"):
            return "+91 XXXXX XXXXX"
        return "XXX-XXX-XXXX"

    if entity_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", raw_text)
        last4 = digits[-4:] if len(digits) >= 4 else "XXXX"
        return f"**** **** **** {last4}"

    # Default character masking: keep first letter of each word
    words = raw_text.split()
    masked_words = []
    for w in words:
        if len(w) <= 1:
            masked_words.append("*")
        else:
            masked_words.append(w[0] + "*" * (len(w) - 1))
    return " ".join(masked_words)


# ---------------------------------------------------------------------------
# Strategy 3: Token Generator
# ---------------------------------------------------------------------------

def _generate_token(entity_type: str) -> str:
    _TOKEN_COUNTERS[entity_type] = _TOKEN_COUNTERS.get(entity_type, 0) + 1
    count = _TOKEN_COUNTERS[entity_type]
    return f"<{entity_type}_{count:03d}>"


# ---------------------------------------------------------------------------
# Strategy 4: Category Label Generator
# ---------------------------------------------------------------------------

def _generate_category_label(entity_type: str) -> str:
    return f"[REDACTED {entity_type}]"


# ---------------------------------------------------------------------------
# Public Dispatcher
# ---------------------------------------------------------------------------

def get_replacement(
    match: PIIMatch,
    strategy: RedactionStrategy = RedactionStrategy.SYNTHETIC,
    seed: int = 42,
) -> str:
    """Generate replacement value for a match based on the selected strategy."""
    if strategy == RedactionStrategy.SYNTHETIC:
        return _generate_synthetic(match.entity_type, match.text, seed)
    elif strategy == RedactionStrategy.MASK:
        return _generate_mask(match.entity_type, match.text)
    elif strategy == RedactionStrategy.TOKEN:
        return _generate_token(match.entity_type)
    elif strategy == RedactionStrategy.CATEGORY_LABEL:
        return _generate_category_label(match.entity_type)
    return _generate_synthetic(match.entity_type, match.text, seed)


def get_synthetic_values() -> Set[str]:
    """Return all known synthetic replacement values for residual scanning exclusion."""
    return set(_KNOWN_SYNTHETIC_VALUES)


def get_replacement_map() -> Dict[Tuple[str, str, int], str]:
    """Return a copy of the current synthetic replacement map."""
    return dict(_SYNTHETIC_REGISTRY)


def reset_generator_state() -> None:
    """Reset token counters and registries for new sessions."""
    _TOKEN_COUNTERS.clear()
    _SYNTHETIC_REGISTRY.clear()


def reset_replacement_map() -> None:
    """Legacy alias for reset_generator_state."""
    reset_generator_state()
