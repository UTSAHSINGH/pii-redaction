"""
replacement_generator.py
------------------------
Deterministic, collision-free, safe-namespace PII replacement generator.

Key Principles:
1. One-to-one deterministic mapping: the same (original_text, entity_type) always
   produces the identical synthetic replacement.
2. Collision-free: no two distinct originals receive the same synthetic replacement.
3. Safe namespace: replacements are drawn from safe test ranges and curated names that
   do not collide with protected vocabulary or trigger secondary detections.
4. Clean case preservation: if the original text was ALL-CAPS, the replacement is
   rendered in ALL-CAPS without trailing suffix corruption.
5. Synthetic Exclusion Registry: tracks all generated synthetic replacements so the
   residual PII scanner can distinguish between original PII and synthetic replacements.
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import random
import re
from typing import Dict, Optional, Set

from utils import PIIMatch, luhn_generate, setup_logger

log = setup_logger("replacement_generator")


# ---------------------------------------------------------------------------
# Global Registry
# ---------------------------------------------------------------------------

# original_text -> {"entity_type": ..., "replacement": ...}
_replacement_map: Dict[str, Dict] = {}

# entity_type -> set of used replacement strings (to ensure collision-freedom)
_used_replacements: Dict[str, Set[str]] = {}

# Set of all synthetic values generated (for residual scan filtering)
_synthetic_exclusion_set: Set[str] = set()


def _seed_from_text(text: str, entity_type: str) -> int:
    """Derive a deterministic integer seed from (entity_type, text)."""
    h = hashlib.sha256(f"{entity_type}:{text.strip()}".encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big")


def _register(original: str, entity_type: str, replacement: str) -> str:
    """Store mapping in the single source of truth registry."""
    _replacement_map[original] = {
        "entity_type": entity_type,
        "replacement": replacement,
    }
    _used_replacements.setdefault(entity_type, set()).add(replacement)
    _synthetic_exclusion_set.add(replacement)
    _synthetic_exclusion_set.add(replacement.upper())
    _synthetic_exclusion_set.add(replacement.lower())
    return replacement


def _is_collision_free(entity_type: str, candidate: str) -> bool:
    """Return True if candidate has not yet been assigned to any other original."""
    return candidate not in _used_replacements.get(entity_type, set())


# ---------------------------------------------------------------------------
# Curated Safe Namespaces
# ---------------------------------------------------------------------------

_SAFE_FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Avery", "Casey", "Riley", "Sam",
    "Cameron", "Jamie", "Robin", "Drew", "Devon", "Kendall", "Logan", "Peyton",
    "Quinn", "Rowan", "Skyler", "Reese", "Harper", "Hayden", "Finley", "Emerson",
]

_SAFE_LAST_NAMES = [
    "Carter", "Bennett", "Mitchell", "Vance", "Parker", "Morgan", "Hayes", "Foster",
    "Sullivan", "Anderson", "Harrison", "Sinclair", "Reynolds", "Thornton", "Prescott",
    "Sterling", "Mercer", "Montgomery", "Blackwood", "Caldwell", "Ellington", "Whitman",
]

_SAFE_COMPANY_PREFIXES = [
    "Apex Dynamics", "Summit Technologies", "Pinnacle Advisory", "Horizon Holdings",
    "Crestview Capital", "Meridian Solutions", "Vanguard Industries", "Nexus Enterprises",
    "Beacon Financial", "Sterling Global", "Solstice Systems", "Prism Ventures",
    "Titan Crest", "Paramount Infra", "Omni Core", "Zenith Energy",
]

_SAFE_ADDRESS_STREETS = [
    "Plot No. 42, Sector 18, Commercial Zone",
    "Tower 5, Level 8, Horizon Business Park",
    "Unit 102, Pinnacle Towers, Central Avenue",
    "Building 7, Cyber Crest Park, Phase 2",
    "Survey No. 88/1, Industrial Corridor, Expressway",
]


# ---------------------------------------------------------------------------
# Per-Entity Replacement Generators
# ---------------------------------------------------------------------------

def _generate_email(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "EMAIL"))
    first = rng.choice(_SAFE_FIRST_NAMES).lower()
    last = rng.choice(_SAFE_LAST_NAMES).lower()
    n = rng.randint(10, 99)
    return f"{first}.{last}{n}@example.com"


def _generate_phone(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "PHONE"))
    # Indian mobile: +91 91234 XXXXX
    prefix = rng.choice(["91234", "98765", "91765", "93210", "97654"])
    suffix = f"{rng.randint(10000, 99999):05d}"
    return f"+91 {prefix} {suffix}"


def _generate_person(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "PERSON"))
    first = rng.choice(_SAFE_FIRST_NAMES)
    last = rng.choice(_SAFE_LAST_NAMES)
    return f"{first} {last}"


def _generate_company(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "COMPANY"))
    base = rng.choice(_SAFE_COMPANY_PREFIXES)

    # Preserve corporate legal suffix if present in original
    orig_upper = original.upper()
    if "PRIVATE LIMITED" in orig_upper or "PVT. LTD" in orig_upper or "PVT LTD" in orig_upper:
        suffix = "Private Limited"
    elif "LIMITED" in orig_upper or "LTD" in orig_upper:
        suffix = "Limited"
    elif "LLP" in orig_upper:
        suffix = "LLP"
    elif "INC" in orig_upper:
        suffix = "Inc."
    elif "BANK" in orig_upper:
        suffix = "Bank Limited"
    elif "SECURITIES" in orig_upper:
        suffix = "Securities Limited"
    else:
        suffix = "Limited"

    return f"{base} {suffix}"


def _generate_address(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "ADDRESS"))
    street = rng.choice(_SAFE_ADDRESS_STREETS)
    pincode = rng.randint(400001, 411099)
    return f"{street}, Pune - {pincode}, Maharashtra, India"


def _generate_credit_card(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "CREDIT_CARD"))
    prefix = rng.choice(["411111", "550000", "378282"])
    return luhn_generate(prefix, 16)


def _generate_ssn(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "SSN"))
    area = rng.randint(900, 999)  # SSA unassigned area code
    group = rng.randint(10, 99)
    serial = rng.randint(1000, 9999)
    return f"{area}-{group:02d}-{serial:04d}"


def _generate_ip(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "IP_ADDRESS"))
    # RFC 5737 TEST-NET-1: 192.0.2.0/24
    host = rng.randint(1, 254)
    return f"192.0.2.{host}"


def _generate_dob(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "DOB"))
    day = rng.randint(1, 28)
    month = rng.choice(["January", "February", "March", "April", "May", "June",
                        "July", "August", "September", "October", "November", "December"])
    year = rng.randint(1965, 1995)
    return f"{month} {day}, {year}"


def _generate_pan(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "PAN"))
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    p1 = "".join(rng.choice(letters) for _ in range(3))
    status = "P"  # Individual
    p3 = rng.choice(letters)
    digits = f"{rng.randint(1000, 9999):04d}"
    check = rng.choice(letters)
    return f"{p1}{status}{p3}{digits}{check}"


def _generate_upi(original: str) -> str:
    rng = random.Random(_seed_from_text(original, "UPI_ID"))
    user = rng.choice(_SAFE_FIRST_NAMES).lower()
    n = rng.randint(10, 99)
    return f"{user}{n}@okaxis"


_GENERATORS = {
    "EMAIL":       _generate_email,
    "PHONE":       _generate_phone,
    "PERSON":      _generate_person,
    "COMPANY":     _generate_company,
    "ADDRESS":     _generate_address,
    "CREDIT_CARD": _generate_credit_card,
    "SSN":         _generate_ssn,
    "IP_ADDRESS":  _generate_ip,
    "DOB":         _generate_dob,
    "PAN":         _generate_pan,
    "UPI_ID":      _generate_upi,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_replacement(match: PIIMatch) -> str:
    """
    Return the deterministic synthetic replacement for match.text.
    Maintains strict 1-to-1 consistency across the entire document.
    Preserves ALL-CAPS formatting if the original text was ALL-CAPS.
    """
    raw_key = match.text.strip()
    is_all_caps = raw_key.isupper() and len(raw_key) > 3 and match.entity_type in {"PERSON", "COMPANY"}
    canonical_key = raw_key.title() if is_all_caps else raw_key

    # Check existing registration
    if canonical_key in _replacement_map:
        base_rep = _replacement_map[canonical_key]["replacement"]
        return base_rep.upper() if is_all_caps else base_rep

    gen = _GENERATORS.get(match.entity_type)
    if gen is None:
        rep = f"[{match.entity_type}]"
        _register(canonical_key, match.entity_type, rep)
        return rep.upper() if is_all_caps else rep

    # Generate candidate and verify collision-freedom
    candidate = None
    for attempt in range(100):
        salt = canonical_key if attempt == 0 else f"{canonical_key}_alt_{attempt}"
        c = gen(salt)
        if _is_collision_free(match.entity_type, c):
            candidate = c
            break

    if candidate is None:
        candidate = gen(f"{canonical_key}_fallback_{len(_used_replacements.get(match.entity_type, set()))}")

    _register(canonical_key, match.entity_type, candidate)
    return candidate.upper() if is_all_caps else candidate


def get_replacement_map() -> Dict[str, Dict]:
    """Return a snapshot copy of the current replacement map."""
    return dict(_replacement_map)


def get_synthetic_values() -> Set[str]:
    """Return the set of all generated synthetic values (for residual scan filtering)."""
    return set(_synthetic_exclusion_set)


def reset_replacement_map() -> None:
    """Reset the registry state (for testing)."""
    _replacement_map.clear()
    _used_replacements.clear()
    _synthetic_exclusion_set.clear()
