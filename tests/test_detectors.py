"""
test_detectors.py
-----------------
Unit tests for all PII detectors operating on segment text.
"""

import pytest
import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors import (
    EmailDetector,
    PhoneDetector,
    CreditCardDetector,
    SSNDetector,
    IPAddressDetector,
    DOBDetector,
    AddressDetector,
    PersonDetector,
    CompanyDetector,
    PANDetector,
    UPIDetector,
    _overlaps_protected,
    _get_protected_spans,
)


class TestEmailDetector:
    def setup_method(self):
        self.d = EmailDetector()

    def test_basic_email(self):
        matches = self.d.detect_in_segment("seg_1", "Contact: cs.connect@kshinternational.com for details.")
        assert len(matches) == 1
        assert matches[0].text == "cs.connect@kshinternational.com"
        assert matches[0].entity_type == "EMAIL"

    def test_subaddress(self):
        matches = self.d.detect_in_segment("seg_2", "Email us at user+tag@example.co.in please.")
        assert len(matches) == 1
        assert matches[0].text == "user+tag@example.co.in"

    def test_no_false_positive_filename(self):
        matches = self.d.detect_in_segment("seg_3", "See document file_report.pdf and image.png.")
        assert len(matches) == 0


class TestPhoneDetector:
    def setup_method(self):
        self.d = PhoneDetector()

    def test_indian_mobile(self):
        matches = self.d.detect_in_segment("seg_1", "Mobile: +91 98765 43210 or call office.")
        assert len(matches) >= 1
        assert any("98765" in m.text for m in matches)

    def test_landline_std(self):
        matches = self.d.detect_in_segment("seg_2", "Telephone: +91 20 4505 3237")
        assert len(matches) == 1
        assert "4505" in matches[0].text

    def test_no_false_positive_financial_number(self):
        matches = self.d.detect_in_segment("seg_3", "The company issued 1,528,000 equity shares.")
        assert len(matches) == 0


class TestCreditCardDetector:
    def setup_method(self):
        self.d = CreditCardDetector()

    def test_valid_visa(self):
        # 4111 1111 1111 1111 is a valid test Visa number
        matches = self.d.detect_in_segment("seg_1", "Card: 4111-1111-1111-1111 used for payment.")
        assert len(matches) == 1
        assert matches[0].entity_type == "CREDIT_CARD"

    def test_invalid_luhn(self):
        # 4111 1111 1111 1112 fails Luhn
        matches = self.d.detect_in_segment("seg_2", "Card: 4111-1111-1111-1112 failed.")
        assert len(matches) == 0

    def test_ignores_plain_numbers(self):
        matches = self.d.detect_in_segment("seg_3", "Revenue of 1234567890123456 without card context.")
        # Only valid Luhn matching card prefixes is detected
        for m in matches:
            assert m.entity_type == "CREDIT_CARD"


class TestSSNDetector:
    def setup_method(self):
        self.d = SSNDetector()

    def test_with_ssn_context(self):
        matches = self.d.detect_in_segment("seg_1", "SSN: 987-65-4321 for US tax purposes.")
        assert len(matches) == 1
        assert matches[0].text == "987-65-4321"

    def test_without_context_ignored(self):
        # Without SSN label, arbitrary 3-2-4 hyphenated numbers are rejected
        matches = self.d.detect_in_segment("seg_2", "Code 123-45-6789 in product catalogue.")
        assert len(matches) == 0


class TestIPDetector:
    def setup_method(self):
        self.d = IPAddressDetector()

    def test_valid_ipv4(self):
        matches = self.d.detect_in_segment("seg_1", "Server IP: 192.168.1.100 connected.")
        assert len(matches) == 1
        assert matches[0].text == "192.168.1.100"

    def test_invalid_octet(self):
        matches = self.d.detect_in_segment("seg_2", "Invalid IP: 256.100.1.1 not valid.")
        assert len(matches) == 0

    def test_not_version_string(self):
        matches = self.d.detect_in_segment("seg_3", "Software version 1.2.3.4 released.")
        assert len(matches) == 0


class TestDOBDetector:
    def setup_method(self):
        self.d = DOBDetector()

    def test_with_dob_label(self):
        matches = self.d.detect_in_segment("seg_1", "Director Date of Birth: July 30, 1979")
        assert len(matches) == 1
        assert "July 30, 1979" in matches[0].text

    def test_ordinary_prospectus_date_NEVER_detected(self):
        # Critical golden requirement: 'Dated December 10, 2025' must NOT be classified as DOB
        matches = self.d.detect_in_segment("seg_2", "Dated December 10, 2025")
        assert len(matches) == 0

    def test_general_date_without_dob_context_ignored(self):
        matches = self.d.detect_in_segment("seg_3", "Incorporated on June 1, 1996 as Private Limited.")
        assert len(matches) == 0


class TestAddressDetector:
    def setup_method(self):
        self.d = AddressDetector()

    def test_registered_office_block(self):
        text = (
            "Registered Office: Gat No. 11/3, 11/4, 11/5, Village Birdewadi, "
            "Taluka Khed, Chakan, District Pune - 410 501, Maharashtra, India. "
            "Telephone: +91 20 4505 3237"
        )
        matches = self.d.detect_in_segment("seg_1", text)
        assert len(matches) == 1
        assert matches[0].entity_type == "ADDRESS"
        assert "Birdewadi" in matches[0].text
        assert "Telephone" not in matches[0].text

    def test_city_alone_not_address(self):
        matches = self.d.detect_in_segment("seg_2", "The meeting was held in Pune, Maharashtra.")
        assert len(matches) == 0


class TestPersonDetector:
    def setup_method(self):
        self.d = PersonDetector()

    def test_salutation_name(self):
        matches = self.d.detect_in_segment("seg_1", "The director Mr. Sarthak Malvadkar attended.")
        assert len(matches) >= 1
        assert any("Sarthak Malvadkar" in m.text for m in matches)

    def test_role_context_name(self):
        text = "Company Secretary and Compliance Officer: Sarthak Malvadkar"
        matches = self.d.detect_in_segment("seg_2", text)
        assert len(matches) >= 1
        assert any("Sarthak Malvadkar" in m.text for m in matches)

    def test_protected_phrases_not_person(self):
        # 'Companies Act, 1956' and 'Capital Structure' must NEVER be detected as PERSON
        matches = self.d.detect_in_segment("seg_3", "In accordance with Companies Act, 1956 and Capital Structure.")
        for m in matches:
            assert "Companies Act" not in m.text
            assert "Capital Structure" not in m.text


class TestCompanyDetector:
    def setup_method(self):
        self.d = CompanyDetector()

    def test_full_company_span(self):
        matches = self.d.detect_in_segment("seg_1", "Issuer: KSH International Limited")
        assert len(matches) >= 1
        assert any(m.text == "KSH International Limited" for m in matches)

    def test_known_brlm(self):
        matches = self.d.detect_in_segment("seg_2", "Book Running Lead Manager: Nuvama Wealth Management Limited")
        assert len(matches) >= 1
        assert any("Nuvama Wealth Management Limited" in m.text for m in matches)

    def test_does_not_match_companies_act(self):
        matches = self.d.detect_in_segment("seg_3", "Under the provisions of Companies Act, 1956.")
        assert len(matches) == 0
