"""Rule-based candidate extraction over recovered text (paper Algorithm 1).

``EXTRACT_VALID(S, E)``: apply every compiled credential rule to recovered
character sequences, filter allowlisted and low-entropy matches, and emit
:class:`~divide.models.Candidate` objects that carry location, context, and
recovery provenance forward to verification.
"""

from __future__ import annotations

import re
from itertools import islice
from typing import Any

import regex as regex_engine

from divide.config import AppConfig
from divide.models import Candidate, CarrierRecord, RecoveryTrace
from divide.verification.providers import CompositeRuleProvider, ConfigRuleProvider, GitleaksRuleProvider
from divide.verification.rules import CredentialRule, shannon_entropy


class CandidateExtractor:
    """Compile rule sources once and extract candidates from recovered text."""

    def __init__(self, config: AppConfig, provider: CompositeRuleProvider | None = None):
        self.config = config
        self.provider = provider or CompositeRuleProvider([ConfigRuleProvider(config), GitleaksRuleProvider()])
        self.rules: list[CredentialRule] = []
        self.compile_errors: list[dict[str, str]] = []
        self.runtime_errors: list[dict[str, str]] = []
        for item in self.provider.load():
            try:
                self.rules.append(CredentialRule.from_mapping(item))
            except (re.error, regex_engine.error) as exc:
                self.compile_errors.append({"rule_id": str(item.get("id")), "error": str(exc)})

    @property
    def rule_hash(self) -> str:
        """Content hash of every loaded rule source, for provenance records."""
        return str(self.provider.audit()["content_sha256"])

    def extract(self, text: str, record: CarrierRecord, trace: RecoveryTrace) -> list[Candidate]:
        """Return every rule match that survives allowlists and entropy gates."""
        candidates: list[Candidate] = []
        for rule in self.rules:
            if rule.keywords and not any(keyword in text for keyword in rule.keywords):
                continue
            try:
                matches = list(islice(
                    rule.regex.finditer(text, timeout=self.config.detection.max_regex_seconds),
                    self.config.limits.max_rule_matches + 1,
                ))
            except TimeoutError:
                self.runtime_errors.append({"rule_id": rule.id, "error": "regex timeout"})
                continue
            if len(matches) > self.config.limits.max_rule_matches:
                self.runtime_errors.append({"rule_id": rule.id, "error": "rule match budget reached"})
                matches.pop()
            for match in matches:
                try:
                    value = match.group(rule.secret_group)
                    start, end = match.span(rule.secret_group)
                except (IndexError, TypeError):
                    continue
                allowlisted, _ = rule.is_allowlisted(
                    value, f"{record.root_path}!/{record.nested_path}", match.group(0),
                )
                if allowlisted:
                    continue
                if rule.entropy is not None and shannon_entropy(value) < float(rule.entropy):
                    continue
                local_context = text[max(0, match.start() - 120):min(len(text), match.end() + 120)]
                location = f"{record.location}@{start}:{end}"
                candidates.append(Candidate(
                    value=value, credential_type=rule.name, rule_id=rule.id,
                    root_path=record.root_path, nested_path=record.nested_path, location=location,
                    context=" ".join(filter(None, (record.context, local_context))), carrier_type=record.carrier_type,
                    structural_evidence=[], trace=trace, base_score=rule.base_score,
                    require_positive_context=rule.require_positive_context, source_provider=rule.provider_id,
                    source_location_key=f"{record.root_path}\0{record.nested_path}\0{location}",
                    field_relation=record.relationship or ("field" if record.field_path else None),
                    rule_version=rule.provider_version, rule_metadata={
                        **rule.metadata(),
                        "matched_rule_sources": [{"provider_id": rule.provider_id, "rule_id": rule.id}],
                    },
                ))
        return candidates
