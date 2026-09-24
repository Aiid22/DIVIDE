"""Related-group construction and deterministic fragment recovery (paper Sec. 2.2)."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from divide.models import CarrierRecord, RecoveryStep, RecoveryTrace, RelatedGroup

from .decoder import RecoveredText


_PART_FIELD = re.compile(r"(?i)(?:secret|token|key|credential)?.*?(?:part|chunk|segment|prefix|suffix)[_-]?(\d+)?$")
_ORDER_NUMBER = re.compile(r"(\d+)")


def _natural_order(record: CarrierRecord) -> tuple[object, ...]:
    value = record.field_path or record.location
    return tuple(int(part) if part.isdigit() else part.casefold() for part in re.split(r"(\d+)", value))


def build_related_groups(records: list[CarrierRecord]) -> tuple[list[RelatedGroup], dict[str, CarrierRecord]]:
    """Build structural/positional groups rather than content-only windows."""
    by_id = {record.id: record for record in records}
    buckets: dict[tuple[str, str, str], list[CarrierRecord]] = defaultdict(list)
    for record in records:
        structural_parent = str(record.metadata.get("group") or record.parent_object_id or record.nested_path)
        relationship = record.relationship or ("field-sibling" if record.field_path else "position-neighbor")
        buckets[(record.root_path, structural_parent, relationship)].append(record)
    groups: list[RelatedGroup] = []
    for (root, parent, relationship), items in buckets.items():
        if len(items) < 2:
            continue
        ordered = sorted(items, key=_natural_order)
        fields = [item.field_path or str(item.metadata.get("field", "")) for item in ordered]
        explicit_parts = sum(bool(_PART_FIELD.search(field)) for field in fields if field)
        same_object = len({item.parent_object_id for item in ordered}) == 1
        positional = all(item.nested_path == ordered[0].nested_path for item in ordered)
        if not explicit_parts and not (same_object and positional):
            continue
        digest = hashlib.sha256(f"{root}\0{parent}\0{relationship}".encode()).hexdigest()[:16]
        rationale = [f"shared structural parent {parent}", f"relation {relationship}"]
        if explicit_parts:
            rationale.append(f"{explicit_parts} ordered fragment-labelled fields")
        groups.append(RelatedGroup(
            id=f"G:{digest}", relation=relationship,
            record_ids=[item.id for item in ordered], ordering=[item.location for item in ordered],
            confidence=min(item.extraction_confidence for item in ordered) * (.95 if explicit_parts else .80),
            rationale=rationale,
        ))
    return groups, by_id


def recover_fragments(records: list[CarrierRecord]) -> list[tuple[CarrierRecord, RecoveredText]]:
    """Deterministically recover whole values from related groups."""
    recovered: list[tuple[CarrierRecord, RecoveredText]] = []
    groups, by_id = build_related_groups(records)
    for group in groups:
        selected = [by_id[identifier] for identifier in group.record_ids]
        atoms = [_fragment_atom(record.text) for record in selected]
        if any(not atom for atom in atoms):
            continue
        value = "".join(atoms)
        if not 12 <= len(value) <= 512:
            continue
        trace = RecoveryTrace(
            group.record_ids,
            [RecoveryStep(
                "concatenate", f"deterministic {group.relation} order from {group.id}",
                hashlib.sha256("\0".join(atoms).encode()).hexdigest(), hashlib.sha256(value.encode()).hexdigest(),
                1, None, group.confidence,
            )],
            group.confidence,
        )
        synthetic = CarrierRecord(
            id=f"F:{group.id}", root_path=selected[0].root_path, nested_path=selected[0].nested_path,
            carrier_type="related-group", location=" + ".join(group.ordering), text=value,
            context=" ".join(record.context for record in selected), confidence=group.confidence,
            metadata={"group": group.id, "relation": group.relation, "rationale": group.rationale},
            parent_object_id=selected[0].parent_object_id, detected_type="related-group",
            relationship=group.relation, content_sha256=hashlib.sha256(value.encode()).hexdigest(),
            extraction_confidence=group.confidence,
        )
        recovered.append((synthetic, RecoveredText(value, trace)))
    return recovered


def _fragment_atom(text: str) -> str:
    value = text.strip().strip("\"'` ,;:")
    if not 2 <= len(value) <= 256 or any(character.isspace() for character in value):
        return ""
    if len(re.findall(r"[A-Za-z0-9]", value)) / len(value) < .65:
        return ""
    return value
