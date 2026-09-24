from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from divide.config import AppConfig
from divide.models import CarrierRecord, RecoveryStep, RecoveryTrace


BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{24,}(?![0-9A-Fa-f])")
URL_TOKEN = re.compile(r"\S*%[0-9A-Fa-f]{2}\S*")
ESCAPE_TOKEN = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|n|r|t)")
OCR_SUBSTITUTIONS = {"0": ("O",), "O": ("0",), "1": ("l", "I"), "l": ("1", "I"), "I": ("1", "l")}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class RecoveredText:
    text: str
    trace: RecoveryTrace


@dataclass(frozen=True, slots=True)
class RecoveryConstraint:
    rule_id: str
    prefixes: tuple[str, ...]
    min_length: int
    max_length: int
    charset: str | None = None

    def permits(self, value: str, *, final: bool) -> bool:
        if len(value) > self.max_length or (final and len(value) < self.min_length):
            return False
        if self.prefixes:
            prefix_possible = any(prefix.startswith(value) or value.startswith(prefix) for prefix in self.prefixes)
            if not prefix_possible:
                return False
        if self.charset and final and re.fullmatch(self.charset, value) is None:
            return False
        return True


def constraints_from_config(config: AppConfig) -> list[RecoveryConstraint]:
    return [
        RecoveryConstraint(
            str(rule.get("id", "unknown")), tuple(rule.get("prefixes", ())),
            int(rule.get("min_length", 1)), int(rule.get("max_length", 65536)), rule.get("charset"),
        )
        for rule in config.credential_rules
    ]


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "").replace("\ufeff", "")

    def replace_escape(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in {"\\n", "\\r", "\\t"}:
            return {"\\n": "\n", "\\r": "\r", "\\t": "\t"}[token]
        try:
            return chr(int(token[2:], 16))
        except ValueError:
            return token

    return ESCAPE_TOKEN.sub(replace_escape, normalized)


def decode_exact(value: str, encoding: str, max_output: int) -> str:
    if encoding in {"base64", "base64url"}:
        padded = value + "=" * (-len(value) % 4)
        if encoding == "base64url":
            raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        else:
            raw = base64.b64decode(padded, validate=True)
        decoded = raw.decode("utf-8", errors="strict")
    elif encoding == "hex":
        decoded = bytes.fromhex(value).decode("utf-8", errors="strict")
    elif encoding == "url":
        decoded = unquote(value, errors="strict")
    else:
        raise ValueError(f"Unsupported decoding: {encoding}")
    if len(decoded.encode("utf-8")) > max_output:
        raise ValueError("Decoded output exceeds limit")
    if not _is_valid_text(decoded):
        raise ValueError("Decoded output is not a valid character sequence")
    return decoded


def recover_record(record: CarrierRecord, config: AppConfig) -> list[RecoveredText]:
    normalized = normalize_text(record.text)
    initial_steps: list[RecoveryStep] = []
    if normalized != record.text:
        initial_steps.append(RecoveryStep(
            "normalize", "Unicode, escape, and invisible-character normalization",
            _sha(record.text), _sha(normalized), 0, None, .98,
        ))
    results = [RecoveredText(normalized, RecoveryTrace([record.id], initial_steps, record.confidence))]
    queue: list[tuple[str, int, list[RecoveryStep], float]] = [(normalized, 0, initial_steps, record.confidence)]
    seen = {normalized}
    while queue:
        current, depth, steps, confidence = queue.pop(0)
        if depth >= config.limits.max_decode_depth:
            continue
        for token, encoding in _encoded_tokens(current):
            try:
                decoded = decode_exact(token, encoding, config.limits.max_decode_output)
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if decoded in seen:
                continue
            seen.add(decoded)
            next_confidence = max(.35, confidence - .06)
            next_steps = [*steps, RecoveryStep(
                "decode", f"bounded {encoding} decoding",
                _sha(token), _sha(decoded), depth + 1, encoding, next_confidence,
            )]
            results.append(RecoveredText(decoded, RecoveryTrace([record.id], next_steps, next_confidence)))
            queue.append((decoded, depth + 1, next_steps, next_confidence))
    if record.carrier_type in {"image", "pdf-page"}:
        results.extend(_ocr_variants(normalized, record, config))
    return results


def _encoded_tokens(text: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for match in BASE64_TOKEN.finditer(text):
        token = match.group(0)
        values.append((token, "base64url" if "-" in token or "_" in token else "base64"))
    values.extend((match.group(0), "hex") for match in HEX_TOKEN.finditer(text) if len(match.group(0)) % 2 == 0)
    values.extend((match.group(0), "url") for match in URL_TOKEN.finditer(text))
    return values


def _is_valid_text(value: str) -> bool:
    if not value or "\x00" in value:
        return False
    printable = sum(character.isprintable() or character in "\r\n\t" for character in value)
    return printable / len(value) >= .9


def constrained_ocr_beam(
    token: str, constraints: list[RecoveryConstraint], beam_width: int,
) -> list[tuple[str, float, str]]:
    """Equation (1) realization: retain at most B format-valid sequences per step.

    The score is a deterministic edit penalty. B=64 and the penalty are
    engineering assumptions because we do not report them in the paper.
    """
    beam: list[tuple[str, float]] = [("", 0.0)]
    for character in token:
        options = (character, *OCR_SUBSTITUTIONS.get(character, ()))
        expanded: dict[str, float] = {}
        for prefix, score in beam:
            for option in options:
                value = prefix + option
                if constraints and not any(rule.permits(value, final=False) for rule in constraints):
                    continue
                penalty = score + (0.0 if option == character else 1.0)
                expanded[value] = min(penalty, expanded.get(value, float("inf")))
        beam = sorted(expanded.items(), key=lambda item: (item[1], item[0]))[:beam_width]
        if not beam:
            return []
    output: list[tuple[str, float, str]] = []
    for value, penalty in beam:
        matching = [rule.rule_id for rule in constraints if rule.permits(value, final=True)]
        if value != token and matching:
            output.append((value, penalty, matching[0]))
    return output[:beam_width]


def _ocr_variants(text: str, record: CarrierRecord, config: AppConfig) -> list[RecoveredText]:
    constraints = constraints_from_config(config)
    results: list[RecoveredText] = []
    beam_width = min(config.limits.max_recovery_beam, config.limits.max_ocr_variants)
    for match in re.finditer(r"[A-Za-z0-9_\-]{8,512}", text):
        token = match.group(0)
        for variant, penalty, rule_id in constrained_ocr_beam(token, constraints, beam_width):
            recovered = f"{text[:match.start()]}{variant}{text[match.end():]}"
            confidence = max(.25, record.confidence - min(.5, .05 * penalty))
            results.append(RecoveredText(
                recovered,
                RecoveryTrace([record.id], [RecoveryStep(
                    "ocr_substitute", f"Equation (1) constrained beam; rule={rule_id}; B={beam_width}; edits={int(penalty)}",
                    _sha(token), _sha(variant), 1, None, confidence,
                )], confidence),
            ))
            if len(results) >= beam_width:
                return results
    return results
