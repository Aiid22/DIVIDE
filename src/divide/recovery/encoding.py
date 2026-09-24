from __future__ import annotations

from dataclasses import dataclass, field

from charset_normalizer import from_bytes


@dataclass(frozen=True, slots=True)
class EncodingInference:
    encoding: str
    confidence: float
    text: str
    evidence: dict[str, object] = field(default_factory=dict)


_BOMS = (
    (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8-sig"), (b"\xfe\xff", "utf-16-be"), (b"\xff\xfe", "utf-16-le"),
)


def _printable_ratio(text: str) -> float:
    if not text:
        return 1.0
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    return printable / len(text)


def infer_encoding(data: bytes) -> EncodingInference:
    """Combine BOM, strict validity, charset-normalizer, and printable ratio.

    Confidence aggregation is EA-007: the paper identifies the evidence families,
    but does not publish their numerical combination.
    """
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            text = data.decode(encoding, errors="strict")
            ratio = _printable_ratio(text)
            return EncodingInference(encoding, min(1.0, .85 + .15 * ratio), text, {
                "bom": bom.hex(), "strict_decode": True, "printable_ratio": ratio, "source": "bom",
            })
    candidates: list[tuple[float, str, str, dict[str, object]]] = []
    for encoding in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        try:
            text = data.decode(encoding, errors="strict")
        except (UnicodeDecodeError, UnicodeError):
            continue
        ratio = _printable_ratio(text)
        nul_penalty = min(0.35, text.count("\x00") / max(1, len(text)))
        score = .55 + .40 * ratio - nul_penalty
        candidates.append((score, encoding, text, {
            "bom": None, "strict_decode": True, "printable_ratio": ratio, "source": "strict-candidate",
        }))
    match = from_bytes(data).best()
    if match is not None and match.encoding:
        text = str(match)
        ratio = _printable_ratio(text)
        coherence = float(match.percent_coherence or 0.0) / 100.0
        score = .35 + .35 * coherence + .30 * ratio
        candidates.append((score, match.encoding, text, {
            "bom": None, "strict_decode": False, "printable_ratio": ratio,
            "charset_normalizer_coherence": coherence, "source": "charset-normalizer",
        }))
    if not candidates:
        text = data.decode("utf-8", errors="replace")
        return EncodingInference("utf-8-replacement", .20, text, {
            "bom": None, "strict_decode": False, "printable_ratio": _printable_ratio(text), "source": "replacement",
        })
    score, encoding, text, evidence = max(candidates, key=lambda item: (item[0], item[1] == "utf-8"))
    evidence["candidate_count"] = len(candidates)
    return EncodingInference(encoding, max(0.0, min(1.0, score)), text, evidence)
