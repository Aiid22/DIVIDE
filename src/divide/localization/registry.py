from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass
from typing import Any, Iterable

from divide.interfaces import Capability, CarrierHandler, ProbeResult
from divide.models import CarrierObject, CarrierRecord

from .detector import detect


@dataclass(frozen=True, slots=True)
class HandlerSpec:
    handler_id: str
    kinds: tuple[str, ...]
    formats: tuple[str, ...]
    backend: str
    python_modules: tuple[str, ...] = ()
    external_commands: tuple[str, ...] = ()
    installed_status: str = "full"
    missing_status: str = "fallback"
    reason: str = ""
    priority: int = 100


class DeclaredCarrierHandler(CarrierHandler):
    """Capability contract selected by signatures and structural probes.

    Recursive extraction is orchestrated centrally by ``ArtifactLocalizer`` so
    every adapter shares the same expansion, timeout, and depth budgets.
    """

    def __init__(self, spec: HandlerSpec):
        self.spec = spec
        self.handler_id = spec.handler_id
        self.priority = spec.priority

    def _missing(self) -> list[str]:
        missing = [module for module in self.spec.python_modules if importlib.util.find_spec(module) is None]
        missing.extend(command for command in self.spec.external_commands if shutil.which(command) is None)
        return missing

    def capability(self) -> Capability:
        missing = self._missing()
        status = self.spec.missing_status if missing else self.spec.installed_status
        reason = self.spec.reason
        if missing:
            reason = f"missing optional backend(s): {', '.join(missing)}; safe fallback is used"
        return Capability(
            self.handler_id, self.spec.formats, status, self.spec.backend, reason,
            tuple(self.spec.python_modules + self.spec.external_commands),
        )

    def probe(self, obj: CarrierObject) -> ProbeResult:
        result = detect(obj.data, obj.name)
        return ProbeResult(
            result.kind in self.spec.kinds, result.kind, result.mime, result.confidence,
            result.structural_valid, list(result.evidence),
        )

    def validate_structure(self, obj: CarrierObject, probe: ProbeResult) -> tuple[bool, str]:
        if probe.structural_valid:
            return True, "; ".join(probe.evidence)
        if probe.detected_type in {"zip", "jar", "apk", "tar", "gzip", "7z", "rar", "rpm", "iso"}:
            return False, "archive signature was present but structural validation failed"
        return probe.matched, "extension/MIME match without a complete structural proof"

    def extract_records(self, obj: CarrierObject, context: Any) -> Iterable[CarrierRecord]:
        return context.extract_records(self, obj)

    def enumerate_children(self, obj: CarrierObject, context: Any) -> Iterable[CarrierObject]:
        return context.enumerate_children(self, obj)


class HandlerRegistry:
    def __init__(self, handlers: Iterable[CarrierHandler] = ()):
        self._handlers: list[CarrierHandler] = []
        for handler in handlers:
            self.register(handler)

    def register(self, handler: CarrierHandler) -> None:
        if any(item.handler_id == handler.handler_id for item in self._handlers):
            raise ValueError(f"duplicate carrier handler: {handler.handler_id}")
        self._handlers.append(handler)
        self._handlers.sort(key=lambda item: item.priority)

    def select(self, obj: CarrierObject) -> tuple[CarrierHandler, ProbeResult]:
        fallback: tuple[CarrierHandler, ProbeResult] | None = None
        for handler in self._handlers:
            probe = handler.probe(obj)
            if not probe.matched:
                continue
            if handler.handler_id == "unknown-binary":
                fallback = (handler, probe)
            else:
                return handler, probe
        if fallback:
            return fallback
        raise LookupError(f"no carrier handler accepted {obj.nested_path}")

    def capabilities(self) -> list[dict[str, Any]]:
        return [handler.capability().to_dict() for handler in self._handlers]


def default_registry() -> HandlerRegistry:
    specs = [
        HandlerSpec("structured-text", ("text", "json", "yaml", "xml", "csv"),
                    ("source", "TXT", "JSON", "CSV", "XML", "YAML", "SVG", "PEM"), "stdlib/defusedxml/PyYAML", priority=10),
        HandlerSpec("zip-family", ("zip", "jar", "apk"), ("ZIP", "JAR", "APK"), "zipfile", priority=20),
        HandlerSpec("tar-gzip", ("tar", "gzip"), ("TAR", "GZIP"), "tarfile/gzip", priority=21),
        HandlerSpec("sevenzip", ("7z",), ("7z",), "py7zr", ("py7zr",), priority=22),
        HandlerSpec("rar", ("rar",), ("RAR",), "rarfile+unrar/unar", ("rarfile",), ("unrar",),
                    installed_status="partial", reason="backend may require an external decoder", priority=23),
        HandlerSpec("rpm", ("rpm",), ("RPM",), "rpmfile", ("rpmfile",), priority=24),
        HandlerSpec("iso", ("iso",), ("ISO",), "pycdlib", ("pycdlib",), priority=25),
        HandlerSpec("ooxml", ("docx", "xlsx", "pptx"), ("DOCX", "XLSX", "PPTX"),
                    "python-docx/openpyxl/python-pptx", ("docx", "openpyxl", "pptx"), priority=30),
        HandlerSpec("legacy-office", ("doc", "xls", "ppt", "ole"), ("DOC", "XLS", "PPT"),
                    "olefile/xlrd/fallback", ("olefile",), installed_status="partial", reason="OLE metadata and string fallback", priority=31),
        HandlerSpec("open-document", ("odf",), ("ODF",), "odfpy", ("odf",), priority=32),
        HandlerSpec("epub", ("epub",), ("EPUB",), "ebooklib", ("ebooklib",), priority=33),
        HandlerSpec("rtf", ("rtf",), ("RTF",), "striprtf", ("striprtf",), priority=34),
        HandlerSpec("outlook-msg", ("outlook-msg",), ("Outlook MSG",), "extract-msg", ("extract_msg",), priority=35),
        HandlerSpec("executable", ("elf", "pe", "mach-o", "wasm"), ("ELF", "PE", "Mach-O", "WASM"),
                    "lief/fallback", ("lief",), installed_status="partial", reason="metadata/sections plus string fallback", priority=40),
        HandlerSpec("font", ("font",), ("fonts",), "fonttools", ("fontTools",), installed_status="partial", priority=41),
        HandlerSpec("audio", ("audio",), ("audio",), "mutagen", ("mutagen",), installed_status="partial", priority=42),
        HandlerSpec("video", ("video",), ("video",), "pymediainfo", ("pymediainfo",),
                    installed_status="partial", reason="metadata only unless frame decoding is configured", priority=43),
        HandlerSpec("image", ("image",), ("PNG", "JPEG", "GIF", "TIFF", "WebP", "ICO", "PSD"),
                    "Pillow+pytesseract", ("PIL", "pytesseract"), installed_status="partial", missing_status="unavailable",
                    reason="OCR requires an engine and language data", priority=50),
        HandlerSpec("pdf", ("pdf",), ("PDF",), "pypdf+PyMuPDF", ("pypdf", "fitz"), priority=51),
        HandlerSpec("sqlite", ("sqlite",), ("SQLite",), "sqlite3", priority=52),
        HandlerSpec("gettext", ("gettext",), ("GNU MO/Gettext",), "gettext", priority=53),
        HandlerSpec("unknown-binary", ("binary",), ("unknown binary fallback",), "ASCII/UTF-16 string carving",
                    installed_status="fallback", missing_status="fallback", priority=999),
    ]
    return HandlerRegistry(DeclaredCarrierHandler(spec) for spec in specs)
