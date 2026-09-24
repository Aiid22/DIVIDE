from __future__ import annotations

import io
import mimetypes
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Detection:
    kind: str
    mime: str
    confidence: float
    structural_valid: bool
    evidence: tuple[str, ...]


TEXT_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".cs", ".css", ".env", ".go", ".h", ".hpp",
    ".ini", ".java", ".js", ".jsx", ".kt", ".log", ".md", ".pem", ".php", ".properties",
    ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx", ".txt", ".vue",
}
STRUCTURED_EXTENSIONS = {
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".xml": "xml", ".svg": "xml", ".csv": "csv",
}
EXTENSION_KINDS = {
    ".7z": "7z", ".rar": "rar", ".jar": "jar", ".apk": "apk", ".rpm": "rpm", ".iso": "iso",
    ".doc": "doc", ".xls": "xls", ".ppt": "ppt", ".odt": "odf", ".ods": "odf", ".odp": "odf",
    ".epub": "epub", ".rtf": "rtf", ".msg": "outlook-msg", ".wasm": "wasm", ".ttf": "font",
    ".otf": "font", ".woff": "font", ".woff2": "font", ".mp3": "audio", ".wav": "audio",
    ".flac": "audio", ".ogg": "audio", ".m4a": "audio", ".mp4": "video", ".mkv": "video",
    ".mov": "video", ".avi": "video", ".webm": "video", ".psd": "image", ".ico": "image",
}


def _zip_subtype(data: bytes, suffix: str) -> tuple[str, bool, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return "zip", False, "invalid ZIP central directory"
    if "word/document.xml" in names:
        return "docx", True, "OOXML word/document.xml"
    if "xl/workbook.xml" in names:
        return "xlsx", True, "OOXML xl/workbook.xml"
    if "ppt/presentation.xml" in names:
        return "pptx", True, "OOXML ppt/presentation.xml"
    if "META-INF/container.xml" in names:
        return "epub", True, "EPUB container"
    if "mimetype" in names:
        try:
            mimetype = archive.read("mimetype")[:128]
        except (KeyError, OSError):
            mimetype = b""
        if mimetype.startswith(b"application/vnd.oasis.opendocument"):
            return "odf", True, "ODF mimetype member"
    if suffix == ".jar" and "META-INF/MANIFEST.MF" in names:
        return "jar", True, "JAR manifest"
    if suffix == ".apk" and ("AndroidManifest.xml" in names or "classes.dex" in names):
        return "apk", True, "APK manifest/classes"
    return "zip", True, "valid ZIP central directory"


def detect(data: bytes, name: str) -> Detection:
    suffix = Path(name).suffix.lower()
    guessed_mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    signatures = (
        (b"%PDF-", "pdf", "application/pdf", "PDF signature"),
        (b"SQLite format 3\x00", "sqlite", "application/vnd.sqlite3", "SQLite header"),
        (b"\x1f\x8b", "gzip", "application/gzip", "GZIP signature"),
        (b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed", "7z signature"),
        (b"Rar!\x1a\x07", "rar", "application/vnd.rar", "RAR signature"),
        (b"\xed\xab\xee\xdb", "rpm", "application/x-rpm", "RPM lead magic"),
        (b"{\\rtf", "rtf", "application/rtf", "RTF control header"),
        (b"\x7fELF", "elf", "application/x-elf", "ELF magic"),
        (b"\x00asm", "wasm", "application/wasm", "WASM magic"),
    )
    for magic, kind, mime, evidence in signatures:
        if data.startswith(magic):
            return Detection(kind, mime, .99, True, (evidence,))
    if data[:4] in {b"\xde\x12\x04\x95", b"\x95\x04\x12\xde"}:
        return Detection("gettext", "application/x-gettext-translation", .99, True, ("GNU MO magic",))
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return Detection("iso", "application/x-iso9660-image", .99, True, ("ISO-9660 volume descriptor",))
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        kind, valid, evidence = _zip_subtype(data, suffix)
        return Detection(kind, guessed_mime, .98 if valid else .55, valid, ("ZIP signature", evidence))
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        kind = EXTENSION_KINDS.get(suffix, "ole")
        if kind not in {"doc", "xls", "ppt", "outlook-msg"}:
            kind = "ole"
        return Detection(kind, guessed_mime, .85, True, ("OLE compound-file signature", "extension-assisted subtype"))
    if data.startswith(b"MZ"):
        return Detection("pe", "application/vnd.microsoft.portable-executable", .92, True, ("DOS MZ header",))
    if data[:4] in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    }:
        return Detection("mach-o", "application/x-mach-binary", .99, True, ("Mach-O/fat magic",))
    image_magic = (
        (b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"), (b"II*\x00", "image/tiff"),
        (b"MM\x00*", "image/tiff"), (b"8BPS", "image/vnd.adobe.photoshop"),
        (b"\x00\x00\x01\x00", "image/x-icon"),
    )
    for magic, mime in image_magic:
        if data.startswith(magic):
            return Detection("image", mime, .99, True, (f"{mime} signature",))
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return Detection("image", "image/webp", .99, True, ("WebP RIFF signature",))
    if data.startswith((b"\x00\x01\x00\x00", b"OTTO", b"wOFF", b"wOF2", b"true")):
        return Detection("font", guessed_mime, .95, True, ("font signature",))
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return Detection("tar", "application/x-tar", .95, True, ("valid TAR structure",))
    except (tarfile.TarError, OSError, EOFError):
        pass
    if suffix in STRUCTURED_EXTENSIONS:
        return Detection(STRUCTURED_EXTENSIONS[suffix], guessed_mime, .65, False, ("extension hint",))
    if suffix in TEXT_EXTENSIONS:
        return Detection("text", guessed_mime, .60, False, ("extension hint",))
    if suffix in EXTENSION_KINDS:
        return Detection(EXTENSION_KINDS[suffix], guessed_mime, .45, False, ("extension-only hint",))
    if b"\x00" not in data[:4096]:
        try:
            data[:4096].decode("utf-8", errors="strict")
            return Detection("text", "text/plain", .75, True, ("strict UTF-8 prefix",))
        except UnicodeDecodeError:
            pass
    try:
        import magic

        mime = str(magic.from_buffer(data[:8192], mime=True))
        prefix_map = {"text/": "text", "image/": "image", "audio/": "audio", "video/": "video"}
        for prefix, kind in prefix_map.items():
            if mime.startswith(prefix):
                return Detection(kind, mime, .75, True, ("libmagic MIME",))
    except (ImportError, OSError):
        pass
    return Detection("binary", "application/octet-stream", .40, False, ("unknown-binary fallback",))


def detect_kind(data: bytes, name: str) -> str:
    return detect(data, name).kind
