from __future__ import annotations

from enum import StrEnum


class OutputLanguage(StrEnum):
    """Human-facing output languages supported by the research prototype."""

    ENGLISH = "en"
    CHINESE = "zh"


_MESSAGES: dict[str, dict[OutputLanguage, str]] = {
    "scan_summary": {
        OutputLanguage.ENGLISH: "Scanned {objects} objects; {findings} findings; {warnings} warnings.",
        OutputLanguage.CHINESE: "已扫描 {objects} 个对象；发现 {findings} 项；产生 {warnings} 条警告。",
    },
    "json_report": {
        OutputLanguage.ENGLISH: "JSON report: {path}",
        OutputLanguage.CHINESE: "JSON 报告：{path}",
    },
    "benchmark_result": {
        OutputLanguage.ENGLISH: "Benchmark result: {path}",
        OutputLanguage.CHINESE: "基准评测结果：{path}",
    },
    "ablation_result": {
        OutputLanguage.ENGLISH: "Ablation result: {path}",
        OutputLanguage.CHINESE: "消融实验结果：{path}",
    },
    "rule_audit": {
        OutputLanguage.ENGLISH: "Rule audit: {path}",
        OutputLanguage.CHINESE: "规则审计结果：{path}",
    },
    "capability_status.full": {
        OutputLanguage.ENGLISH: "full",
        OutputLanguage.CHINESE: "完整",
    },
    "capability_status.partial": {
        OutputLanguage.ENGLISH: "partial",
        OutputLanguage.CHINESE: "部分",
    },
    "capability_status.fallback": {
        OutputLanguage.ENGLISH: "fallback",
        OutputLanguage.CHINESE: "回退",
    },
    "capability_status.unavailable": {
        OutputLanguage.ENGLISH: "unavailable",
        OutputLanguage.CHINESE: "不可用",
    },
}


def parse_language(value: str | OutputLanguage) -> OutputLanguage:
    """Normalize a configured language and fail closed on unsupported values."""

    if isinstance(value, OutputLanguage):
        return value
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "en": OutputLanguage.ENGLISH,
        "en-us": OutputLanguage.ENGLISH,
        "english": OutputLanguage.ENGLISH,
        "zh": OutputLanguage.CHINESE,
        "zh-cn": OutputLanguage.CHINESE,
        "chinese": OutputLanguage.CHINESE,
        "中文": OutputLanguage.CHINESE,
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported output language: {value!r}; expected 'en' or 'zh'") from exc


def message(key: str, language: str | OutputLanguage, **values: object) -> str:
    selected = parse_language(language)
    try:
        template = _MESSAGES[key][selected]
    except KeyError as exc:
        raise KeyError(f"unknown localized message: {key}") from exc
    return template.format(**values)
