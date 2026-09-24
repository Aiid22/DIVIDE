"""Typer CLI exposing scan, capabilities, benchmark, ablate, and rules audit."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer

from divide.config import load_config
from divide.evaluation import ExperimentRunner, load_manifest
from divide.localization import ArtifactLocalizer
from divide.pipeline import DividePipeline
from divide.reporting import write_json_data, write_json_report
from divide.verification import CompositeRuleProvider, ConfigRuleProvider, GitleaksRuleProvider


app = typer.Typer(
    name="divide", help="Recover and verify scanner-blind secrets across heterogeneous carriers.",
    no_args_is_help=True,
)
rules_app = typer.Typer(name="rules", help="Audit the versioned rule library.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


def _apply_overrides(
    config, max_depth, max_object_size, max_expanded_size, max_compression_ratio,
    ocr, llm_base_url, llm_model, allow_remote_llm, show_secrets,
) -> None:
    """Map CLI flags onto the corresponding config fields."""
    if max_depth is not None:
        config.limits.max_depth = max_depth
    if max_object_size is not None:
        config.limits.max_object_size = max_object_size
    if max_expanded_size is not None:
        config.limits.max_expanded_size = max_expanded_size
    if max_compression_ratio is not None:
        config.limits.max_compression_ratio = max_compression_ratio
    if ocr is not None:
        config.ocr.enabled = ocr
    if llm_base_url is not None:
        config.llm.base_url = llm_base_url
    if llm_model is not None:
        config.llm.model = llm_model
    if llm_base_url and llm_model:
        config.llm.planner = "openai-compatible"
    if allow_remote_llm:
        config.llm.allow_remote = True
    config.detection.show_secrets = show_secrets


@app.command()
def scan(
    target: Path = typer.Argument(..., help="File or directory to scan."),
    output: Path = typer.Option(Path("divide-report.json"), "--output", "-o", help="JSON report path."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="YAML configuration override."),
    max_depth: Optional[int] = typer.Option(None, "--max-depth", min=0),
    max_object_size: Optional[int] = typer.Option(None, "--max-object-size", min=1),
    max_expanded_size: Optional[int] = typer.Option(None, "--max-expanded-size", min=1),
    max_compression_ratio: Optional[float] = typer.Option(None, "--max-compression-ratio", min=1),
    ocr: Optional[bool] = typer.Option(None, "--ocr/--no-ocr"),
    llm_base_url: Optional[str] = typer.Option(None, "--llm-base-url", help="OpenAI-compatible local /v1 endpoint."),
    llm_model: Optional[str] = typer.Option(None, "--llm-model"),
    allow_remote_llm: bool = typer.Option(False, "--allow-remote-llm"),
    timeout: Optional[float] = typer.Option(None, "--timeout", min=.1),
    show_secrets: bool = typer.Option(False, "--show-secrets"),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings"),
) -> None:
    """Scan TARGET and write a schema-2.0 redacted JSON report."""
    config = load_config(config_path)
    _apply_overrides(
        config, max_depth, max_object_size, max_expanded_size, max_compression_ratio,
        ocr, llm_base_url, llm_model, allow_remote_llm, show_secrets,
    )
    report = DividePipeline(config).scan(target, timeout_seconds=timeout)
    write_json_report(report, output, show_secrets=show_secrets)
    typer.echo(
        f"Scanned {report.scanned_objects} objects; {len(report.findings)} findings; "
        f"{len(report.warnings)} warnings."
    )
    typer.echo(f"JSON report: {output}")
    if fail_on_findings and report.findings:
        raise typer.Exit(code=1)


@app.command()
def capabilities(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Report full/partial/fallback/unavailable carrier adapters."""
    config = load_config(config_path)
    rows = ArtifactLocalizer(config).capabilities()
    if json_output:
        typer.echo(json.dumps(
            {"schema_version": "2.0", "display_language": "en", "capabilities": rows},
            ensure_ascii=False, indent=2,
        ))
        return
    for row in rows:
        status = row["status"]
        typer.echo(f"{row['handler_id']:<20} {status:<11} {', '.join(row['formats'])}")


@app.command()
def benchmark(
    manifest: Path = typer.Argument(..., help="Dataset manifest containing fingerprints, not plaintext secrets."),
    output: Path = typer.Option(Path("divide-benchmark.json"), "--output", "-o"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Run RQ1 raw-occurrence and project-unique evaluation."""
    config = load_config(config_path)
    results = ExperimentRunner(config).run(load_manifest(manifest), "full")
    write_json_data({
        "schema_version": "2.0", "display_language": "en",
        "status": "executed", "results": [asdict(item) for item in results],
    }, output)
    typer.echo(f"Benchmark result: {output}")


@app.command()
def ablate(
    manifest: Path = typer.Argument(...),
    output: Path = typer.Option(Path("divide-ablation.json"), "--output", "-o"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Run full, no-media, no-recovery, and no-post-filter profiles."""
    config = load_config(config_path)
    results = ExperimentRunner(config).ablate(load_manifest(manifest))
    write_json_data({
        "schema_version": "2.0", "display_language": "en",
        "status": "executed", "profiles": results,
    }, output)
    typer.echo(f"Ablation result: {output}")


@rules_app.command("audit")
def rules_audit(
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Check rule origins, conflicts, compilation status, hashes, and licenses."""
    config = load_config(config_path)
    report = CompositeRuleProvider([ConfigRuleProvider(config), GitleaksRuleProvider()]).audit()
    payload = {"schema_version": "2.0", "display_language": "en", **report}
    if output:
        write_json_data(payload, output)
        typer.echo(f"Rule audit: {output}")
    else:
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
