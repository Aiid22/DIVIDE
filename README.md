# DIVIDE: Publication-Oriented Research Artifact

[English](README.md) | [中文](README.zh-CN.md)

In *Divide and Conquer: Secret Discovery Beyond Text-Only Scanning*, we present DIVIDE, a three-stage approach for carrier localization, secret recovery, and hierarchical offline verification. This repository provides our current Python implementation of Fig. 2, Table 1, Algorithm 1, Equation (1), and Sections 2.1–2.3 of the paper.

## Method-to-artifact mapping

```text
Input file/project
  └─ CarrierHandler registry
       signature + MIME + structural validation → CarrierObject / CarrierRecord
       recursive expansion + shared resource budgets → parent, field, page, bbox, offset, hash
          └─ Recovery
               encoding inference and normalization → bounded Base64/Base64URL/Hex/URL decoding
               OCR geometric reconstruction → Equation (1) constrained beam search
               RelatedGroup → validated RecoveryPlan → deterministic executor
                  └─ Hierarchical verification
                       type/version → hard format checks → checksum → exact placeholder checks
                       → field relations and code noise → carrier/context/recovery scoring
                          └─ redacted schema-2.0 report / RQ1 / RQ2
```

See [our method mapping](docs/METHOD_MAPPING.en.md) for the source-level correspondence and evidence boundaries.

## Carrier capability matrix

- Text: source code, TXT, JSON, CSV, XML, YAML, SVG, and PEM.
- Archives: ZIP, TAR, GZIP, 7z, RAR, JAR, APK, RPM, and ISO.
- Documents: DOC/DOCX, XLS/XLSX, PPT/PPTX, ODF, EPUB, RTF, and Outlook MSG.
- Binary and media: ELF, PE, Mach-O, WASM, fonts, audio, and video.
- Images: PNG, JPEG, GIF, TIFF, WebP, ICO, and PSD.
- Other carriers: PDF, SQLite, GNU MO/Gettext, and ASCII/UTF-16 fallback for unknown binaries.

`divide capabilities --json` reports each adapter as `full`, `partial`, `fallback`, or `unavailable` in the current environment. We do not silently label a format as fully supported when an optional parser or external decoder is missing. Some formats, including RAR and video, may expose only metadata or string fallback; image OCR also depends on the configured OCR engine and language data.

## Repository layout

```text
DIVIDE/
├── README.md                     # English entry point (default)
├── README.zh-CN.md               # Chinese entry point
├── requirement.txt               # compatible dependency ranges
├── constraints.txt               # pinned reproducibility versions
├── requirements-dev.txt          # test and audit dependencies
├── docs/                          # bilingual method and audit records
├── examples/                      # unusable synthetic examples only
├── src/divide/
│   ├── localization/             # handler registry and recursive extraction
│   ├── recovery/                 # encoding, beam search, RelatedGroup, RecoveryPlan
│   ├── rulesets/                 # our rules, Gitleaks snapshot, and checksums
│   ├── verification/             # hierarchical decisions and source-level deduplication
│   ├── evaluation/               # manifest, RQ1 metrics, RQ2 ablations, baselines
│   └── schemas/                  # JSON Schemas for reports and recovery plans
└── tests/                         # unit, security, and handler-contract tests
```

## CLI and language selection

English is the default display language. Every command accepts `--language en|zh` (or `--lang en|zh`); `output.language` in `default_rules.yaml` provides the persistent default. JSON field names remain stable in English for schema compatibility, while each output records `display_language`.

```bash
divide scan TARGET --output report.json
divide scan TARGET --output report.json --language zh
divide capabilities --json --language en
divide benchmark MANIFEST --output benchmark.json --language en
divide ablate MANIFEST --output ablation.json --language en
divide rules audit --output rules-audit.json --language en
```

Scan options include `--config`, resource limits, `--ocr/--no-ocr`, `--timeout`, local OpenAI-compatible planner settings, and `--show-secrets`. Reports contain only masked values and SHA-256 fingerprints by default; plaintext is emitted only when `--show-secrets` is explicitly set.

Our default configuration is in `src/divide/default_rules.yaml`. It bounds recursive depth, per-object and total expanded size, archive members and compression ratio, image pixels, media frames, SQLite rows and VM steps, OCR pages, decode depth and output, beam width, and recovery-plan budgets.

## Recovery planning and Qwen profile

The default planner is `null` and reports `model_unavailable`; it does not call a model. We provide a versioned profile for serving Qwen3-32B-AWQ through an OpenAI-compatible vLLM endpoint and fix the prompt identifier to `divide-recovery-plan-v1`. A model may propose only `concat`, `decode`, and constrained `substitute` operations over existing record references. Our deterministic executor runs a plan only after schema, reference-set, single-assignment, operation allowlist, budget, and unique-output validation.

## Rules and offline verification

Our high-confidence core rules carry version, source, format constraints, test-vector, and license metadata. We also pin the complete upstream Gitleaks v8.30.1 configuration at commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`; its content SHA-256 is recorded in the snapshot manifest. The importer converts `secretGroup`, entropy, keywords, global and rule-level allowlists, stopwords, and path rules. Our rules have precedence, while cross-provider conflicts retain both provenance records.

The GitHub token checksum plugin implements CRC32 → Base62 with the `0-9A-Za-z` alphabet → a six-character suffix with left padding. The alphabet remains an explicit constructor parameter for format-version handling.

## Dataset and experiment protocol

We do not commit the research dataset. A manifest supplies `artifact_id`, `project_id`, relative path, file SHA-256, MIME, secret SHA-256 fingerprints, and location annotations. See `examples/dataset-manifest.example.json`.

`benchmark` reports two units:

- raw occurrence: an instance defined by project, carrier, fingerprint, and location;
- project unique: `(project_id, secret fingerprint)`, normalized only in the evaluation layer.

Both units report precision, recall, F1, FDR, and latency. `ablate` runs the fixed `full`, `no-media`, `no-recovery`, and `no-post-filter` profiles. Results record code version, configuration/rule/capability hashes, random seed, model profile, manifest hash, and environment information. Adapters for Gitleaks, TruffleHog, KEYSENTINEL, and Qwen LLM/VLM baselines explicitly report `unavailable` in this delivery rather than fabricating results.

## Schema 2.0 excerpt

```json
{
  "schema_version": "2.0",
  "display_language": "en",
  "provenance": {"code_revision": "..."},
  "capabilities": [{"handler_id": "rar", "status": "fallback"}],
  "candidate_decisions": [{"accepted": false, "stage": "hard:checksum"}],
  "ablation_profile": "full",
  "summary": {"findings": 0},
  "findings": []
}
```

Corrupt files, encrypted archives, exceeded budgets, unavailable dependencies, and malicious recovery plans become warnings or decisions instead of aborting the entire scan.

## Security boundaries

- We validate archive member paths before temporary extraction, never write into the scan target, and skip symbolic links by default.
- We open SQLite in read-only immutable mode with a query budget and parse XML through `defusedxml`.
- Decoding, OCR beams, plan operations, and outputs are bounded; model text is never executed as code.
- We use only unusable synthetic secrets in examples and tests. Evaluation manifests store fingerprints rather than plaintext.
- `--show-secrets` writes plaintext into the report and should be used only in a controlled experiment environment.

## Artifact scope

We intentionally do not bundle the research dataset, private deployment configuration, model weights, or external baseline binaries. A “complete adapter matrix” means that every Table 1 format has an explicit handler and capability contract; it does not mean every optional backend is available in every environment.
