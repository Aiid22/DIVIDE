# Paper-to-implementation mapping

We use this table to record the source-level correspondence and evidence boundary between our paper and current implementation.

| Paper component | Implementation entry | Fidelity statement |
|---|---|---|
| Fig. 2, three-stage architecture | `pipeline.py` | Localization, recovery, and verification run in a fixed sequence and retain provenance. |
| Table 1, carrier matrix | `localization/registry.py` | Every format family has a handler, probe, capability state, and explicit degradation path. |
| True-type and structural validation | `localization/detector.py` | Signatures and internal structure take precedence; extensions are low-confidence hints only. |
| Recursive carrier extraction | `localization/localizer.py` | Shared depth, object-size, expansion, compression-ratio, member-count, and timeout budgets. |
| Section 2.2, encoding inference | `recovery/encoding.py` | Combines BOM, strict decoding, character distribution, and printable ratio, recording all decision evidence. |
| Section 2.2, bounded decoding | `recovery/decoder.py` | Standard/URL-safe Base64, Hex, and URL decoding with per-step input/output hashes and depth. |
| Equation (1) | `constrained_ocr_beam` | Applies prefix, length, and alphabet constraints during generation and returns at most B outputs; the default is B=64. |
| Algorithm 1, candidate extraction | `recovery/extraction.py` | Applies every compiled rule to recovered text; allowlists and entropy gates filter matches before verification. |
| Structurally related grouping | `recovery/fragments.py` | Builds `RelatedGroup` from parent objects, field relations, and expression/position order. |
| Algorithm 1, planned recovery | `recovery/planner.py` | Fixed schema, reference/operation/budget validation, deterministic execution, and at most one accepted plan. |
| Section 2.3, hierarchical verification | `verification/verifier.py` | Type/version → hard constraints → checksum → placeholder → context → score. |
| Rule corpus | `verification/` | Our core rules and a complete pinned Gitleaks v8.30.1 configuration retain source, commit, content hash, and license. |
| GitHub checksum | `verification/checksums.py` | CRC32 → Base62 using the `0-9A-Za-z` alphabet → final six characters. |
| RQ1/RQ2 | `evaluation/` | Raw occurrence, project-unique normalization, and four fixed ablation profiles. |

This table records the correspondence between our method and source code.
