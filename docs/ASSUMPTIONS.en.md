# Engineering assumption ledger

[English](ASSUMPTIONS.en.md) | [中文](ASSUMPTIONS.md)

| ID | Engineering assumption | Impact | Retirement criterion |
|---|---|---|---|
| EA-001 | The OCR-constrained beam defaults to `B=64`. | Recall and latency. | Reconcile with our original experiment configuration or preregister calibration on a development set. |
| EA-002 | Depth, size, compression, pixel, frame, query, and timeout budgets. | Processable carrier range. | Record our original budgets or complete safety/performance experiments. |
| EA-003 | Verification threshold and carrier, field, context, and recovery weights. | Precision and recall. | Calibrate on a development set after strict test-set isolation. |
| EA-004 | OCR geometric spacing threshold and substitution penalty. | Image recovery rate. | Ablate and report on labeled OCR data. |
| EA-005 | The default GitHub Base62 alphabet is `0-9A-Za-z`. | Checksum acceptance and rejection. | Confirm alphabet and padding with independent provider vectors. |
| EA-006 | The complete Gitleaks v8.30.1 configuration at commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` is our reproducible proxy because we do not identify an exact rule commit in the paper. | Equivalence to the paper's rule corpus. | Reconcile with the exact commit used in our original experiments. |
| EA-007 | Numeric aggregation of encoding evidence. | Extraction from non-UTF text. | Record our original formula or calibrate independently. |
| EA-008 | `RelatedGroup` field-name and same-parent heuristics. | Fragment recovery rate. | Validate against relationship annotations in the research dataset. |
| EA-009 | `no-media` skips image, audio, and video objects before handler dispatch while retaining the PDF text layer. | Ablation boundary. | Align with the media definition and timing boundary in our paper experiments. |
| EA-010 | Gitleaks RE2 patterns run through Python `regex`, with explicit `\\z` to `\\Z` translation. | Some regular-expression semantics may differ. | Use Gitleaks/Go RE2 in process or verify equivalence rule by rule. |

We require every experiment result to carry configuration hash, rule hash, and ledger version. Until reconciliation is complete, these values must not be presented as the paper's original parameters.
