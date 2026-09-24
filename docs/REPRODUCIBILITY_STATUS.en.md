# Reproducibility status

[English](REPRODUCIBILITY_STATUS.en.md) | [中文](REPRODUCIBILITY_STATUS.md)

**UNVALIDATED**

In this delivery, we generated the method implementation, capability contracts, rule audit, dataset manifest, metric/ablation framework, and test sources. We did not execute:

- pytest or static analysis;
- conversion or evaluation of the research/user dataset;
- Qwen3-32B-AWQ or any LLM/VLM inference;
- Gitleaks, TruffleHog, or KEYSENTINEL baselines;
- performance, resource-safety, or cross-platform experiments.

We have pinned the complete Gitleaks snapshot, commit SHA, and content hash. Before upgrading this status, we still need to freeze the actual execution environment; run all unit, security, and handler-contract tests; lock EA parameters on an isolated development set; run RQ1 and all four RQ2 profiles on a held-out test set; verify raw-occurrence and project-unique accounting; record failure cases and capability degradation; and complete a reproducible-run audit.
