# Rule sources and versions

[English](RULE_SOURCES.en.md) | [中文](RULE_SOURCES.md)

## DIVIDE core 2026.09.1

Our core rules cover AWS, GitHub, GitLab, Slack, Stripe, Google API keys, PEM private keys, and generic sensitive-field assignments. They are defined in `default_rules.yaml`. Because we do not disclose the complete experimental rule corpus in the paper, this reference prototype uses an auditable high-confidence approximation. Every compiled rule carries provider, version, source, and license fields.

## Gitleaks v8.30.1

- Upstream configuration: <https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml>
- Upstream project: <https://github.com/gitleaks/gitleaks>
- License: MIT; a copy is stored at `src/divide/rulesets/data/LICENSE.gitleaks`
- Pinned commit: `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`
- Bundled file: the complete upstream `config/gitleaks.toml`, content SHA-256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`; `rules audit` recomputes and checks the manifest.
- Converted fields: `regex`, `secretGroup`, `entropy`, `keywords`, global and rule-level `allowlists.regexes`, `allowlists.paths`, and `stopwords`.

Our core rules take precedence over imported rules. Identical-pattern conflicts across providers are not overwritten; both sources remain visible in the audit.

## GitHub token checksum

Algorithm source: <https://github.blog/engineering/behind-githubs-new-authentication-token-formats/>. The source describes CRC32, Base62, the final six characters, and padding. We still register the alphabet as EA-005 pending confirmation with independent provider vectors.
