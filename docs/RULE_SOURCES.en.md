# Rule sources and versions

## DIVIDE core 2026.09.1

Our current core rules cover AWS, GitHub, GitLab, Slack, Stripe, Google API keys, PEM private keys, and generic sensitive-field assignments. They are defined in `default_rules.yaml`, and every compiled rule carries provider, version, source, and license fields.

## Gitleaks v8.30.1

- Upstream configuration: <https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml>
- Upstream project: <https://github.com/gitleaks/gitleaks>
- License: MIT; a copy is stored at `src/divide/verification/data/LICENSE.gitleaks`
- Pinned commit: `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`
- Bundled file: the complete upstream `config/gitleaks.toml`, content SHA-256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`; `rules audit` recomputes and checks the manifest.
- Converted fields: `regex`, `secretGroup`, `entropy`, `keywords`, global and rule-level `allowlists.regexes`, `allowlists.paths`, and `stopwords`.

Our core rules take precedence over imported rules. Identical-pattern conflicts across providers are not overwritten; both sources remain visible in the audit.

## GitHub token checksum

Algorithm source: <https://github.blog/engineering/behind-githubs-new-authentication-token-formats/>. The current implementation uses CRC32, the `0-9A-Za-z` Base62 alphabet, the final six characters, and left padding.
