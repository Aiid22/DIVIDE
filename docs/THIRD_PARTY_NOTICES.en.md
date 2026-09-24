# Third-party notices

Our DIVIDE prototype invokes several third-party parsers through Python
dependencies. Compatible ranges are declared in `pyproject.toml`, and pinned
experiment versions are listed in `constraints.txt`. Each component remains
subject to its own license.

## Bundled Gitleaks rule snapshot

We bundle a rule snapshot prepared from the upstream Gitleaks v8.30.1
configuration (<https://github.com/gitleaks/gitleaks>, MIT License, copyright
Zachary Rice; license copy at `src/divide/verification/data/LICENSE.gitleaks`):

- Upstream configuration: <https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml>
- Pinned commit: `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`
- Bundled file: the complete upstream `config/gitleaks.toml`, content SHA-256
  `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`;
  `divide rules audit` recomputes and checks the manifest.
- Converted fields: `regex`, `secretGroup`, `entropy`, `keywords`, global and
  rule-level `allowlists.regexes`, `allowlists.paths`, and `stopwords`.

Our core rules take precedence over imported rules. Identical-pattern conflicts
across providers are not overwritten; both sources remain visible in the audit.

The GitHub token checksum follows the algorithm published at
<https://github.blog/engineering/behind-githubs-new-authentication-token-formats/>
(CRC32, `0-9A-Za-z` Base62 alphabet, final six characters, left padding).

We do not distribute the paper, research dataset, Qwen weights, the Gitleaks
executable, TruffleHog, KEYSENTINEL, or any external media/OCR program with
this repository.
