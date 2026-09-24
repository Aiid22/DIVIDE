# Sample Data

This folder contains a small showcase of **multi-type carrier samples** drawn from
the benchmark used in the paper. Each file demonstrates one of the heterogeneous
carriers that DIVIDE's localization, recovery, and verification stages are built
for — plain text and source code, images, archives, binaries, and compiled
translation catalogs.

Every credential-looking value in these samples is **synthetic**: planted
markers, documentation defaults, or test fixtures. No real secret is included.

| Folder | Samples | What it shows |
|---|---|---|
| `text/` | Python, JavaScript, JSON, shell, Java, C, plain text | Secrets in source code, config files, base64-encoded pairs, embedded PGP keys, weak tokens |
| `image/` | PNG, JPEG, WebP, GIF | Credential tables recovered by OCR; photo carriers |
| `archive/` | ZIP, 7z, JAR | Nested and compressed carriers that flat scanners never open |
| `binary/` | ELF, PE | Executables with embedded flag-like secrets |
| `gettext/` | GNU `.mo` | Compiled message catalogs as a carrier |

Try the pipeline on all of them:

```bash
divide scan data/ -o data-report.json
```

## Full dataset

The complete benchmark — thousands of files across 40+ format types with
file-level secret annotations — is **not** redistributed here. It will be
fully released upon acceptance of the paper.
