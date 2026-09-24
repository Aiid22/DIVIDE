# Sample Data

This folder contains a small showcase of **multi-type carrier samples** drawn from
the benchmark used in the paper. Every credential-looking value in these samples
is **synthetic**: planted markers, documentation defaults, or test fixtures. No
real secret is included.

## What is here now

**20 files across 5 carrier categories and 17 MIME types**, 15 of which carry
ground-truth secret annotations:

| Folder | Files | Types | Annotated |
|---|---|---|---|
| `text/` | 9 | Python, JavaScript, JSON, Shell, Java, C, plain text | 9 |
| `image/` | 5 | PNG, JPEG, WebP, GIF | 2 |
| `archive/` | 3 | ZIP, 7z, JAR | 2 |
| `binary/` | 2 | ELF, PE | 2 |
| `gettext/` | 1 | GNU `.mo` | 0 |

Ground truth lives in [`labels.jsonl`](labels.jsonl) — one JSON line per sample
with `file`, `original_hash`, `category`, `mime`, `size_bytes`, and the
annotated `secrets` (empty for carrier-only samples). Filenames keep the
original content MD5 so results can be traced back to the benchmark.

Try the pipeline on all of them and compare against the labels:

```bash
divide scan data/ -o data-report.json
```

## What is not here yet

The complete benchmark — thousands of files spanning 40+ format families with
file-level secret annotations — is **not** redistributed at this stage. It will
be fully released upon acceptance of the paper.
