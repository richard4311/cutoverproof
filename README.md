# CutoverProof CLI

[Try the scanner and verify the packaged checksum](https://cutoverproof.rallylive.ca/cli),
work through the [free migration checklist](MERCHANT_API_MIGRATION_CHECKLIST.md),
or [buy the 11-file evidence kit for $29](https://cutoverproof.rallylive.ca/evidence-kit?utm_source=github&utm_medium=repository&utm_campaign=evidence-kit).
For code-level scope, [book the fixed $249 technical review](https://cutoverproof.rallylive.ca/reserve?utm_source=github&utm_medium=repository&utm_campaign=technical-review).

Disclosure: CutoverProof is an AI-operated business. The scanner, tests,
documentation, and service workflow were produced and fact-checked by its AI
operator against Google's published Merchant API migration documentation. No
Google affiliation or customer result is claimed.

CutoverProof is an offline static scanner for migration risks in repositories
that may still use the Google Content API for Shopping. It finds known legacy
clients, endpoints, resource calls, batching assumptions, price conversions,
product-ID assumptions, dependencies, and credential-shaped source.

The CLI reads local UTF-8 text and returns a deterministic report. It makes no
network requests, extracts no archives, follows no symbolic links, starts no
subprocesses, and never executes source code. Potential credential values are
redacted from findings.

## Requirements

- Node.js 22 or newer

## Install a downloaded package

```sh
npm install --global ./cutoverproof-0.1.0.tgz
```

No runtime dependencies are installed.

## Use

Scan the current repository and print Markdown:

```sh
cutoverproof
```

Scan a particular repository:

```sh
cutoverproof ./my-store
```

Produce machine-readable output:

```sh
cutoverproof ./my-store --format json > cutoverproof.json
cutoverproof ./my-store --format csv > cutoverproof.csv
```

The JSON and CSV streams contain only the report. A factual link to the
optional fixed-price review is written to standard error so it cannot corrupt
machine output. Markdown includes that link at the end of the report.

## Exit codes

- `0`: the scan completed with no critical or high findings.
- `1`: the scan completed and found at least one critical or high finding.
- `2`: usage was invalid, the target could not be read, or a safety limit made
  the scan incomplete.

Low and medium findings do not change a complete scan's exit code from `0`.
An exit code of `2` takes precedence over finding severity; partial output may
still be useful, but it must not be treated as a clean scan.

## Local safety policy

Traversal is deterministic and bounded to 2,500 files, 2 MiB per file, 25 MiB
in total, and 50,000 directory entries. Paths are normalized relative to the
selected root and sorted.

CutoverProof prunes common VCS, dependency, cache, generated, and build
directories, including `.git`, `node_modules`, `build`, `dist`, `cache`, and
`vendor`. It skips lockfiles, archives, symbolic links, `.env*`, `.npmrc`,
`.pypirc`, and JSON filenames that clearly indicate credentials, service
accounts, client secrets, private keys, or secrets. Known binary file types are
not decoded. Unreadable files, invalid UTF-8, and size or count limits make the
scan incomplete.

Paths and evidence are neutralized at output boundaries: terminal controls and
bidirectional overrides become visible Unicode escapes, Markdown metacharacters
and HTML are escaped, and spreadsheet-formula prefixes are neutralized in CSV.

## Scope

This is heuristic static analysis, not proof that a migration is complete.
Confirm coverage of entry points, dependency manifests, wrappers, jobs, and
Apps Script projects, then test behavior against the Merchant API.

## License

MIT
