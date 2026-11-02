# npm-validator GitHub Action

Scan a repository for compromised or vulnerable npm package versions using the bundled list. The action also checks Node.js versions for the Brotli decoder vulnerability CVE-2026-111497. No outbound network calls are required unless you deliberately override the list source.

The Node.js check reads the `node` executable on the scanner's `PATH` and version declarations in `.nvmrc`, `.node-version`, and `.tool-versions`. It compares versions with the upstream fixes in Node.js 22.23.4, 24.22.1, and 26.12.1. Unsupported Node.js 16–21, 23, and 25 are also potentially affected. Potentially affected versions are findings; this includes partial selectors when all matching upstream versions are affected. Other partial selectors, aliases, unassessed release lines, and unavailable versions are inconclusive and do not block the scan.

A scanner runtime or repository declaration does not establish the version running in production. The scanner probes `node` from an empty temporary directory, so a version-manager shim may select a different version from the one used inside the project. The check does not inspect running processes, container images, or distribution backports; verify the deployed runtime and vendor security updates. The package list also detects affected `bun` npm versions; upgrade to Bun 1.4.4 or later and rebuild compiled Bun executables. See the [Node.js security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) and [Bun advisory](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p).

## Usage

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: salsadigitalauorg/npm-validator-action@v2
        with:
          # optional: use a custom list
          # list-url: https://example.com/compromised_packages.json
          # optional: annotate the summary with a PSA identifier
          # psa-id: PSA-2025-09-17
    env:
      # optional: report findings without failing the job
      NPM_VALIDATOR_WARN_ONLY: "false"
```

## Inputs

| Name | Required | Description |
| --- | --- | --- |
| `list-url` | No | Override path or URL for `compromised_packages.json`. Defaults to the file packaged with the action. |
| `psa-id` | No | Identifier appended to the generated summary (e.g. `PSA-2025-09-17`). |

## Outputs

| Name | Description |
| --- | --- |
| `findings` | Total package findings and potentially affected Node.js runtime checks. |
| `report-path` | Absolute path to the generated JSON report. |
| `summary-path` | Absolute path to the Markdown summary (also written to the GitHub step summary). |
| `inventory-path` | Absolute path to the tab-delimited package inventory. |

## Environment Variables

- `NPM_VALIDATOR_WARN_ONLY` (default: empty) — when set to `true`, findings are reported but do not fail the job.
- `NPM_VALIDATOR_CREATE_GH_ISSUE` (default: empty) — when `true`, the action creates or updates a single GitHub issue enumerating findings (requires `GITHUB_TOKEN` with `issues:write`).

## Exit Codes

- `0`: No blocking findings or warning-only mode. Inconclusive runtime checks do not block.
- `10`: Blocking findings detected (job fails).
- `>=20`: Unexpected error (schema validation, parsing, download failure when using a remote list, etc.).

## License

Distributed under the PolyForm Shield License. See `LICENSE` in this repository for details; usage is permitted, but modifications and redistribution are restricted.

## CLI Package

The repository also ships a standalone CLI that mirrors the GitHub Action so you can run scans
outside GitHub-hosted workflows while retaining identical outputs and exit codes.

### Installation

```
npm install -g @ivangrynenko/npm-validator-cli
# or run without installing globally
npx @ivangrynenko/npm-validator-cli --help
```

### Usage

```
npm-validator --root . --json ./report.json --summary ./summary.md --inventory ./inventory.txt
```

- `--root`: repository path to scan (defaults to the current working directory).
- `--list`: optional path or HTTPS URL for a custom compromised list.
- `--warn-only`: report findings without failing (mirrors `NPM_VALIDATOR_WARN_ONLY`).
- `--summary`, `--json`, `--inventory`: override artifact destinations; otherwise the CLI writes to
  the OS temp directory and reports paths in the final JSON payload.
- `--verbose`: emit structured telemetry logs on stderr for troubleshooting.

The CLI bundles the same Python engine used by the action, so JSON reports, Markdown summaries, and
inventory files are byte-for-byte compatible.

### Release Automation

Publishing the CLI is handled by `.github/workflows/npm-cli-release.yml`, which triggers on
semantic version tags (`v*.*.*`). The workflow rebuilds the bundled Python zipapp, runs the Python
and Node test suites, synchronises changelog entries, creates a GitHub Release, and executes
`npm publish --workspace cli --access public`. Failures automatically open a tooling team issue with
workflow logs for quick triage.
