# npm-validator GitHub Action

Scan a repository for compromised npm package versions using the curated list bundled inside this action. No outbound network calls are required unless you deliberately override the list source.

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
| `findings` | Total number of compromised package occurrences detected. |
| `report-path` | Absolute path to the generated JSON report. |
| `summary-path` | Absolute path to the Markdown summary (also written to the GitHub step summary). |
| `inventory-path` | Absolute path to the tab-delimited package inventory. |

## Environment Variables

- `NPM_VALIDATOR_WARN_ONLY` (default: empty) — when set to `true`, findings are reported but do not fail the job.
- `NPM_VALIDATOR_CREATE_GH_ISSUE` (default: empty) — when `true`, the action creates or updates a single GitHub issue enumerating findings (requires `GITHUB_TOKEN` with `issues:write`).

## Exit Codes

- `0`: No findings or warning-only mode.
- `10`: Findings detected (job fails).
- `>=20`: Unexpected error (schema validation, parsing, download failure when using a remote list, etc.).

## License

Distributed under the PolyForm Shield License. See `LICENSE` in this repository for details; usage is permitted, but modifications and redistribution are restricted.
