# FortiCNAPP Scripts

Helper scripts for querying FortiCNAPP (Lacework) data. Dependencies are managed with [uv](https://docs.astral.sh/uv/).

## Contents

| File | Purpose |
|------|---------|
| `forticnapp_hosts_by_cve.py` | List hosts affected by one or more CVEs via the Lacework v2 API |
| `pyproject.toml` | Project metadata and dependencies (`requests`) |
| `uv.lock` | Locked dependency versions |
| `.python-version` | Python version used by uv (3.13) |

## Prerequisites

- [uv](https://docs.astral.sh/uv/getting-started/installation/) installed
- A FortiCNAPP API key (key ID and secret) with permission to read vulnerability data

## Setup

From this directory:

```bash
uv sync
```

This creates `.venv/` and installs the locked dependencies. You can skip it: `uv run` does the same on first use.

## Configuration

The script reads credentials from environment variables:

```bash
export LW_ACCOUNT="youraccount"       # the part before .lacework.net
export LW_API_KEY="YOUR_KEY_ID"
export LW_API_SECRET="YOUR_SECRET"
```

## Usage: `forticnapp_hosts_by_cve.py`

```bash
uv run forticnapp_hosts_by_cve.py CVE-2024-3094 CVE-2021-44228 --days 1 --csv out.csv
```

| Argument | Description |
|----------|-------------|
| `cves` | One or more CVE IDs (case-insensitive, required) |
| `--days N` | Look-back window in days (default: `1`) |
| `--csv PATH` | Also write the results to a CSV file |

The script:

1. Exchanges the key ID and secret for a one-hour bearer token.
2. Queries `POST /api/v2/Vulnerabilities/Hosts/search`, using `eq` for a single CVE and `in` for several.
3. Follows `nextPage` links until all results are retrieved.
4. Deduplicates to one row per host, CVE, package and installed version.
5. Prints a summary and, if `--csv` is set, writes the rows to a file.

### Output columns

`machine_id`, `hostname`, `cve`, `severity`, `package`, `version`, `status`, `fix_version`

## Managing dependencies

```bash
uv add <package>      # add a dependency
uv remove <package>   # remove a dependency
uv lock --upgrade     # refresh uv.lock to the latest allowed versions
```

## Troubleshooting

- **`Set LW_ACCOUNT, LW_API_KEY and LW_API_SECRET environment variables.`**: one or more variables are unset.
- **HTTP 401/403**: check the key ID, secret and account name, and that the key has the required permissions.
- **No results**: increase `--days`. Only records evaluated inside the time window are returned.
