# brewx-index

Pre-computed package index for [brewx](https://github.com/neul-labs/brewx), a fast Rust-based Homebrew-compatible package manager.

## Overview

This repository contains pre-processed package metadata that brewx downloads for instant searches and queries. By pre-computing indexes at build time rather than runtime, brewx achieves 10-100x faster operations than traditional package managers.

## Index Structure

```
brewx-index/
├── manifest.json           # Version info, checksums, package counts
├── formulas/
│   ├── index.db.zst        # SQLite database with FTS5 search (~1.5MB)
│   └── data/
│       ├── a/
│       │   ├── aom.json.zst
│       │   └── ...
│       ├── b/
│       └── ...
├── casks/
│   ├── index.db.zst        # Cask metadata database
│   └── data/
│       └── <letter>/<token>.json.zst
├── linux-apps/
│   ├── index.db.zst        # AppImage/Flatpak index
│   └── data/
│       └── <id>.json.zst
└── vulnerabilities/
    └── index.db.zst        # CVE mappings for audit
```

## Automatic Updates

This index is automatically updated via GitHub Actions:

| Schedule | Workflow | Description |
|----------|----------|-------------|
| Every 4 hours | `sync.yml` | Full sync of all indexes |
| On push to main | `sync.yml` | Triggered on script changes |
| Manual | `sync.yml` | Dispatch via Actions UI |

## Data Sources

| Index | Source | Update Frequency |
|-------|--------|------------------|
| Formulas | [Homebrew Formula API](https://formulae.brew.sh/api/formula.json) | Daily |
| Casks | [Homebrew Cask API](https://formulae.brew.sh/api/cask.json) | Daily |
| Linux Apps | AppImageHub + Flathub | Daily |
| Vulnerabilities | [OSV Database](https://osv.dev) | Daily |

## Using the Index

### For brewx Users

brewx automatically downloads and caches this index:

```bash
# Update to latest index
brewx update

# Force re-download
brewx update --force
```

### For Developers

The index can be accessed directly:

```bash
# Base URL
https://raw.githubusercontent.com/neul-labs/brewx-index/main/

# Manifest (version info)
curl -s https://raw.githubusercontent.com/neul-labs/brewx-index/main/manifest.json

# Formula index (compressed SQLite)
curl -LO https://raw.githubusercontent.com/neul-labs/brewx-index/main/formulas/index.db.zst

# Individual formula
curl -s https://raw.githubusercontent.com/neul-labs/brewx-index/main/formulas/data/j/jq.json.zst | zstd -d
```

## Manifest Schema

```json
{
  "version": "2024.01.15.1200",
  "created_at": "2024-01-15T12:00:00Z",
  "brewx_min_version": "0.1.0",
  "indexes": {
    "formulas": {
      "count": 8000,
      "db_sha256": "abc123...",
      "db_size": 1500000,
      "updated_at": "2024-01-15T12:00:00Z"
    },
    "casks": {
      "count": 6000,
      "db_sha256": "def456...",
      "db_size": 800000,
      "updated_at": "2024-01-15T12:00:00Z"
    },
    "linux_apps": {
      "count": 2000,
      "db_sha256": "789abc...",
      "db_size": 300000,
      "updated_at": "2024-01-15T12:00:00Z"
    },
    "vulnerabilities": {
      "count": 5000,
      "db_sha256": "xyz789...",
      "db_size": 200000,
      "updated_at": "2024-01-15T12:00:00Z"
    }
  }
}
```

## Local Development

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- zstd

### Running Sync Scripts

```bash
# Install dependencies
cd scripts
uv sync

# Sync formulas
uv run python sync.py --output ../

# Sync casks
uv run python sync_casks.py --output ../

# Sync Linux apps
uv run python sync_linux_apps.py --output ../

# Sync vulnerabilities
uv run python sync_vulns.py --output ../

# Full sync (all indexes)
./sync_all.sh
```

### Testing Changes

```bash
# Verify manifest
python -c "import json; json.load(open('manifest.json'))"

# Check SQLite database
zstd -d formulas/index.db.zst -o /tmp/index.db
sqlite3 /tmp/index.db "SELECT COUNT(*) FROM formulas"

# Verify individual formula
zstd -d formulas/data/j/jq.json.zst | python -m json.tool
```

## Contributing

To improve the index:

1. Fork this repository
2. Make changes to sync scripts in `scripts/`
3. Test locally with `./scripts/sync_all.sh`
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

The index data is derived from:
- Homebrew (BSD 2-Clause)
- AppImageHub (various licenses)
- Flathub (various licenses)
- OSV Database (Apache 2.0)
