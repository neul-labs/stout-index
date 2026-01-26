#!/usr/bin/env python3
"""
Update the main manifest.json with information from all indexes.
"""

import argparse
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def sha256_file(path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_index_info(base_dir: Path, index_name: str, db_name: str = "index.db.zst") -> dict:
    """Get info about an index database."""
    index_dir = base_dir / index_name
    db_path = index_dir / db_name

    if not db_path.exists():
        return {
            "count": 0,
            "db_sha256": "",
            "db_size": 0,
            "updated_at": "1970-01-01T00:00:00Z",
        }

    db_size = db_path.stat().st_size
    db_sha256 = sha256_file(db_path)
    updated_at = datetime.fromtimestamp(db_path.stat().st_mtime).isoformat() + "Z"

    # Try to get count from local manifest or estimate
    local_manifest = index_dir / "manifest.json"
    count = 0
    if local_manifest.exists():
        try:
            with open(local_manifest) as f:
                data = json.load(f)
                # Try different count field names
                count = (
                    data.get("formula_count") or
                    data.get("cask_count") or
                    data.get("vulnerability_count") or
                    data.get("count") or
                    0
                )
        except (json.JSONDecodeError, KeyError):
            pass

    return {
        "count": count,
        "db_sha256": db_sha256,
        "db_size": db_size,
        "updated_at": updated_at,
    }


def update_manifest(output_dir: Path) -> dict:
    """Update the main manifest.json with all index information."""
    log.info(f"Updating manifest in {output_dir}")

    # Get info for each index
    formulas_info = get_index_info(output_dir, "formulas")
    casks_info = get_index_info(output_dir, "casks")
    linux_apps_info = get_index_info(output_dir, "linux-apps")
    vulns_info = get_index_info(output_dir, "vulnerabilities")

    # Also check for index.db.zst in root (legacy location)
    root_db = output_dir / "index.db.zst"
    if root_db.exists() and formulas_info["count"] == 0:
        formulas_info = {
            "count": 0,  # Will need to be set from sync.py
            "db_sha256": sha256_file(root_db),
            "db_size": root_db.stat().st_size,
            "updated_at": datetime.fromtimestamp(root_db.stat().st_mtime).isoformat() + "Z",
        }
        # Try to get count from root manifest
        root_manifest = output_dir / "manifest.json"
        if root_manifest.exists():
            try:
                with open(root_manifest) as f:
                    data = json.load(f)
                    formulas_info["count"] = data.get("formula_count", 0)
            except (json.JSONDecodeError, KeyError):
                pass

    # Build manifest
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")

    manifest = {
        "version": version,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "stout_min_version": "0.1.0",
        "indexes": {
            "formulas": formulas_info,
            "casks": casks_info,
            "linux_apps": linux_apps_info,
            "vulnerabilities": vulns_info,
        },
    }

    # Write manifest
    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    log.info(f"Updated manifest: {manifest_path}")
    log.info(f"  Version: {version}")
    log.info(f"  Formulas: {formulas_info['count']}")
    log.info(f"  Casks: {casks_info['count']}")
    log.info(f"  Linux Apps: {linux_apps_info['count']}")
    log.info(f"  Vulnerabilities: {vulns_info['count']}")

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Update stout-index manifest")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("."),
        help="Output directory (default: current directory)",
    )

    args = parser.parse_args()
    update_manifest(args.output)


if __name__ == "__main__":
    main()
