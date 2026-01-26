#!/usr/bin/env python3
"""
stout cask index sync script.

Fetches cask data from Homebrew API and builds:
1. SQLite index database (casks/index.db.zst)
2. Individual cask JSON files (casks/data/<letter>/<token>.json.zst)
3. Local manifest file (casks/manifest.json)
"""

import argparse
import asyncio
import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

import aiohttp
import zstandard as zstd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Homebrew API endpoint
HOMEBREW_CASK_API = "https://formulae.brew.sh/api/cask.json"

# Compression level (19 = max)
ZSTD_LEVEL = 19

# Concurrency settings
MAX_CONCURRENT_WRITES = 100


async def fetch_homebrew_casks(session: aiohttp.ClientSession) -> list[dict]:
    """Fetch all casks from Homebrew API."""
    log.info(f"Fetching casks from {HOMEBREW_CASK_API}")
    async with session.get(HOMEBREW_CASK_API) as response:
        response.raise_for_status()
        casks = await response.json()
    log.info(f"Fetched {len(casks)} casks")
    return casks


def extract_artifacts(hb_cask: dict) -> list[dict]:
    """Extract and normalize artifact definitions."""
    artifacts = []

    for artifact in hb_cask.get("artifacts", []):
        if isinstance(artifact, dict):
            # Handle different artifact types
            if "app" in artifact:
                apps = artifact["app"]
                if isinstance(apps, list):
                    for app in apps:
                        if isinstance(app, str):
                            artifacts.append({"type": "app", "source": app})
                        elif isinstance(app, list) and len(app) >= 1:
                            artifacts.append({"type": "app", "source": app[0], "target": app[1] if len(app) > 1 else None})

            elif "pkg" in artifact:
                pkgs = artifact["pkg"]
                if isinstance(pkgs, list):
                    for pkg in pkgs:
                        if isinstance(pkg, str):
                            artifacts.append({"type": "pkg", "path": pkg})
                        elif isinstance(pkg, list) and len(pkg) >= 1:
                            artifacts.append({"type": "pkg", "path": pkg[0]})

            elif "binary" in artifact:
                bins = artifact["binary"]
                if isinstance(bins, list):
                    for b in bins:
                        if isinstance(b, str):
                            artifacts.append({"type": "binary", "source": b})
                        elif isinstance(b, list) and len(b) >= 1:
                            artifacts.append({"type": "binary", "source": b[0], "target": b[1] if len(b) > 1 else None})

            elif "zap" in artifact:
                artifacts.append({"type": "zap", "stanza": artifact["zap"]})

            elif "uninstall" in artifact:
                artifacts.append({"type": "uninstall", "stanza": artifact["uninstall"]})

            elif "prefpane" in artifact:
                items = artifact["prefpane"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "prefpane", "source": item})

            elif "qlplugin" in artifact:
                items = artifact["qlplugin"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "qlplugin", "source": item})

            elif "mdimporter" in artifact:
                items = artifact["mdimporter"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "mdimporter", "source": item})

            elif "colorpicker" in artifact:
                items = artifact["colorpicker"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "colorpicker", "source": item})

            elif "dictionary" in artifact:
                items = artifact["dictionary"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "dictionary", "source": item})

            elif "font" in artifact:
                items = artifact["font"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "font", "source": item})

            elif "service" in artifact:
                items = artifact["service"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "service", "source": item})

            elif "input_method" in artifact:
                items = artifact["input_method"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "input_method", "source": item})

            elif "internet_plugin" in artifact:
                items = artifact["internet_plugin"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "internet_plugin", "source": item})

            elif "audio_unit_plugin" in artifact:
                items = artifact["audio_unit_plugin"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "audio_unit_plugin", "source": item})

            elif "vst_plugin" in artifact:
                items = artifact["vst_plugin"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "vst_plugin", "source": item})

            elif "vst3_plugin" in artifact:
                items = artifact["vst3_plugin"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "vst3_plugin", "source": item})

            elif "screen_saver" in artifact:
                items = artifact["screen_saver"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "screen_saver", "source": item})

            elif "suite" in artifact:
                items = artifact["suite"]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            artifacts.append({"type": "suite", "source": item})

    return artifacts


def transform_cask(hb_cask: dict) -> dict:
    """Transform Homebrew cask JSON to stout format."""
    # Extract artifacts
    artifacts = extract_artifacts(hb_cask)

    # Build stout format
    return {
        "token": hb_cask["token"],
        "name": hb_cask.get("name", []),
        "version": hb_cask.get("version"),
        "sha256": hb_cask.get("sha256"),
        "url": hb_cask.get("url"),
        "homepage": hb_cask.get("homepage"),
        "desc": hb_cask.get("desc"),
        "tap": hb_cask.get("tap", "homebrew/cask"),
        "artifacts": artifacts,
        "caveats": hb_cask.get("caveats"),
        "depends_on": hb_cask.get("depends_on", {}),
        "conflicts_with": hb_cask.get("conflicts_with"),
        "auto_updates": hb_cask.get("auto_updates", False),
        "deprecated": hb_cask.get("deprecated", False),
        "disabled": hb_cask.get("disabled", False),
        "container": hb_cask.get("container"),
        "meta": {
            "ruby_source_path": hb_cask.get("ruby_source_path"),
            "tap_git_head": hb_cask.get("tap_git_head"),
        },
    }


def create_database(db_path: Path) -> sqlite3.Connection:
    """Create SQLite database with schema."""
    log.info(f"Creating database at {db_path}")

    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)

    conn.executescript(
        """
        -- Cask metadata
        CREATE TABLE casks (
            token TEXT PRIMARY KEY,
            name TEXT,
            version TEXT,
            sha256 TEXT,
            url TEXT,
            homepage TEXT,
            desc TEXT,
            tap TEXT DEFAULT 'homebrew/cask',
            auto_updates INTEGER DEFAULT 0,
            deprecated INTEGER DEFAULT 0,
            disabled INTEGER DEFAULT 0,
            json_hash TEXT,
            updated_at INTEGER
        );

        -- Full-text search
        CREATE VIRTUAL TABLE casks_fts USING fts5(
            token, name, desc,
            content='casks',
            content_rowid='rowid'
        );

        -- Triggers for FTS sync
        CREATE TRIGGER casks_ai AFTER INSERT ON casks BEGIN
            INSERT INTO casks_fts(rowid, token, name, desc)
            VALUES (NEW.rowid, NEW.token, NEW.name, NEW.desc);
        END;

        CREATE TRIGGER casks_ad AFTER DELETE ON casks BEGIN
            INSERT INTO casks_fts(casks_fts, rowid, token, name, desc)
            VALUES('delete', OLD.rowid, OLD.token, OLD.name, OLD.desc);
        END;

        CREATE TRIGGER casks_au AFTER UPDATE ON casks BEGIN
            INSERT INTO casks_fts(casks_fts, rowid, token, name, desc)
            VALUES('delete', OLD.rowid, OLD.token, OLD.name, OLD.desc);
            INSERT INTO casks_fts(rowid, token, name, desc)
            VALUES (NEW.rowid, NEW.token, NEW.name, NEW.desc);
        END;

        -- Artifacts
        CREATE TABLE cask_artifacts (
            cask TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            source TEXT,
            target TEXT,
            FOREIGN KEY (cask) REFERENCES casks(token)
        );

        -- Dependencies
        CREATE TABLE cask_dependencies (
            cask TEXT NOT NULL,
            dep_type TEXT NOT NULL,
            dep_value TEXT NOT NULL,
            PRIMARY KEY (cask, dep_type, dep_value),
            FOREIGN KEY (cask) REFERENCES casks(token)
        );

        -- Index metadata
        CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        -- Indexes
        CREATE INDEX idx_cask_artifacts_cask ON cask_artifacts(cask);
        CREATE INDEX idx_cask_artifacts_type ON cask_artifacts(artifact_type);
        CREATE INDEX idx_cask_dependencies_cask ON cask_dependencies(cask);
        CREATE INDEX idx_casks_tap ON casks(tap);
    """
    )

    return conn


def compress_json(data: dict) -> bytes:
    """Compress JSON data with zstd."""
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    compressor = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    return compressor.compress(json_bytes)


def sha256_bytes(data: bytes) -> str:
    """Calculate SHA256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


async def write_cask_json(
    cask_data: dict,
    data_dir: Path,
    semaphore: asyncio.Semaphore,
) -> tuple[str, str]:
    """Write compressed JSON for a single cask. Returns (token, hash)."""
    async with semaphore:
        token = cask_data["token"]
        compressed = compress_json(cask_data)
        json_hash = sha256_bytes(compressed)

        first_letter = token[0].lower()
        letter_dir = data_dir / first_letter
        letter_dir.mkdir(exist_ok=True)

        cask_path = letter_dir / f"{token}.json.zst"

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, cask_path.write_bytes, compressed)

        return token, json_hash


async def sync(output_dir: Path, full: bool = False) -> dict:
    """
    Sync casks from Homebrew API.

    Returns manifest dict.
    """
    casks_dir = output_dir / "casks"
    casks_dir.mkdir(parents=True, exist_ok=True)
    data_dir = casks_dir / "data"
    data_dir.mkdir(exist_ok=True)

    # Fetch casks
    async with aiohttp.ClientSession() as session:
        hb_casks = await fetch_homebrew_casks(session)

    # Transform all casks
    log.info("Transforming casks...")
    loop = asyncio.get_event_loop()
    stout_casks = await loop.run_in_executor(
        None,
        lambda: [transform_cask(c) for c in hb_casks]
    )

    # Write individual JSON files in parallel
    log.info("Writing individual JSON files...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_WRITES)

    write_tasks = [
        write_cask_json(cask, data_dir, semaphore)
        for cask in stout_casks
    ]

    results = await asyncio.gather(*write_tasks)
    json_hashes = {token: hash_val for token, hash_val in results}

    log.info(f"Wrote {len(results)} JSON files")

    # Create database
    db_path = casks_dir / "index.db"
    conn = create_database(db_path)
    cursor = conn.cursor()

    timestamp = int(datetime.utcnow().timestamp())
    cask_count = 0

    log.info("Inserting into database...")

    for stout_cask in stout_casks:
        token = stout_cask["token"]
        json_hash = json_hashes.get(token, "")

        version = stout_cask["version"] or ""
        sha256 = stout_cask["sha256"]
        url = stout_cask["url"]
        homepage = stout_cask["homepage"]
        desc = stout_cask["desc"]
        tap = stout_cask.get("tap", "homebrew/cask")
        auto_updates = 1 if stout_cask["auto_updates"] else 0
        deprecated = 1 if stout_cask["deprecated"] else 0
        disabled = 1 if stout_cask["disabled"] else 0

        name_str = ", ".join(stout_cask["name"]) if stout_cask["name"] else token

        cursor.execute(
            """
            INSERT INTO casks (token, name, version, sha256, url, homepage, desc, tap,
                               auto_updates, deprecated, disabled, json_hash, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                name_str,
                version,
                sha256,
                url,
                homepage,
                desc,
                tap,
                auto_updates,
                deprecated,
                disabled,
                json_hash,
                timestamp,
            ),
        )

        # Insert artifacts
        for artifact in stout_cask["artifacts"]:
            artifact_type = artifact.get("type", "")
            source = artifact.get("source", artifact.get("path", ""))
            target = artifact.get("target")

            cursor.execute(
                "INSERT INTO cask_artifacts (cask, artifact_type, source, target) VALUES (?, ?, ?, ?)",
                (token, artifact_type, source, target),
            )

        # Insert dependencies
        depends_on = stout_cask.get("depends_on", {})
        if depends_on:
            if "formula" in depends_on:
                for formula in depends_on["formula"]:
                    cursor.execute(
                        "INSERT OR IGNORE INTO cask_dependencies (cask, dep_type, dep_value) VALUES (?, ?, ?)",
                        (token, "formula", formula),
                    )
            if "cask" in depends_on:
                for cask in depends_on["cask"]:
                    cursor.execute(
                        "INSERT OR IGNORE INTO cask_dependencies (cask, dep_type, dep_value) VALUES (?, ?, ?)",
                        (token, "cask", cask),
                    )
            if "macos" in depends_on:
                macos = depends_on["macos"]
                if isinstance(macos, dict):
                    for op, versions in macos.items():
                        for v in (versions if isinstance(versions, list) else [versions]):
                            cursor.execute(
                                "INSERT OR IGNORE INTO cask_dependencies (cask, dep_type, dep_value) VALUES (?, ?, ?)",
                                (token, f"macos_{op}", str(v)),
                            )
                elif isinstance(macos, str):
                    cursor.execute(
                        "INSERT OR IGNORE INTO cask_dependencies (cask, dep_type, dep_value) VALUES (?, ?, ?)",
                        (token, "macos", macos),
                    )

        cask_count += 1

        if cask_count % 1000 == 0:
            log.info(f"  Inserted {cask_count} casks...")

    # Set metadata
    version = datetime.utcnow().strftime("%Y.%m.%d.%H%M")
    cursor.execute("INSERT INTO meta (key, value) VALUES ('version', ?)", (version,))
    cursor.execute(
        "INSERT INTO meta (key, value) VALUES ('created_at', ?)",
        (datetime.utcnow().isoformat(),),
    )
    cursor.execute(
        "INSERT INTO meta (key, value) VALUES ('cask_count', ?)", (str(cask_count),)
    )

    conn.commit()
    conn.close()

    log.info(f"Processed {cask_count} casks")

    # Compress database
    log.info("Compressing database...")
    db_bytes = db_path.read_bytes()
    compressor = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    compressed_db = compressor.compress(db_bytes)

    compressed_path = casks_dir / "index.db.zst"
    compressed_path.write_bytes(compressed_db)

    # Remove uncompressed database
    db_path.unlink()

    db_hash = sha256_bytes(compressed_db)
    log.info(
        f"Database: {len(db_bytes)} bytes -> {len(compressed_db)} bytes ({len(compressed_db)/len(db_bytes)*100:.1f}%)"
    )

    # Create manifest
    manifest = {
        "version": version,
        "cask_index_version": version,
        "cask_index_sha256": db_hash,
        "cask_index_size": len(compressed_db),
        "cask_count": cask_count,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    manifest_path = casks_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    log.info(f"Created manifest: {manifest_path}")
    log.info(f"Version: {version}")

    return manifest


async def main_async():
    parser = argparse.ArgumentParser(description="Sync stout cask index from Homebrew API")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("."),
        help="Output directory (default: current directory)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Full rebuild (ignore incremental)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing files",
    )

    args = parser.parse_args()

    if args.dry_run:
        log.info("Dry run mode - no files will be written")
        async with aiohttp.ClientSession() as session:
            casks = await fetch_homebrew_casks(session)
        log.info(f"Would process {len(casks)} casks")
        return

    manifest = await sync(args.output, full=args.full)

    log.info("Sync complete!")
    log.info(f"  Version: {manifest['version']}")
    log.info(f"  Casks: {manifest['cask_count']}")
    log.info(f"  Index size: {manifest['cask_index_size']} bytes")


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
