#!/usr/bin/env python3
"""
stout index signing tool.

This script handles:
1. Generating Ed25519 keypairs for signing
2. Signing index manifests
3. Verifying signatures

The private key should be kept secure (GitHub Secrets for CI).
The public key is embedded in the stout binary.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:
    print("Error: cryptography package required. Install with: pip install cryptography")
    sys.exit(1)


def generate_keypair(output_dir: Path) -> tuple[str, str]:
    """Generate a new Ed25519 keypair.

    Returns (public_key_hex, private_key_hex)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get raw bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_hex = private_bytes.hex()
    public_hex = public_bytes.hex()

    # Save keys
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = output_dir / "stout-index.key"
    public_key_path = output_dir / "stout-index.pub"

    # Private key - restricted permissions
    private_key_path.write_text(private_hex)
    os.chmod(private_key_path, 0o600)

    # Public key - can be shared
    public_key_path.write_text(public_hex)

    print(f"Generated keypair:")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key:  {public_key_path}")
    print(f"")
    print(f"Public key (hex): {public_hex}")
    print(f"")
    print(f"⚠️  Keep the private key secure!")
    print(f"   Add it to GitHub Secrets as STOUT_SIGNING_KEY")
    print(f"")
    print(f"📋 Update stout source with this public key:")
    print(f'   pub const DEFAULT_PUBLIC_KEY_HEX: &str = "{public_hex}";')

    return public_hex, private_hex


def load_private_key(key_source: str) -> Ed25519PrivateKey:
    """Load private key from hex string, file path, or environment variable."""
    # Check if it's an environment variable name
    if key_source.startswith("$"):
        env_var = key_source[1:]
        key_hex = os.environ.get(env_var)
        if not key_hex:
            raise ValueError(f"Environment variable {env_var} not set")
    # Check if it's a file path
    elif Path(key_source).exists():
        key_hex = Path(key_source).read_text().strip()
    # Assume it's a hex string
    else:
        key_hex = key_source

    key_bytes = bytes.fromhex(key_hex)
    return Ed25519PrivateKey.from_private_bytes(key_bytes)


def load_public_key(key_source: str) -> Ed25519PublicKey:
    """Load public key from hex string or file path."""
    if Path(key_source).exists():
        key_hex = Path(key_source).read_text().strip()
    else:
        key_hex = key_source

    key_bytes = bytes.fromhex(key_hex)
    return Ed25519PublicKey.from_public_bytes(key_bytes)


def compute_file_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sign_manifest(
    index_dir: Path,
    private_key: Ed25519PrivateKey,
    index_type: str = "formulas",
) -> dict:
    """Sign an index manifest.

    Args:
        index_dir: Directory containing the index (e.g., formulas/)
        private_key: Ed25519 private key for signing
        index_type: Type of index (formulas, casks, linux-apps, vulnerabilities)

    Returns:
        Signed manifest dict
    """
    # Find the index database
    db_path = index_dir / "index.db.zst"
    if not db_path.exists():
        raise FileNotFoundError(f"Index database not found: {db_path}")

    # Load existing manifest if present
    manifest_path = index_dir / "manifest.json"
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text())
    else:
        existing = {}

    # Compute hash of the compressed database
    db_hash = compute_file_sha256(db_path)
    db_size = db_path.stat().st_size

    # Get counts from existing manifest or default
    formula_count = existing.get("formula_count", existing.get("count", 0))
    cask_count = existing.get("cask_count", 0)

    # Build the manifest
    version = 1  # Manifest format version
    signed_at = int(time.time())
    index_version = existing.get("version", time.strftime("%Y.%m.%d.%H%M"))

    # Create the signed data string (must match Rust verification)
    signed_data = f"stout-index:v{version}:{db_hash}:{signed_at}:{index_version}:{formula_count}:{cask_count}"

    # Sign the data
    signature = private_key.sign(signed_data.encode())
    signature_hex = signature.hex()

    # Build signed manifest
    # Note: Rust expects version as String (the index version), not format version
    signed_manifest = {
        "version": index_version,  # Index version (used by Rust Manifest.version)
        "index_version": index_version,  # Also keep for compatibility
        "index_sha256": db_hash,
        "index_size": db_size,
        "signed_at": signed_at,
        "formula_count": formula_count,
        "cask_count": cask_count,
        "signature": signature_hex,
        "created_at": existing.get("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
    }

    return signed_manifest


def verify_manifest(manifest: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify a signed manifest.

    Returns True if signature is valid.
    """
    # Reconstruct signed data - always use format version 1
    # The signed_data format must match what's used in sign_manifest and Rust code
    signed_data = (
        f"stout-index:v1:"
        f"{manifest['index_sha256']}:"
        f"{manifest['signed_at']}:"
        f"{manifest.get('index_version', manifest['version'])}:"
        f"{manifest['formula_count']}:"
        f"{manifest.get('cask_count', 0)}"
    )

    signature = bytes.fromhex(manifest["signature"])

    try:
        public_key.verify(signature, signed_data.encode())
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


def sign_all_indexes(base_dir: Path, private_key: Ed25519PrivateKey) -> dict:
    """Sign all indexes and update the root manifest."""
    indexes = {}

    # Sign each index type
    for index_name in ["formulas", "casks", "linux-apps", "vulnerabilities"]:
        index_dir = base_dir / index_name
        if not index_dir.exists():
            continue

        db_path = index_dir / "index.db.zst"
        if not db_path.exists():
            continue

        print(f"Signing {index_name}...")
        signed = sign_manifest(index_dir, private_key, index_name)

        # Write index-specific manifest
        manifest_path = index_dir / "manifest.json"
        manifest_path.write_text(json.dumps(signed, indent=2))
        print(f"  Wrote {manifest_path}")

        # Add to root manifest
        indexes[index_name] = {
            "count": signed.get("formula_count", signed.get("cask_count", 0)),
            "db_sha256": signed["index_sha256"],
            "db_size": signed["index_size"],
            "signature": signed["signature"],
            "signed_at": signed["signed_at"],
            "updated_at": signed["created_at"],
        }

    # Create/update root manifest
    root_manifest_path = base_dir / "manifest.json"
    if root_manifest_path.exists():
        root_manifest = json.loads(root_manifest_path.read_text())
    else:
        root_manifest = {}

    root_manifest.update({
        "version": time.strftime("%Y.%m.%d.%H%M"),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stout_min_version": "0.1.0",
        "indexes": indexes,
    })

    root_manifest_path.write_text(json.dumps(root_manifest, indent=2))
    print(f"Updated root manifest: {root_manifest_path}")

    return root_manifest


def main():
    parser = argparse.ArgumentParser(
        description="stout index signing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a new keypair
  python sign_index.py generate --output ./keys

  # Sign all indexes using key from environment
  python sign_index.py sign --key '$STOUT_SIGNING_KEY' --index-dir ../

  # Sign using key file
  python sign_index.py sign --key ./keys/stout-index.key --index-dir ../

  # Verify a manifest
  python sign_index.py verify --key ./keys/stout-index.pub --manifest ../formulas/manifest.json
""",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate a new Ed25519 keypair")
    gen_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("./keys"),
        help="Output directory for keys (default: ./keys)",
    )

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign index manifests")
    sign_parser.add_argument(
        "--key", "-k",
        required=True,
        help="Private key (hex string, file path, or $ENV_VAR)",
    )
    sign_parser.add_argument(
        "--index-dir", "-d",
        type=Path,
        default=Path(".."),
        help="Root index directory (default: ../)",
    )

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signed manifest")
    verify_parser.add_argument(
        "--key", "-k",
        required=True,
        help="Public key (hex string or file path)",
    )
    verify_parser.add_argument(
        "--manifest", "-m",
        type=Path,
        required=True,
        help="Manifest file to verify",
    )

    args = parser.parse_args()

    if args.command == "generate":
        generate_keypair(args.output)

    elif args.command == "sign":
        private_key = load_private_key(args.key)
        sign_all_indexes(args.index_dir, private_key)
        print("\n✓ All indexes signed successfully")

    elif args.command == "verify":
        public_key = load_public_key(args.key)
        manifest = json.loads(args.manifest.read_text())

        if verify_manifest(manifest, public_key):
            print("✓ Signature is valid")
            print(f"  Index version: {manifest['index_version']}")
            print(f"  Signed at: {time.ctime(manifest['signed_at'])}")
            print(f"  SHA256: {manifest['index_sha256']}")
        else:
            print("✗ Signature is INVALID")
            sys.exit(1)


if __name__ == "__main__":
    main()
