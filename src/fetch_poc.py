#!/usr/bin/env python3
"""AMENDER milestone 1, step 1: fetch a PoC from the Exploit-DB GitLab mirror.

The live Exploit-DB website is intentionally avoided. Instead the official
read-only GitLab mirror (``exploit-database/exploitdb``) is used: its
``files_exploits.csv`` index maps each EDB id to the exploit's path in the repo,
which is then downloaded raw.

Example::

    python src/fetch_poc.py 52610
    python src/fetch_poc.py 52610 --output-dir data/pocs --force
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


LOGGER = logging.getLogger(__name__)

# Read-only Exploit-DB mirror on GitLab (not the live exploit-db.com site).
MIRROR_RAW_BASE = "https://gitlab.com/exploit-database/exploitdb/-/raw/main"
INDEX_CSV_URL = f"{MIRROR_RAW_BASE}/files_exploits.csv"
USER_AGENT = "amender-fetch-poc/1.0 (local OpenEMR research)"


@dataclass(frozen=True)
class FetchResult:
    """Outcome of a successful fetch."""

    edb_id: str
    mirror_path: str
    description: str
    cve: str
    source_url: str
    local_path: Path


def _http_get(url: str, timeout: int) -> bytes:
    """GET ``url`` and return the raw body, raising RuntimeError on failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"Request to {url} failed: {reason}") from exc


def resolve_mirror_path(edb_id: str, timeout: int = 60) -> dict[str, str]:
    """Return the mirror index row for ``edb_id`` (file, description, codes...).

    Streams the index CSV line by line so the whole file need not be held in
    memory, and stops as soon as the row is found.
    """
    LOGGER.info("Resolving EDB %s against the mirror index", edb_id)
    payload = _http_get(INDEX_CSV_URL, timeout)
    reader = csv.DictReader(io.StringIO(payload.decode("utf-8", errors="replace")))
    for row in reader:
        if row.get("id") == str(edb_id):
            LOGGER.info("EDB %s -> %s", edb_id, row.get("file"))
            return row
    raise RuntimeError(f"EDB id {edb_id} not found in the mirror index.")


def fetch_poc(
    edb_id: str,
    output_dir: Path,
    *,
    force: bool = False,
    timeout: int = 60,
) -> FetchResult:
    """Download the PoC for ``edb_id`` into ``output_dir`` and return its metadata."""
    row = resolve_mirror_path(edb_id, timeout=timeout)
    mirror_path = row["file"]  # e.g. exploits/multiple/webapps/52610.py
    raw_url = f"{MIRROR_RAW_BASE}/{mirror_path}"

    output_dir.mkdir(parents=True, exist_ok=True)
    local_path = output_dir / Path(mirror_path).name

    if local_path.exists() and not force:
        LOGGER.info("Already present (use --force to re-download): %s", local_path)
    else:
        LOGGER.info("Downloading %s", raw_url)
        body = _http_get(raw_url, timeout)
        local_path.write_bytes(body)
        LOGGER.info("Saved %d bytes -> %s", len(body), local_path)

    return FetchResult(
        edb_id=str(edb_id),
        mirror_path=mirror_path,
        description=row.get("description", ""),
        cve=row.get("codes", ""),
        source_url=raw_url,
        local_path=local_path,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch an Exploit-DB PoC from the GitLab mirror.",
    )
    parser.add_argument("edb_id", help="Exploit-DB entry id (e.g. 52610).")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/pocs"),
        help="Directory to save the PoC into (default: data/pocs).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if the file already exists locally.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-request network timeout in seconds (default: 60).",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging.")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    try:
        result = fetch_poc(
            args.edb_id,
            args.output_dir,
            force=args.force,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        LOGGER.error("%s", exc)
        return 1

    print("\n[+] Fetched Exploit-DB PoC")
    print(f"    EDB id:      {result.edb_id}")
    print(f"    Description: {result.description}")
    print(f"    CVE:         {result.cve or '(none listed)'}")
    print(f"    Mirror path: {result.mirror_path}")
    print(f"    Source URL:  {result.source_url}")
    print(f"    Saved to:    {result.local_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
