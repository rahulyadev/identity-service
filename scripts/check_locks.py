"""Verify locked reproducibility and regenerated hashes through the canonical compiler."""

from scripts.compile_locks import check_locks


def main() -> int:
    return check_locks()


if __name__ == "__main__":
    raise SystemExit(main())
