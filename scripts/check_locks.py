"""Verify exact dependency locks through the canonical compile wrapper."""

from scripts.compile_locks import check_locks


def main() -> int:
    return check_locks()


if __name__ == "__main__":
    raise SystemExit(main())
