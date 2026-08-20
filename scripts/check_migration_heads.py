"""Fail when Alembic and the packaged runtime revision are not one exact head."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from identity_service.db.revisions import EXPECTED_MIGRATION_HEAD

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    config = Config(str(ROOT / "alembic.ini"))
    scripts = ScriptDirectory.from_config(config)
    heads = scripts.get_heads()
    if heads != [EXPECTED_MIGRATION_HEAD]:
        print(f"expected one packaged head, found {len(heads)}")
        return 1
    print(f"one Alembic head: {EXPECTED_MIGRATION_HEAD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
