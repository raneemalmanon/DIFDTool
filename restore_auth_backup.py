from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from security_auth import (
    AUTH_BACKUP_DIR,
    AUTH_DB_PATH,
    create_auth_db_backup,
    log_security_event,
)


CONFIRM_PHRASE = "RESTORE_AUTH_DB"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("difd.restore_auth_backup")


def _list_backups() -> int:
    """List available local authentication database backups.

    Returns:
        Process exit status. Zero indicates at least one backup was listed.
    """
    backups = sorted(
        AUTH_BACKUP_DIR.glob("auth-*.db"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    if not backups:
        LOGGER.error("No auth DB backups found in %s.", AUTH_BACKUP_DIR)
        return 1
    for backup in backups:
        LOGGER.info("%s", backup)
    return 0


def main() -> int:
    """Restore a trusted local authentication database backup.

    Returns:
        Process exit status. Zero indicates success.
    """
    parser = argparse.ArgumentParser(description="Restore a DIFD auth database backup.")
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available auth DB backups.",
    )
    parser.add_argument("--backup", help="Path to the auth DB backup to restore.")
    parser.add_argument(
        "--confirm",
        help=f"Required confirmation phrase for restore: {CONFIRM_PHRASE}",
    )
    args = parser.parse_args()

    if args.list:
        return _list_backups()

    if not args.backup:
        LOGGER.error("Provide --backup or use --list.")
        return 1
    if args.confirm != CONFIRM_PHRASE:
        LOGGER.error(
            "Restore refused. Re-run with --confirm %s after verifying the backup.",
            CONFIRM_PHRASE,
        )
        return 1

    backup_root = AUTH_BACKUP_DIR.resolve()
    backup_path = Path(args.backup).expanduser().resolve()
    try:
        backup_path.relative_to(backup_root)
    except ValueError:
        LOGGER.error("Backup path must be inside %s.", backup_root)
        return 1
    if not backup_path.name.startswith("auth-") or backup_path.suffix != ".db":
        LOGGER.error("Backup file must match the local auth-*.db backup naming policy.")
        return 1
    if not backup_path.exists() or not backup_path.is_file():
        LOGGER.error("Backup file not found: %s", backup_path)
        return 1

    if AUTH_DB_PATH.exists():
        create_auth_db_backup("before_restore", actor="restore_command")

    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_path, AUTH_DB_PATH)
    log_security_event(
        "auth_db_restored",
        username="restore_command",
        success=True,
        message="Auth DB restored from backup.",
        details={"backup_path": str(backup_path), "auth_db_path": str(AUTH_DB_PATH)},
    )
    LOGGER.info("Restored auth DB from %s", backup_path)
    LOGGER.info("Target: %s", AUTH_DB_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
