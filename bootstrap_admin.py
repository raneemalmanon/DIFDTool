from __future__ import annotations

import argparse
import getpass
import logging
import sys

from security_auth import AuthError, bootstrap_first_admin, get_auth_store_status


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("difd.bootstrap_admin")


def main() -> int:
    """Create the first local admin account when the app is uninitialized.

    Returns:
        Process exit status. Zero indicates success.
    """
    parser = argparse.ArgumentParser(description="Create the first DIFD admin account.")
    parser.add_argument("--username", required=True, help="Admin username to create.")
    args = parser.parse_args()

    status = get_auth_store_status()
    if status["state"] == "recovery_required":
        LOGGER.error(
            "Bootstrap refused: installation requires auth database recovery. "
            "Auth DB: %s; install seal: %s. Restore a trusted backup.",
            status["auth_db_path"],
            status["install_state_path"],
        )
        return 1
    if status["state"] == "ready":
        LOGGER.error(
            "At least one user exists. Create additional users from the admin UI."
        )
        return 1

    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        LOGGER.error("Passwords do not match.")
        return 1

    try:
        bootstrap_first_admin(args.username, password)
    except AuthError as exc:
        LOGGER.error("Unable to create admin user: %s", exc)
        return 1

    LOGGER.info("Created admin user '%s'.", args.username.strip().lower())
    return 0


if __name__ == "__main__":
    sys.exit(main())
