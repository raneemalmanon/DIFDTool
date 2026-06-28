from __future__ import annotations

import os
import secrets
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
TOKEN_PATH = Path(os.getenv("DIFD_SIDECAR_TOKEN_FILE", str(ROOT_DIR / "security" / "sidecar_token")))
TOKEN_BYTES = 32


def _restrict_owner_read(path: Path) -> None:
    """Restrict token file permissions on POSIX hosts; Windows uses ACLs."""

    if os.name != "nt":
        path.chmod(0o600)


def ensure_sidecar_token(*, force: bool = False) -> str:
    """Create or read the host-local BusterNet sidecar token.

    Args:
        force: Rotate the token even if one already exists.

    Returns:
        Token text suitable for the `BUSTERNET_TOKEN` environment variable.
    """

    if TOKEN_PATH.exists() and not force:
        token = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if token:
            return token

    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    temp_path = TOKEN_PATH.with_suffix(".tmp")
    temp_path.write_text(token + "\n", encoding="utf-8")
    temp_path.replace(TOKEN_PATH)
    _restrict_owner_read(TOKEN_PATH)
    return token


def export_sidecar_token_env() -> str:
    """Ensure `BUSTERNET_TOKEN` exists in the current process environment."""

    token = os.getenv("BUSTERNET_TOKEN", "").strip() or ensure_sidecar_token()
    os.environ["BUSTERNET_TOKEN"] = token
    return token


def main() -> None:
    """Create the token and print the token-file location, not the secret."""

    token = ensure_sidecar_token()
    print(f"Token file: {TOKEN_PATH}")
    print(f"Token length: {len(token)} characters")


if __name__ == "__main__":
    main()
