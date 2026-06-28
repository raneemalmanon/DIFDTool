from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tools.create_local_https_cert import ensure_local_https_cert
from tools.sidecar_token import export_sidecar_token_env


ROOT_DIR = Path(__file__).resolve().parent


def _start_sidecar():
    """Start the BusterNet sidecar automatically if a legacy environment is found."""
    sidecar_dir = ROOT_DIR / "busternet_sidecar"
    sidecar_py = os.getenv("BUSTERNET_PYTHON_EXE")
    if not sidecar_py:
        for venv in [".venv36", ".venv"]:
            potential_py = sidecar_dir / venv / "Scripts" / "python.exe"
            if potential_py.exists():
                sidecar_py = str(potential_py)
                break
    
    if sidecar_py:
        subprocess.Popen([sidecar_py, "run_sidecar.py"], cwd=str(sidecar_dir))


def main() -> int:
    """Launch the Streamlit app over local HTTPS."""

    os.environ["STREAMLIT_CLI_TELEMETRY_OPTOUT"] = "true"
    export_sidecar_token_env()
    _start_sidecar()

    cert_path, key_path = ensure_local_https_cert()
    address = os.getenv("DIFD_STREAMLIT_ADDRESS", "localhost")
    port = os.getenv("DIFD_STREAMLIT_PORT", "8501")

    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(ROOT_DIR / "app.py"),
        "--logger.level=error",
        f"--server.address={address}",
        f"--server.port={port}",
        f"--server.sslCertFile={cert_path}",
        f"--server.sslKeyFile={key_path}",
    ]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
