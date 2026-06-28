import subprocess
import sys
import os
from pathlib import Path

from tools.sidecar_token import export_sidecar_token_env

# Disable the email prompt
os.environ['STREAMLIT_CLI_TELEMETRY_OPTOUT'] = 'true'
export_sidecar_token_env()

def _start_sidecar():
    """Start the BusterNet sidecar automatically if a legacy environment is found."""
    root_dir = Path(__file__).resolve().parent
    sidecar_dir = root_dir / "busternet_sidecar"
    sidecar_py = os.getenv("BUSTERNET_PYTHON_EXE")
    if not sidecar_py:
        for venv in [".venv36", ".venv"]:
            potential_py = sidecar_dir / venv / "Scripts" / "python.exe"
            if potential_py.exists():
                sidecar_py = str(potential_py)
                break
    
    if sidecar_py:
        subprocess.Popen([sidecar_py, "run_sidecar.py"], cwd=str(sidecar_dir))

_start_sidecar()

# Run streamlit
subprocess.run([
    sys.executable, '-m', 'streamlit', 'run',
    '.\\app.py', '--logger.level=error'
])
