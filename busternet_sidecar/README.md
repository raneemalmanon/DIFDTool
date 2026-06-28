# BusterNet Sidecar

This directory self-hosts the fine-tuned BusterNet model behind a local-only HTTP API. It serves as a dedicated microservice for the Digital Image Forgery Detector (DIFD) tool.

> **CRITICAL ARCHITECTURE NOTE**
> The BusterNet sidecar **must** run in its own isolated environment. The main Streamlit application cannot run BusterNet inside its own environment due to dependency conflicts. The main app communicates with this sidecar locally over HTTP.

---

## Directory Structure

| Path / File | Description |
| :--- | :--- |
| `official_model/` | Downloaded directly from the official [isi-vista/BusterNet](https://github.com/isi-vista/BusterNet) repository. Includes `BusterNetCore.py`, `BusterNetUtils.py`, `ReadMe.md`, and the base `pretrained_busterNet.hd5` model. |
| `finetuned_model/` | Contains the deployed fine-tuned checkpoint (`phase5_final_seed42_finetuned_best.hd5`) and `model_metadata.json` detailing the run name, selected threshold, and test metrics. |
| `sidecar_server.py` | The API server script exposing `GET /health` and `POST /predict` endpoints. |
| `run_sidecar.py` | The entry point script that starts the sidecar server on `127.0.0.1:7861`. |
| `requirements-legacy.txt` | Pinned legacy runtime packages strictly required for the official model. |

---

## Prerequisites & Setup

You must use a separate **Python 3.6.x 64-bit** environment for this directory.

### Step-by-Step Installation

1. **Install Python 3.6 x64** on your Windows machine.
2. **Create a dedicated virtual environment** inside this specific folder.
3. **Install the pinned requirements.**
4. **Run the sidecar** from within the legacy environment.

**Manual Setup Example:**

```powershell
cd C:\Users\raneem\DIFD-MLmodel\busternet_sidecar
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip setuptools wheel
pip install -r .\requirements-legacy.txt
python .\run_sidecar.py
```

**Automated Setup (Helper Script):**

If you already have a Python 3.6 executable available, you can quickly bootstrap the environment:

```powershell
.\bootstrap_legacy_env.ps1 -PythonExe C:\Path\To\Python36\python.exe
```

---

## API Reference

The sidecar runs locally on port `7861` and exposes the following endpoints:

### `GET /health`

Checks the health and readiness of the sidecar model.

### `POST /predict`

Processes an image for forgery detection.

- **Payload:** Multipart form field containing the `image`.
- **Headers:** Request must include the `X-BusterNet-Token` (unless token enforcement is disabled).
- **Output:** Returns masks that preserve the original image dimensions.

#### Class Output Decoding

The sidecar decodes the official 3-channel BusterNet softmax output as follows:

| Class | Interpretation |
| --- | --- |
| `0` | Target |
| `1` | Source |
| `2` | Background |

#### Threshold Configuration

By default, the deployed fine-tuned model uses the validation-selected forged-pixel threshold found in `model_metadata.json`. For testing purposes, you can override this via an environment variable:

```powershell
$env:BUSTERNET_FORGED_THRESHOLD = "0.7"
```

---

## Security & Authentication

To ensure secure local communication, the sidecar enforces token authentication by default (`DIFD_REQUIRE_SIDECAR_TOKEN=1`) and listens exclusively on `127.0.0.1`.

- **Default Behavior:** The launcher (`start_sidecar.ps1`) automatically creates or reads a shared host-local token from `..\security\sidecar_token` (if `BUSTERNET_TOKEN` is not already set). The Streamlit launchers use this exact same token file.

- **Manual Token Override:** You can specify your own token by setting the environment variable:

```powershell
$env:BUSTERNET_TOKEN = "replace-with-a-long-random-token"
```

- **Disable Auth (Debugging Only):** If token enforcement is enabled and no token is provided, the sidecar will reject `/predict` requests. For isolated local debugging only, you can disable token enforcement:

```powershell
$env:DIFD_REQUIRE_SIDECAR_TOKEN = "0"
```