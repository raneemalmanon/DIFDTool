import base64
import cgi
import hmac
import io
import json
import logging
import os
import socketserver
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict

import numpy as np
from PIL import Image


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("difd.busternet_sidecar")

ROOT_DIR = Path(__file__).resolve().parent
OFFICIAL_MODEL_DIR = ROOT_DIR / "official_model"
FINETUNED_MODEL_DIR = ROOT_DIR / "finetuned_model"
DEFAULT_WEIGHTS_PATH = FINETUNED_MODEL_DIR / "phase5_final_seed42_finetuned_best.hd5"
DEFAULT_METADATA_PATH = FINETUNED_MODEL_DIR / "model_metadata.json"
WEIGHTS_PATH = Path(os.getenv("BUSTERNET_WEIGHTS_PATH", str(DEFAULT_WEIGHTS_PATH)))
METADATA_PATH = Path(os.getenv("BUSTERNET_MODEL_METADATA_PATH", str(DEFAULT_METADATA_PATH)))
HOST = os.getenv("BUSTERNET_HOST", "127.0.0.1")
PORT = int(os.getenv("BUSTERNET_PORT", "7861"))
SIDECAR_TOKEN = os.getenv("BUSTERNET_TOKEN", "")
REQUIRE_SIDECAR_TOKEN = os.getenv("DIFD_REQUIRE_SIDECAR_TOKEN", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
MAX_IMAGE_PIXELS = int(os.getenv("BUSTERNET_MAX_IMAGE_PIXELS", "50000000"))


def _resolve_project_path(path_value: str, *, label: str) -> Path:
    """Resolve and validate a configured path under the sidecar root."""
    resolved_root = ROOT_DIR.resolve()
    resolved_path = Path(path_value).expanduser().resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError:
        raise ValueError(f"{label} must be inside the sidecar project directory.")
    return resolved_path


WEIGHTS_PATH = _resolve_project_path(str(WEIGHTS_PATH), label="BusterNet weights path")
METADATA_PATH = _resolve_project_path(str(METADATA_PATH), label="BusterNet metadata path")


def _load_model_metadata() -> Dict[str, Any]:
    """Load local fine-tuned model metadata from JSON."""
    if not METADATA_PATH.exists():
        return {
            "model_name": "Fine-tuned BusterNet",
            "model_stage": "finetuned",
            "run_name": "",
            "validation_selected_threshold": 0.7,
        }
    with METADATA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


MODEL_METADATA = _load_model_metadata()
MODEL_NAME = str(MODEL_METADATA.get("model_name", "Fine-tuned BusterNet"))
MODEL_STAGE = str(MODEL_METADATA.get("model_stage", "finetuned"))
MODEL_RUN_NAME = str(MODEL_METADATA.get("run_name", ""))
FORGED_THRESHOLD = float(os.getenv(
    "BUSTERNET_FORGED_THRESHOLD",
    str(MODEL_METADATA.get("validation_selected_threshold", 0.7)),
))

_MODEL_LOCK = threading.Lock()
_MODEL = None
_GRAPH = None
_MODEL_ERROR = None
_KERAS_VERSION = ""
_TENSORFLOW_VERSION = ""


def _ensure_model_loaded() -> None:
    global _MODEL
    global _GRAPH
    global _MODEL_ERROR
    global _KERAS_VERSION
    global _TENSORFLOW_VERSION

    if _MODEL is not None or _MODEL_ERROR is not None:
        return

    with _MODEL_LOCK:
        if _MODEL is not None or _MODEL_ERROR is not None:
            return

        try:
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
            official_dir = str(OFFICIAL_MODEL_DIR)
            if official_dir not in sys.path:
                sys.path.insert(0, official_dir)

            import keras  # type: ignore
            import tensorflow as tf  # type: ignore
            from BusterNetCore import create_BusterNet_testing_model  # type: ignore

            _KERAS_VERSION = str(getattr(keras, "__version__", "unknown"))
            _TENSORFLOW_VERSION = str(getattr(tf, "__version__", "unknown"))
            _MODEL = create_BusterNet_testing_model(str(WEIGHTS_PATH))
            _GRAPH = tf.get_default_graph()
        except Exception as exc:
            _MODEL_ERROR = f"{type(exc).__name__}: {exc}"
            LOGGER.exception("Failed to load BusterNet model.")


def _health_payload() -> Dict[str, Any]:
    """Build the local sidecar health response."""
    _ensure_model_loaded()
    return {
        "available": True,
        "loaded": _MODEL is not None,
        "algorithm": "BusterNet",
        "model_name": MODEL_NAME,
        "model_stage": MODEL_STAGE,
        "model_run_name": MODEL_RUN_NAME,
        "forged_threshold": FORGED_THRESHOLD,
        "weights_path": str(WEIGHTS_PATH),
        "model_metadata_path": str(METADATA_PATH),
        "official_model_dir": str(OFFICIAL_MODEL_DIR),
        "python_version": sys.version.split()[0],
        "keras_version": _KERAS_VERSION,
        "tensorflow_version": _TENSORFLOW_VERSION,
        "token_required": REQUIRE_SIDECAR_TOKEN,
        "token_configured": bool(SIDECAR_TOKEN),
        "error": _MODEL_ERROR,
    }


def _mask_to_png_b64(mask: np.ndarray) -> str:
    image = Image.fromarray(np.asarray(mask, dtype=np.uint8), mode="L")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def _count_regions(mask: np.ndarray) -> int:
    binary = np.asarray(mask, dtype=np.uint8) > 0
    if not np.any(binary):
        return 0

    height, width = binary.shape
    visited = np.zeros((height, width), dtype=np.uint8)
    region_count = 0
    neighbors = (
        (-1, -1), (0, -1), (1, -1),
        (-1, 0),           (1, 0),
        (-1, 1),  (0, 1),  (1, 1),
    )

    for start_y in range(height):
        for start_x in range(width):
            if not binary[start_y, start_x] or visited[start_y, start_x]:
                continue

            region_count += 1
            queue = deque([(start_x, start_y)])
            visited[start_y, start_x] = 1

            while queue:
                x, y = queue.popleft()
                for dx, dy in neighbors:
                    nx = x + dx
                    ny = y + dy
                    if nx < 0 or ny < 0 or nx >= width or ny >= height:
                        continue
                    if visited[ny, nx] or not binary[ny, nx]:
                        continue
                    visited[ny, nx] = 1
                    queue.append((nx, ny))

    return region_count


def _compute_probability_confidence(probability: np.ndarray, mask: np.ndarray) -> float:
    selected = mask > 0
    if not np.any(selected):
        return 0.0
    return round(float(np.mean(probability[selected]) * 100.0), 2)


def _predict(image_bytes: bytes) -> Dict[str, Any]:
    """Run BusterNet prediction on one uploaded image."""
    _ensure_model_loaded()
    if _MODEL is None:
        raise RuntimeError(_MODEL_ERROR or "The BusterNet model could not be loaded.")

    import tensorflow as tf
    official_dir = str(OFFICIAL_MODEL_DIR)
    if official_dir not in sys.path:
        sys.path.insert(0, official_dir)

    from BusterNetUtils import simple_cmfd_decoder # type: ignore

    with Image.open(io.BytesIO(image_bytes)) as image:
        image.load()
        pixel_count = int(image.width) * int(image.height)
        if pixel_count <= 0 or pixel_count > MAX_IMAGE_PIXELS:
            raise ValueError("Image dimensions exceed the sidecar safety limit.")
        rgb = np.asarray(image.convert("RGB"), dtype=np.uint8)

    start_time = time.perf_counter()
    with _GRAPH.as_default():
        prediction = np.asarray(simple_cmfd_decoder(_MODEL, rgb), dtype=np.float32)
    runtime_seconds = round(float(time.perf_counter() - start_time), 4)

    if prediction.ndim != 3 or prediction.shape[-1] < 3:
        raise RuntimeError(f"Unexpected BusterNet prediction shape: {prediction.shape}")

    target_probability = prediction[..., 0]
    source_probability = prediction[..., 1]
    forged_probability = np.clip(target_probability + source_probability, 0.0, 1.0)
    combined_binary = forged_probability >= FORGED_THRESHOLD
    source_binary = combined_binary & (source_probability >= target_probability)
    target_binary = combined_binary & (target_probability > source_probability)

    source_mask = np.where(source_binary, 255, 0).astype(np.uint8)
    target_mask = np.where(target_binary, 255, 0).astype(np.uint8)
    combined_mask = np.where(combined_binary, 255, 0).astype(np.uint8)

    total_pixels = int(combined_binary.size)
    source_pixels = int(np.count_nonzero(source_mask))
    target_pixels = int(np.count_nonzero(target_mask))
    tampered_pixels = int(np.count_nonzero(combined_mask))

    return {
        "available": True,
        "loaded": True,
        "algorithm": "BusterNet",
        "model_name": MODEL_NAME,
        "model_stage": MODEL_STAGE,
        "model_run_name": MODEL_RUN_NAME,
        "forged_threshold": FORGED_THRESHOLD,
        "class_order": "0=target, 1=source, 2=background",
        "weights_path": str(WEIGHTS_PATH),
        "model_metadata_path": str(METADATA_PATH),
        "python_version": sys.version.split()[0],
        "keras_version": _KERAS_VERSION,
        "tensorflow_version": _TENSORFLOW_VERSION,
        "input_width": int(rgb.shape[1]),
        "input_height": int(rgb.shape[0]),
        "source_mask_png_b64": _mask_to_png_b64(source_mask),
        "target_mask_png_b64": _mask_to_png_b64(target_mask),
        "combined_mask_png_b64": _mask_to_png_b64(combined_mask),
        "source_pixels": source_pixels,
        "target_pixels": target_pixels,
        "tampered_pixels": tampered_pixels,
        "tampered_ratio": round(float(tampered_pixels / max(total_pixels, 1)), 6),
        "source_regions": _count_regions(source_mask),
        "target_regions": _count_regions(target_mask),
        "combined_regions": _count_regions(combined_mask),
        "source_confidence": _compute_probability_confidence(source_probability, source_mask),
        "target_confidence": _compute_probability_confidence(target_probability, target_mask),
        "combined_confidence": _compute_probability_confidence(forged_probability, combined_mask),
        "runtime_seconds": runtime_seconds,
    }


class BusterNetRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler exposing localhost-only BusterNet inference endpoints."""

    server_version = "BusterNetSidecar/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        """Route HTTP server messages through standard logging."""
        LOGGER.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        """Send a JSON response with explicit status and length headers."""
        encoded = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Swallow errors caused by client timeouts
            LOGGER.debug("Failed to send JSON response: connection closed by client.")

    def _is_authorized(self) -> bool:
        """Check the shared local token before prediction requests."""
        if REQUIRE_SIDECAR_TOKEN and not SIDECAR_TOKEN:
            LOGGER.warning("Prediction refused because BUSTERNET_TOKEN is not configured.")
            return False
        if not REQUIRE_SIDECAR_TOKEN and not SIDECAR_TOKEN:
            return True
        supplied_token = self.headers.get("X-BusterNet-Token", "")
        return hmac.compare_digest(supplied_token, SIDECAR_TOKEN)

    def do_GET(self) -> None:  # noqa: N802
        # Strict Host header validation (NIST SC-7 alignment)
        host_header = self.headers.get("Host", "")
        if not any(h in host_header for h in ["127.0.0.1", "localhost"]):
             self._send_json(400, {"error": "Invalid Host header."})
             return
             
        if self.path.rstrip("/") != "/health":
            self._send_json(404, {"error": "Unknown endpoint."})
            return

        self._send_json(200, _health_payload())

    def do_POST(self) -> None:  # noqa: N802
        # Strict Host header validation (NIST SC-7 alignment)
        host_header = self.headers.get("Host", "")
        if not any(h in host_header for h in ["127.0.0.1", "localhost"]):
             self._send_json(400, {"error": "Invalid Host header."})
             return

        if self.path.rstrip("/") != "/predict":
            self._send_json(404, {"error": "Unknown endpoint."})
            return

        if not self._is_authorized():
            self._send_json(401, {"error": "Unauthorized."})
            return

        try:
            content_type = self.headers.get("Content-Type", "")
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                },
            )
            if "image" not in form:
                raise ValueError("The request must include an 'image' file field.")

            image_field = form["image"]
            image_bytes = image_field.file.read() if getattr(image_field, "file", None) else b""
            if not image_bytes:
                raise ValueError("The uploaded image file is empty.")

            self._send_json(200, _predict(image_bytes))
        except Exception as exc:
            status_code = 400 if isinstance(exc, ValueError) else 503
            LOGGER.exception("Sidecar request failed with status %s", status_code)
            self._send_json(status_code, {"error": f"BusterNet prediction request failed: {exc}"})


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for better responsiveness during model load."""
    daemon_threads = True


def run(*, host: str = HOST, port: int = PORT) -> None:
    """Start the local BusterNet HTTP sidecar."""
    httpd = ThreadedHTTPServer((host, port), BusterNetRequestHandler)
    LOGGER.info("BusterNet sidecar listening on http://%s:%s", host, port)
    httpd.serve_forever()


if __name__ == "__main__":
    run()
