"""Client utilities for the local fine-tuned BusterNet sidecar."""

from __future__ import annotations

import base64
import http.client
import io
import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

import numpy as np
from PIL import Image


LOGGER = logging.getLogger("difd.cmfd_pipeline")
DEFAULT_SIDECAR_URL = os.getenv("BUSTERNET_SIDECAR_URL", "http://127.0.0.1:7861").rstrip("/")
SIDECAR_TOKEN = os.getenv("BUSTERNET_TOKEN", "")
REQUIRE_SIDECAR_TOKEN = os.getenv("DIFD_REQUIRE_SIDECAR_TOKEN", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
SIDECAR_HEALTH_TIMEOUT_SECONDS: float = 20.0
SIDECAR_STARTUP_MAX_RETRIES: int = 3
SIDECAR_STARTUP_BACKOFF_SECONDS: float = 0.25
SIDECAR_BACKOFF_MULTIPLIER: float = 2.0

__all__ = [
    "BusterNetClientError",
    "detect_copy_move",
    "get_sidecar_health",
    "get_sidecar_url",
    "is_sidecar_token_configured",
    "is_sidecar_token_required",
    "wait_for_sidecar",
]


class BusterNetClientError(RuntimeError):
    """Raised when the local BusterNet sidecar cannot be reached or returns invalid data."""


def get_sidecar_url() -> str:
    return DEFAULT_SIDECAR_URL


def is_sidecar_token_required() -> bool:
    """Return whether prediction requests require a shared local token."""

    return REQUIRE_SIDECAR_TOKEN


def is_sidecar_token_configured() -> bool:
    """Return whether the app process has a configured sidecar token."""

    return bool(SIDECAR_TOKEN)


def _sidecar_auth_headers() -> dict[str, str]:
    if not SIDECAR_TOKEN:
        return {}
    return {"X-BusterNet-Token": SIDECAR_TOKEN}


def _extract_error_message(raw_body: str, default: str) -> str:
    body = str(raw_body or "").strip()
    if not body:
        return default

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body or default

    if isinstance(payload, dict):
        detail = payload.get("error") or payload.get("message")
        if detail:
            return str(detail)

    return default


def _json_request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    request = urllib.request.Request(url, data=data, method=method.upper())
    for key, value in (headers or {}).items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        detail = _extract_error_message(body, f"BusterNet sidecar returned HTTP {exc.code}.")
        LOGGER.warning("BusterNet sidecar HTTP error from %s: %s", url, detail)
        raise BusterNetClientError(detail) from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        LOGGER.warning("Unable to reach BusterNet sidecar at %s: %s", url, reason)
        raise BusterNetClientError(f"Unable to reach the BusterNet sidecar at {url}: {reason}") from exc
    except (TimeoutError, socket.timeout, http.client.RemoteDisconnected, OSError) as exc:
        LOGGER.warning("BusterNet sidecar request failed at %s: %s", url, exc)
        raise BusterNetClientError(f"BusterNet sidecar request failed at {url}: {exc}") from exc

    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        LOGGER.warning("BusterNet sidecar returned invalid JSON from %s.", url)
        raise BusterNetClientError(f"BusterNet sidecar returned invalid JSON from {url}.") from exc

    if not isinstance(decoded, dict):
        raise BusterNetClientError(f"BusterNet sidecar returned an unexpected payload from {url}.")

    return decoded


def _encode_multipart_image(
    *,
    field_name: str,
    filename: str,
    content_type: str,
    data: bytes,
) -> tuple[bytes, str]:
    boundary = f"----BusterNetBoundary{uuid.uuid4().hex}"
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode("utf-8"))
    body.write(
        (
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
    )
    body.write(data)
    body.write(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return body.getvalue(), boundary


def _decode_mask(mask_b64: str, *, label: str) -> np.ndarray:
    try:
        raw_bytes = base64.b64decode(mask_b64)
    except Exception as exc:
        LOGGER.warning("Invalid base64 mask payload for %s.", label)
        raise BusterNetClientError(f"Invalid base64 mask payload for {label}.") from exc

    try:
        image = Image.open(io.BytesIO(raw_bytes))
        image.load()
    except Exception as exc:
        LOGGER.warning("Unable to decode PNG mask for %s.", label)
        raise BusterNetClientError(f"Unable to decode PNG mask for {label}.") from exc

    mask = np.asarray(image.convert("L"), dtype=np.uint8)
    return np.where(mask > 0, 255, 0).astype(np.uint8)


def _require_keys(payload: dict[str, Any], required_keys: list[str]) -> None:
    missing = [key for key in required_keys if key not in payload]
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise BusterNetClientError(f"BusterNet sidecar response is missing required fields: {missing_text}")


def get_sidecar_health(
    *,
    base_url: str | None = None,
    retries: int = 0,
    backoff: float = 0.0,
    timeout: float = SIDECAR_HEALTH_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Query the sidecar health endpoint and return None when it is unreachable."""

    resolved_url = (base_url or DEFAULT_SIDECAR_URL).rstrip("/")
    health_url = f"{resolved_url}/health"
    attempts = max(int(retries) + 1, 1)

    for attempt in range(attempts):
        try:
            payload = _json_request(
                health_url,
                headers=_sidecar_auth_headers(),
                timeout=timeout,
            )
        except BusterNetClientError as exc:
            if attempt < attempts - 1:
                wait_seconds = backoff * (SIDECAR_BACKOFF_MULTIPLIER**attempt)
                LOGGER.warning(
                    "BusterNet health check failed; retrying in %.2fs: %s",
                    wait_seconds,
                    exc,
                )
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
                continue
            LOGGER.warning("BusterNet health check failed after %d attempt(s): %s", attempts, exc)
            return None

        payload["available"] = bool(payload.get("available", True))
        payload["loaded"] = bool(payload.get("loaded", False))
        payload["sidecar_url"] = resolved_url
        return payload

    return None


def wait_for_sidecar(
    *,
    retries: int = SIDECAR_STARTUP_MAX_RETRIES,
    backoff: float = SIDECAR_STARTUP_BACKOFF_SECONDS,
    timeout: float = SIDECAR_HEALTH_TIMEOUT_SECONDS,
) -> bool:
    """Poll the local sidecar briefly without crashing if the service is absent."""

    attempts = max(int(retries) + 1, 1)
    for attempt in range(attempts):
        if get_sidecar_health(retries=0, timeout=timeout) is not None:
            LOGGER.info("BusterNet sidecar responded after %d attempt(s).", attempt + 1)
            return True

        if attempt < attempts - 1:
            wait_seconds = backoff * (SIDECAR_BACKOFF_MULTIPLIER**attempt)
            LOGGER.warning(
                "BusterNet sidecar is not ready (attempt %d/%d); retrying in %.2fs.",
                attempt + 1,
                attempts,
                wait_seconds,
            )
            if wait_seconds > 0:
                time.sleep(wait_seconds)

    LOGGER.warning("BusterNet sidecar is unavailable after %d attempt(s).", attempts)
    return False


def detect_copy_move(
    image_bytes: bytes,
    *,
    filename: str = "uploaded-image.png",
    content_type: str = "image/png",
    base_url: str | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    if not image_bytes:
        raise BusterNetClientError("No image data was provided to the BusterNet client.")
    if REQUIRE_SIDECAR_TOKEN and not SIDECAR_TOKEN:
        raise BusterNetClientError(
            "BusterNet prediction requires BUSTERNET_TOKEN. Set the same token in the app and sidecar terminals."
        )

    resolved_url = (base_url or DEFAULT_SIDECAR_URL).rstrip("/")
    body, boundary = _encode_multipart_image(
        field_name="image",
        filename=filename,
        content_type=content_type,
        data=image_bytes,
    )
    payload = _json_request(
        f"{resolved_url}/predict",
        method="POST",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            **_sidecar_auth_headers(),
        },
        timeout=timeout,
    )

    _require_keys(
        payload,
        [
            "algorithm",
            "model_name",
            "input_width",
            "input_height",
            "source_mask_png_b64",
            "target_mask_png_b64",
            "combined_mask_png_b64",
            "source_pixels",
            "target_pixels",
            "tampered_pixels",
            "tampered_ratio",
            "source_regions",
            "target_regions",
            "combined_regions",
            "source_confidence",
            "target_confidence",
            "combined_confidence",
            "runtime_seconds",
        ],
    )

    source_mask = _decode_mask(str(payload["source_mask_png_b64"]), label="source")
    target_mask = _decode_mask(str(payload["target_mask_png_b64"]), label="target")
    combined_mask = _decode_mask(str(payload["combined_mask_png_b64"]), label="combined")

    expected_shape = (int(payload["input_height"]), int(payload["input_width"]))
    for label, mask in (
        ("source", source_mask),
        ("target", target_mask),
        ("combined", combined_mask),
    ):
        if mask.shape != expected_shape:
            raise BusterNetClientError(
                f"BusterNet {label} mask shape {mask.shape} does not match the expected shape {expected_shape}."
            )

    return {
        "algorithm": str(payload["algorithm"]),
        "model_name": str(payload["model_name"]),
        "input_width": int(payload["input_width"]),
        "input_height": int(payload["input_height"]),
        "source_mask": source_mask,
        "target_mask": target_mask,
        "combined_mask": combined_mask,
        "source_pixels": int(payload["source_pixels"]),
        "target_pixels": int(payload["target_pixels"]),
        "tampered_pixels": int(payload["tampered_pixels"]),
        "tampered_ratio": float(payload["tampered_ratio"]),
        "source_regions": int(payload["source_regions"]),
        "target_regions": int(payload["target_regions"]),
        "combined_regions": int(payload["combined_regions"]),
        "source_confidence": float(payload["source_confidence"]),
        "target_confidence": float(payload["target_confidence"]),
        "combined_confidence": float(payload["combined_confidence"]),
        "runtime_seconds": float(payload["runtime_seconds"]),
        "model_runtime": {
            "sidecar_url": resolved_url,
            "weights_path": str(payload.get("weights_path", "")),
            "model_stage": str(payload.get("model_stage", "")),
            "model_run_name": str(payload.get("model_run_name", "")),
            "model_metadata_path": str(payload.get("model_metadata_path", "")),
            "forged_threshold": float(payload.get("forged_threshold", 0.0)),
            "class_order": str(payload.get("class_order", "")),
            "python_version": str(payload.get("python_version", "")),
            "keras_version": str(payload.get("keras_version", "")),
            "tensorflow_version": str(payload.get("tensorflow_version", "")),
            "loaded": bool(payload.get("loaded", True)),
        },
    }
