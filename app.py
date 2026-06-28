from __future__ import annotations

import io
import json
import logging
import os
import secrets
import tempfile
import time
import warnings
from datetime import datetime, timezone
from html import escape
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np
import streamlit as st
import streamlit.components.v1 as components
from PIL import ExifTags, Image

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("difd.app")

from cmfd_pipeline import (
    BusterNetClientError,
    SIDECAR_HEALTH_TIMEOUT_SECONDS,
    SIDECAR_STARTUP_BACKOFF_SECONDS,
    SIDECAR_STARTUP_MAX_RETRIES,
    detect_copy_move,
    get_sidecar_health,
    get_sidecar_url,
    is_sidecar_token_configured,
    is_sidecar_token_required,
    wait_for_sidecar,
)
from security_auth import (
    AUTH_DB_PATH,
    AUTH_BACKUP_DIR,
    INSTALL_STATE_PATH,
    LOCKOUT_THRESHOLD,
    MIN_PASSWORD_LENGTH,
    SECURITY_EVENTS_PATH,
    SESSION_TIMEOUT_SECONDS,
    AuthError,
    authenticate_user,
    create_browser_session,
    create_user,
    get_auth_store_status,
    init_db,
    latest_auth_db_backup,
    list_users,
    log_event,
    log_security_event,
    recent_audit_events,
    recent_security_events,
    refresh_browser_session,
    restore_browser_session,
    revoke_browser_session,
    seal_installation,
    set_user_active,
    update_password,
)

try:
    from fpdf import FPDF
except Exception as exc:
    LOGGER.warning("PDF support is unavailable: %s", exc)
    FPDF = None


ROOT_DIR = Path(__file__).resolve().parent
SIDECAR_DIR = ROOT_DIR / "busternet_sidecar"
AUTH_COOKIE_NAME = "difd_auth_token"
MAX_UPLOAD_BYTES = int(os.getenv("DIFD_MAX_UPLOAD_MB", "15")) * 1024 * 1024
MAX_IMAGE_PIXELS = int(os.getenv("DIFD_MAX_IMAGE_PIXELS", "50000000"))
SIDECAR_HEALTH_CACHE_SECONDS = 5.0
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "BMP", "TIFF"}
TYPE = {
    "heading": {
        "family": "'Barlow Condensed', sans-serif",
        "size_px": 20,
        "weight": 600,
        "letter_spacing_em": 0.08,
        "color": "#f4f7fb",
    },
    "label": {
        "family": "'IBM Plex Sans', sans-serif",
        "size_px": 12,
        "weight": 700,
        "letter_spacing_em": 0.10,
        "color": "#8aa3be",
    },
    "value": {
        "family": "'IBM Plex Sans', sans-serif",
        "size_px": 15,
        "weight": 400,
        "letter_spacing_em": 0.01,
        "color": "#d4e1ee",
    },
}
SP = {"xs": 8, "sm": 16, "md": 24, "lg": 32, "xl": 48}
THEME_CHOICES = ("Auto", "Dark", "Light")

DARK_THEME_TOKENS = {
    "bg-0": "#05080d",
    "bg-1": "#09111c",
    "bg-2": "#101a28",
    "surface-1": "rgba(10, 18, 30, 0.94)",
    "surface-2": "rgba(14, 24, 38, 0.96)",
    "surface-raised": "rgba(18, 31, 48, 0.96)",
    "border-subtle": "rgba(76, 111, 151, 0.40)",
    "border-strong": "rgba(103, 140, 178, 0.78)",
    "text-primary": "#f4f7fb",
    "text-secondary": "#c4d2e2",
    "text-muted": "#9db0c4",
    "text-disabled": "#74859a",
    "accent": "#f7c948",
    "accent-strong": "#ff8b58",
    "accent-source": "#f7c948",
    "accent-target": "#ff5252",
    "success": "#29d398",
    "warning": "#ffd166",
    "danger": "#ff6b6b",
    "focus-ring": "#ffe08a",
    "focus-shadow": "0 0 0 3px rgba(255, 224, 138, 0.44)",
    "shadow-raised": "0 18px 44px rgba(4, 8, 14, 0.32)",
    "app-background": "radial-gradient(1000px 520px at 8% -10%, rgba(247, 201, 72, 0.16), transparent 60%), radial-gradient(900px 420px at 95% 5%, rgba(255, 107, 107, 0.13), transparent 55%), linear-gradient(180deg, #05080d 0%, #09111c 45%, #101a28 100%)",
    "sidebar-background": "linear-gradient(180deg, rgba(8, 13, 21, 0.98), rgba(10, 18, 29, 0.98))",
    "glass-background": "linear-gradient(180deg, rgba(10, 18, 30, 0.94), rgba(10, 18, 30, 0.98))",
    "policy-card-bg": "linear-gradient(180deg, rgba(8, 14, 24, 0.92), rgba(10, 18, 30, 0.94))",
    "policy-card-critical-bg": "linear-gradient(180deg, rgba(33, 13, 21, 0.92), rgba(16, 11, 16, 0.96))",
    "policy-card-critical-text": "#ffd8df",
    "policy-card-good-bg": "linear-gradient(180deg, rgba(10, 29, 24, 0.92), rgba(9, 17, 21, 0.96))",
    "policy-card-warn-bg": "linear-gradient(180deg, rgba(34, 24, 11, 0.92), rgba(17, 13, 9, 0.96))",
    "policy-card-warn-text": "#ffe8a8",
    "landing-panel-bg": "linear-gradient(180deg, rgba(10, 18, 30, 0.94), rgba(14, 24, 38, 0.96))",
    "landing-hero-bg": "radial-gradient(520px 220px at 4% 0%, rgba(247, 201, 72, 0.12), transparent 58%), linear-gradient(180deg, rgba(9, 15, 24, 0.9), rgba(10, 18, 30, 0.96))",
    "landing-badge-bg": "rgba(247, 201, 72, 0.08)",
    "landing-badge-border": "rgba(247, 201, 72, 0.34)",
    "landing-badge-text": "#f6d779",
    "landing-card-bg": "linear-gradient(180deg, rgba(10, 17, 29, 0.92), rgba(8, 14, 24, 0.98))",
    "landing-card-border": "rgba(58, 89, 125, 0.68)",
    "landing-step-bg": "rgba(9, 16, 28, 0.92)",
    "framework-note-bg": "radial-gradient(420px 160px at 0% 0%, rgba(247, 201, 72, 0.08), transparent 58%), linear-gradient(180deg, rgba(14, 18, 27, 0.94), rgba(10, 16, 25, 0.98))",
    "framework-note-strong": "#f6d779",
    "metric-bg": "linear-gradient(180deg, rgba(17, 29, 43, 0.96), rgba(11, 18, 27, 0.96))",
    "metric-border": "rgba(58, 89, 125, 0.48)",
    "input-bg": "rgba(10, 18, 31, 0.9)",
    "input-hover-bg": "rgba(13, 24, 41, 0.96)",
    "input-button-bg": "rgba(255, 255, 255, 0.06)",
    "input-button-hover-bg": "rgba(255, 255, 255, 0.10)",
    "input-icon": "#f4f7fb",
    "input-focus-shadow": "0 0 0 1px rgba(247, 201, 72, 0.22), 0 0 0 8px rgba(247, 201, 72, 0.08)",
    "placeholder-text": "rgba(210, 222, 236, 0.86)",
    "button-text": "#07101e",
    "button-shadow": "0 14px 30px rgba(247, 201, 72, 0.18)",
    "button-shadow-hover": "0 18px 36px rgba(247, 201, 72, 0.22)",
    "download-bg": "linear-gradient(180deg, rgba(18, 31, 48, 0.96), rgba(8, 14, 24, 0.98))",
    "download-text": "#f4f7fb",
    "tab-bg": "rgba(10, 18, 30, 0.9)",
    "tab-active-text": "#07101e",
    "expander-bg": "linear-gradient(180deg, rgba(11, 18, 29, 0.88), rgba(9, 15, 24, 0.94))",
    "uploader-bg": "linear-gradient(180deg, rgba(9, 16, 28, 0.9), rgba(10, 18, 31, 0.96))",
    "uploader-border": "rgba(58, 89, 125, 0.92)",
    "alert-bg": "linear-gradient(180deg, rgba(18, 31, 48, 0.96), rgba(8, 14, 24, 0.98))",
    "empty-bg": "radial-gradient(420px 180px at 8% 0%, rgba(247, 201, 72, 0.08), transparent 62%), rgba(8, 14, 24, 0.78)",
    "code-bg": "rgba(8, 14, 24, 0.92)",
    "dataframe-border": "rgba(58, 89, 125, 0.34)",
    "table-bg": "rgba(7, 15, 27, 0.96)",
    "table-header-bg": "rgba(18, 31, 48, 0.98)",
    "table-row-bg": "rgba(9, 16, 28, 0.96)",
    "table-row-alt-bg": "rgba(11, 20, 34, 0.96)",
    "table-hover-bg": "rgba(24, 40, 58, 0.98)",
    "table-text": "#d4e1ee",
    "json-bg": "rgba(8, 14, 24, 0.92)",
    "form-bg": "linear-gradient(180deg, rgba(10, 18, 30, 0.92), rgba(8, 14, 24, 0.96))",
    "secondary-button-bg": "linear-gradient(180deg, rgba(18, 31, 48, 0.96), rgba(8, 14, 24, 0.98))",
    "secondary-button-text": "#f4f7fb",
    "danger-button-bg": "linear-gradient(90deg, #ff6b6b 0%, #d83c3c 100%)",
    "disabled-bg": "rgba(116, 133, 154, 0.18)",
    "scrollbar-thumb": "rgba(103, 140, 178, 0.48)",
    "scrollbar-track": "rgba(8, 14, 24, 0.72)",
    "login-card-bg": "linear-gradient(180deg, rgba(11, 20, 35, 0.98), rgba(7, 13, 22, 0.98))",
    "login-note-bg": "linear-gradient(180deg, rgba(9, 17, 29, 0.94), rgba(6, 12, 21, 0.94))",
    "login-meta-bg": "rgba(7, 15, 27, 0.94)",
    "login-critical-bg": "linear-gradient(180deg, rgba(36, 13, 22, 0.92), rgba(18, 11, 16, 0.96))",
    "login-critical-text": "#ffd8df",
    "login-track-bg": "rgba(7, 16, 30, 0.92)",
    "login-track-border": "rgba(26, 58, 90, 0.88)",
    "login-processing-bg": "linear-gradient(90deg, rgba(247, 201, 72, 0.12), rgba(255, 139, 88, 0.12))",
    "inset-hairline": "inset 0 0 0 1px rgba(255, 255, 255, 0.02)",
}

LIGHT_THEME_TOKENS = {
    "bg-0": "#f6f0e5",
    "bg-1": "#eef4f6",
    "bg-2": "#dfe9ee",
    "surface-1": "rgba(255, 252, 245, 0.94)",
    "surface-2": "rgba(247, 250, 250, 0.96)",
    "surface-raised": "rgba(255, 255, 255, 0.96)",
    "border-subtle": "rgba(58, 88, 111, 0.24)",
    "border-strong": "rgba(53, 86, 112, 0.48)",
    "text-primary": "#10202e",
    "text-secondary": "#24394a",
    "text-muted": "#4f6a7e",
    "text-disabled": "#8aa0ae",
    "accent": "#c97a16",
    "accent-strong": "#e15d38",
    "accent-source": "#b97900",
    "accent-target": "#d83c3c",
    "success": "#0b7f5b",
    "warning": "#8a5a00",
    "danger": "#b4233b",
    "focus-ring": "#a95f00",
    "focus-shadow": "0 0 0 3px rgba(169, 95, 0, 0.28)",
    "shadow-raised": "0 18px 44px rgba(24, 46, 63, 0.14)",
    "app-background": "radial-gradient(1000px 520px at 8% -10%, rgba(201, 122, 22, 0.18), transparent 60%), radial-gradient(900px 420px at 95% 5%, rgba(216, 60, 60, 0.10), transparent 55%), linear-gradient(180deg, #f6f0e5 0%, #eef4f6 45%, #dfe9ee 100%)",
    "sidebar-background": "linear-gradient(180deg, rgba(250, 247, 240, 0.98), rgba(236, 244, 247, 0.98))",
    "glass-background": "linear-gradient(180deg, rgba(255, 252, 245, 0.94), rgba(247, 250, 250, 0.98))",
    "policy-card-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(247, 250, 250, 0.94))",
    "policy-card-critical-bg": "linear-gradient(180deg, rgba(255, 239, 242, 0.94), rgba(252, 246, 247, 0.98))",
    "policy-card-critical-text": "#7b1528",
    "policy-card-good-bg": "linear-gradient(180deg, rgba(230, 249, 241, 0.94), rgba(246, 252, 249, 0.98))",
    "policy-card-warn-bg": "linear-gradient(180deg, rgba(255, 244, 218, 0.94), rgba(255, 251, 242, 0.98))",
    "policy-card-warn-text": "#684300",
    "landing-panel-bg": "linear-gradient(180deg, rgba(255, 252, 245, 0.94), rgba(247, 250, 250, 0.96))",
    "landing-hero-bg": "radial-gradient(520px 220px at 4% 0%, rgba(201, 122, 22, 0.14), transparent 58%), linear-gradient(180deg, rgba(255, 252, 245, 0.92), rgba(247, 250, 250, 0.98))",
    "landing-badge-bg": "rgba(201, 122, 22, 0.10)",
    "landing-badge-border": "rgba(201, 122, 22, 0.34)",
    "landing-badge-text": "#7c4a09",
    "landing-card-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(247, 250, 250, 0.98))",
    "landing-card-border": "rgba(58, 88, 111, 0.34)",
    "landing-step-bg": "rgba(255, 255, 255, 0.88)",
    "framework-note-bg": "radial-gradient(420px 160px at 0% 0%, rgba(201, 122, 22, 0.10), transparent 58%), linear-gradient(180deg, rgba(255, 251, 242, 0.94), rgba(247, 250, 250, 0.98))",
    "framework-note-strong": "#8a4f00",
    "metric-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 248, 250, 0.96))",
    "metric-border": "rgba(58, 88, 111, 0.28)",
    "input-bg": "rgba(255, 255, 255, 0.94)",
    "input-hover-bg": "rgba(255, 252, 245, 0.98)",
    "input-button-bg": "rgba(16, 32, 46, 0.06)",
    "input-button-hover-bg": "rgba(16, 32, 46, 0.10)",
    "input-icon": "#10202e",
    "input-focus-shadow": "0 0 0 1px rgba(169, 95, 0, 0.22), 0 0 0 8px rgba(169, 95, 0, 0.10)",
    "placeholder-text": "rgba(51, 74, 94, 0.72)",
    "button-text": "#101314",
    "button-shadow": "0 14px 30px rgba(201, 122, 22, 0.18)",
    "button-shadow-hover": "0 18px 36px rgba(201, 122, 22, 0.24)",
    "download-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 248, 250, 0.98))",
    "download-text": "#10202e",
    "tab-bg": "rgba(255, 255, 255, 0.78)",
    "tab-active-text": "#101314",
    "expander-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(247, 250, 250, 0.94))",
    "uploader-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.90), rgba(247, 250, 250, 0.96))",
    "uploader-border": "rgba(58, 88, 111, 0.46)",
    "alert-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 248, 250, 0.98))",
    "empty-bg": "radial-gradient(420px 180px at 8% 0%, rgba(201, 122, 22, 0.10), transparent 62%), rgba(255, 255, 255, 0.78)",
    "code-bg": "rgba(16, 32, 46, 0.06)",
    "dataframe-border": "rgba(58, 88, 111, 0.26)",
    "table-bg": "rgba(255, 255, 255, 0.96)",
    "table-header-bg": "rgba(239, 246, 248, 0.98)",
    "table-row-bg": "rgba(255, 255, 255, 0.98)",
    "table-row-alt-bg": "rgba(248, 251, 252, 0.98)",
    "table-hover-bg": "rgba(255, 247, 232, 0.95)",
    "table-text": "#10202e",
    "json-bg": "rgba(255, 255, 255, 0.92)",
    "form-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.94), rgba(247, 250, 250, 0.98))",
    "secondary-button-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(238, 246, 248, 0.98))",
    "secondary-button-text": "#10202e",
    "danger-button-bg": "linear-gradient(90deg, #d83c3c 0%, #b4233b 100%)",
    "disabled-bg": "rgba(51, 74, 94, 0.08)",
    "scrollbar-thumb": "rgba(53, 86, 112, 0.38)",
    "scrollbar-track": "rgba(255, 255, 255, 0.62)",
    "login-card-bg": "linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(244, 248, 250, 0.98))",
    "login-note-bg": "linear-gradient(180deg, rgba(255, 252, 245, 0.94), rgba(247, 250, 250, 0.94))",
    "login-meta-bg": "rgba(255, 255, 255, 0.92)",
    "login-critical-bg": "linear-gradient(180deg, rgba(255, 239, 242, 0.92), rgba(252, 246, 247, 0.96))",
    "login-critical-text": "#7b1528",
    "login-track-bg": "rgba(16, 32, 46, 0.08)",
    "login-track-border": "rgba(58, 88, 111, 0.24)",
    "login-processing-bg": "linear-gradient(90deg, rgba(201, 122, 22, 0.12), rgba(225, 93, 56, 0.12))",
    "inset-hairline": "inset 0 0 0 1px rgba(16, 32, 46, 0.04)",
}

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


st.set_page_config(
    page_title="DIFD Fine-Tuned BusterNet Analysis",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _browser_session_id() -> str:
    if "browser_session_id" not in st.session_state:
        st.session_state.browser_session_id = secrets.token_urlsafe(18)
    return str(st.session_state.browser_session_id)


def _read_auth_cookie() -> str:
    try:
        cookies = getattr(st.context, "cookies", {})
        return str(cookies.get(AUTH_COOKIE_NAME, "") or "").strip()
    except Exception as exc:
        LOGGER.debug("Could not read auth cookie: %s", exc)
        return ""


def _auth_cookie_secure_suffix() -> str:
    try:
        url = str(getattr(st.context, "url", "") or "").lower()
        headers = getattr(st.context, "headers", {})
        forwarded_proto = str(headers.get("x-forwarded-proto", "") or "").lower()
    except Exception:
        url = ""
        forwarded_proto = ""
    if url.startswith("https://") or forwarded_proto == "https":
        return "; Secure"
    return ""


def _emit_cookie_script(*, token: str | None = None, clear: bool = False) -> None:
    cookie_name = json.dumps(AUTH_COOKIE_NAME)
    secure_suffix = _auth_cookie_secure_suffix()
    if clear:
        cookie_value = (
            f"{AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Strict{secure_suffix}"
        )
    else:
        cookie_value = (
            f"{AUTH_COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TIMEOUT_SECONDS}; "
            f"SameSite=Strict{secure_suffix}"
        )
    cookie_value_js = json.dumps(cookie_value)
    components.html(
        f"""
        <script>
        (function() {{
          const name = {cookie_name};
          const value = {cookie_value_js};
          try {{
            window.parent.document.cookie = value;
          }} catch (err) {{
            document.cookie = value;
          }}
        }})();
        </script>
        """,
        height=0,
    )


def _render_auth_cookie_effects() -> None:
    if st.session_state.pop("clear_auth_cookie", False):
        _emit_cookie_script(clear=True)
    token = st.session_state.pop("pending_auth_cookie", "")
    if token:
        _emit_cookie_script(token=str(token), clear=False)


def _clear_case_state() -> None:
    st.session_state.analysis = {}
    st.session_state.report_pdf_bytes = b""
    st.session_state.last_upload_hash = ""
    st.session_state.uploader_key = int(st.session_state.get("uploader_key", 0)) + 1


def _clear_authenticated_state() -> None:
    for key in (
        "auth_user",
        "analysis",
        "report_pdf_bytes",
        "uploader_key",
        "last_upload_hash",
        "last_sidecar_issue",
        "login_processing",
        "login_notice",
        "login_password",
        "login_clear_password",
        "show_login_screen",
        "runtime_health_cache",
        "pending_auth_cookie",
    ):
        if key in st.session_state:
            del st.session_state[key]


def _audit(event_type: str, *, success: bool = True, message: str = "") -> None:
    auth_user = st.session_state.get("auth_user") or {}
    username = auth_user.get("username")
    session_id = auth_user.get("session_id") or st.session_state.get("browser_session_id")
    log_event(event_type, username=username, success=success, session_id=session_id, message=message)


def _policy_card_markup(label: str, value: str, *, tone: str = "default", extra_class: str = "") -> str:
    tone_class = f" policy-card-{tone}" if tone != "default" else ""
    class_name = f"policy-card{tone_class}"
    if extra_class:
        class_name = f"{class_name} {extra_class}"
    return (
        f'<div class="{class_name}">'
        f'<div class="policy-label">{escape(label)}</div>'
        f'<div class="policy-value">{escape(value)}</div>'
        "</div>"
    )


def _render_empty_state(title: str, body: str) -> None:
    st.markdown(
        f"""
        <section class="empty-state" role="status" aria-live="polite">
            <h3 class="empty-state__title">{escape(title)}</h3>
            <p class="empty-state__body">{escape(body)}</p>
        </section>
        """,
        unsafe_allow_html=True,
    )


def _format_admin_table_value(value: Any, *, max_length: int = 120) -> str:
    """Format audit/admin values for readable, non-secret UI display."""

    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, default=str, sort_keys=True)
    else:
        rendered = str(value)
    rendered = " ".join(rendered.split())
    if len(rendered) > max_length:
        return f"{rendered[: max_length - 1]}..."
    return rendered


def _render_admin_table(
    title: str,
    rows: list[dict[str, Any]],
    columns: list[tuple[str, str]],
    *,
    empty_title: str,
    empty_body: str,
) -> None:
    """Render a theme-aware admin table without Streamlit's dark canvas grid."""

    st.markdown(f'<h3 class="section-title">{escape(title)}</h3>', unsafe_allow_html=True)
    if not rows:
        _render_empty_state(empty_title, empty_body)
        return

    header_markup = "".join(f"<th scope=\"col\">{escape(label)}</th>" for key, label in columns)
    body_rows: list[str] = []
    for row in rows:
        cells: list[str] = []
        for key, _label in columns:
            value = row.get(key)
            if key in {"success", "is_active"}:
                positive = bool(value)
                if key == "success":
                    badge_label = "Success" if positive else "Failed"
                else:
                    badge_label = "Active" if positive else "Disabled"
                badge_class = "admin-badge--success" if positive else "admin-badge--danger"
                cells.append(f'<td><span class="admin-badge {badge_class}">{escape(badge_label)}</span></td>')
            else:
                display_value = _format_admin_table_value(value)
                cells.append(f"<td title=\"{escape(display_value)}\">{escape(display_value)}</td>")
        body_rows.append(f"<tr>{''.join(cells)}</tr>")

    st.markdown(
        f"""
        <div class="admin-table-wrap" role="region" aria-label="{escape(title)}" tabindex="0">
            <table class="admin-table">
                <thead><tr>{header_markup}</tr></thead>
                <tbody>{''.join(body_rows)}</tbody>
            </table>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _offline_sidecar_health(message: str = "BusterNet sidecar is offline.") -> dict[str, Any]:
    """Build a sidecar health payload safe for UI rendering."""

    return {
        "available": False,
        "loaded": False,
        "sidecar_url": get_sidecar_url(),
        "token_required": is_sidecar_token_required(),
        "token_configured": is_sidecar_token_configured(),
        "error": message,
    }


def _runtime_health_snapshot() -> dict[str, Any]:
    """Return sidecar health or a degraded-mode payload without raising."""

    cached = st.session_state.get("runtime_health_cache")
    now = time.time()
    if isinstance(cached, dict):
        checked_at = float(cached.get("checked_at", 0.0) or 0.0)
        payload = cached.get("payload")
        if isinstance(payload, dict) and now - checked_at < SIDECAR_HEALTH_CACHE_SECONDS:
            return dict(payload)

    sidecar_ready = wait_for_sidecar(
        retries=SIDECAR_STARTUP_MAX_RETRIES,
        backoff=SIDECAR_STARTUP_BACKOFF_SECONDS,
        timeout=SIDECAR_HEALTH_TIMEOUT_SECONDS,
    )
    if not sidecar_ready:
        health_payload = _offline_sidecar_health()
        st.session_state.runtime_health_cache = {"checked_at": now, "payload": health_payload}
        return health_payload

    health = get_sidecar_health(timeout=SIDECAR_HEALTH_TIMEOUT_SECONDS)
    if health is None:
        health_payload = _offline_sidecar_health("BusterNet sidecar did not return a usable health response.")
        st.session_state.runtime_health_cache = {"checked_at": now, "payload": health_payload}
        return health_payload
    health["token_required"] = bool(health.get("token_required", is_sidecar_token_required()))
    health["token_configured"] = bool(health.get("token_configured", is_sidecar_token_configured()))
    st.session_state.runtime_health_cache = {"checked_at": now, "payload": health}
    return health


def _runtime_ready_for_prediction(runtime_health: dict[str, Any]) -> bool:
    """Return whether the sidecar can accept an authenticated prediction call."""

    if not runtime_health.get("loaded"):
        return False
    if runtime_health.get("token_required", is_sidecar_token_required()) and not runtime_health.get(
        "token_configured", is_sidecar_token_configured()
    ):
        return False
    return True


def _runtime_status_label(runtime_health: dict[str, Any]) -> tuple[str, str]:
    """Return visible runtime status text and tone for NIST-friendly UI status."""

    if _runtime_ready_for_prediction(runtime_health):
        return "Loaded and Protected", "good"
    if runtime_health.get("loaded"):
        return "Online, Token Missing", "critical"
    return "Offline", "critical"


def _plain_auth_admin_error(exc: Exception) -> str:
    message = str(exc)
    if "Argon2" in message or "argon2-cffi" in message:
        return "Password support is not available. Ask the project maintainer to check the app environment."
    return message


def _theme_mode() -> str:
    mode = str(st.session_state.get("difd_theme_mode", "Auto"))
    if mode not in THEME_CHOICES:
        mode = "Auto"
    st.session_state.difd_theme_mode = mode
    return mode


def _effective_theme() -> str:
    # Streamlit does not expose a stable runtime theme attribute here; Auto keeps the forensic dark default.
    return "light" if _theme_mode() == "Light" else "dark"


def _css_token_block(tokens: dict[str, str]) -> str:
    return "\n".join(f"            --{name}: {value};" for name, value in tokens.items())


def _sync_theme_selector(widget_key: str) -> None:
    selected = str(st.session_state.get(widget_key, "Auto"))
    if selected in THEME_CHOICES:
        st.session_state.difd_theme_mode = selected
        for suffix in ("login", "sidebar", "workspace"):
            st.session_state[f"difd_theme_mode_{suffix}"] = selected


def _render_theme_selector(*, key_suffix: str) -> None:
    mode = _theme_mode()
    widget_key = f"difd_theme_mode_{key_suffix}"
    widget_args: dict[str, Any] = {}
    if widget_key not in st.session_state:
        widget_args["index"] = THEME_CHOICES.index(mode)
    st.selectbox(
        "Theme",
        THEME_CHOICES,
        key=widget_key,
        on_change=_sync_theme_selector,
        args=(widget_key,),
        help="Auto uses the forensic dark theme unless a future Streamlit theme signal is available.",
        **widget_args,
    )


def _render_global_css() -> None:
    effective_theme = _effective_theme()
    theme_tokens = LIGHT_THEME_TOKENS if effective_theme == "light" else DARK_THEME_TOKENS
    css_tokens = _css_token_block(theme_tokens)
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Barlow+Condensed:wght@500;600;700&display=swap');

        :root {{
{css_tokens}
            --motion-fast: 160ms;
            --motion-medium: 260ms;
            --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
            --ease-in: cubic-bezier(0.7, 0, 0.84, 0);
            --text: var(--text-primary);
            --muted: var(--text-muted);
            --accent-good: var(--success);
            --type-heading-family: {TYPE["heading"]["family"]};
            --type-heading-size: {TYPE["heading"]["size_px"]}px;
            --type-heading-weight: {TYPE["heading"]["weight"]};
            --type-heading-track: {TYPE["heading"]["letter_spacing_em"]:.2f}em;
            --type-heading-color: var(--text-primary);
            --type-label-family: {TYPE["label"]["family"]};
            --type-label-size: {TYPE["label"]["size_px"]}px;
            --type-label-weight: {TYPE["label"]["weight"]};
            --type-label-track: {TYPE["label"]["letter_spacing_em"]:.2f}em;
            --type-label-color: var(--text-muted);
            --type-value-family: {TYPE["value"]["family"]};
            --type-value-size: {TYPE["value"]["size_px"]}px;
            --type-value-weight: {TYPE["value"]["weight"]};
            --type-value-track: {TYPE["value"]["letter_spacing_em"]:.2f}em;
            --type-value-color: var(--text-secondary);
            --sp-xs: {SP["xs"]}px;
            --sp-sm: {SP["sm"]}px;
            --sp-md: {SP["md"]}px;
            --sp-lg: {SP["lg"]}px;
            --sp-xl: {SP["xl"]}px;
            --input-border-default: var(--border-strong);
            --input-border-focus: var(--focus-ring);
            --input-border-critical: var(--danger);
            --panel-shadow: var(--shadow-raised);
        }}

        .stApp {{
            background: var(--app-background);
            color: var(--text-primary);
            font-family: 'IBM Plex Sans', sans-serif;
        }}

        .stApp * {{
            box-sizing: border-box;
        }}

        [data-testid="stDecoration"],
        [data-testid="stStatusWidget"],
        .stAppDeployButton,
        #MainMenu, 
        footer {{
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
            min-height: 0 !important;
        }}

        header[data-testid="stHeader"] {{
            display: block !important;
            visibility: visible !important;
            height: 3rem !important;
            min-height: 3rem !important;
            background: transparent !important;
            pointer-events: none;
            z-index: 999990 !important;
        }}

        header[data-testid="stHeader"] [data-testid="stToolbar"] {{
            display: flex !important;
            visibility: visible !important;
            height: 3rem !important;
            min-height: 3rem !important;
            background: transparent !important;
            pointer-events: none !important;
        }}

        header[data-testid="stHeader"] [data-testid="stToolbar"] > div:not([data-testid="collapsedControl"]) {{
            display: none !important;
            visibility: hidden !important;
        }}

        header[data-testid="stHeader"] button,
        [data-testid="collapsedControl"],
        [data-testid="collapsedControl"] button {{
            pointer-events: auto !important;
            visibility: visible !important;
            opacity: 1 !important;
        }}

        [data-testid="collapsedControl"] {{
            display: flex !important;
            position: fixed !important;
            top: 0.75rem !important;
            left: 0.75rem !important;
            z-index: 999999 !important;
        }}

        [data-testid="collapsedControl"] button {{
            min-width: 2.5rem !important;
            min-height: 2.5rem !important;
            border: 1px solid var(--border-strong) !important;
            border-radius: 999px !important;
            background: var(--surface-raised) !important;
            color: var(--text-primary) !important;
            box-shadow: var(--shadow-raised) !important;
        }}

        .main .block-container {{
            padding-top: var(--sp-lg);
            padding-bottom: var(--sp-xl);
            gap: var(--sp-md);
        }}

        [data-testid="stSidebar"] {{
            background: var(--sidebar-background);
            border-right: 1.5px solid var(--border-subtle);
        }}

        [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{
            gap: var(--sp-md);
        }}

        h1, h2, h3, .section-title {{
            font-family: var(--type-heading-family);
            letter-spacing: var(--type-heading-track);
            text-transform: uppercase;
            color: var(--type-heading-color);
            line-height: 1.08;
        }}

        .app-title,
        .landing-title,
        .login-title,
        .section-title,
        .landing-card-value,
        .landing-step-title {{
            margin-top: 0;
        }}

        .app-shell {{
            max-width: 1080px;
            margin: 0 auto var(--sp-lg) auto;
        }}

        .app-kicker,
        .section-eyebrow,
        .policy-label {{
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            font-weight: var(--type-label-weight);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
        }}

        .app-kicker,
        .section-eyebrow {{
            margin-bottom: var(--sp-xs);
        }}

        .app-title {{
            font-family: var(--type-heading-family);
            font-size: clamp(28px, 3.3vw, 44px);
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--type-heading-color);
            margin-bottom: var(--sp-sm);
        }}

        .app-subtitle,
        .section-copy,
        .subtle-note,
        .policy-value {{
            font-family: var(--type-value-family);
            font-size: var(--type-value-size);
            font-weight: var(--type-value-weight);
            letter-spacing: var(--type-value-track);
            color: var(--type-value-color);
            line-height: 1.75;
            overflow-wrap: anywhere;
        }}

        .app-subtitle,
        .section-copy {{
            max-width: 840px;
        }}

        .section-title {{
            font-size: 20px;
            font-weight: 600;
            margin-bottom: var(--sp-xs);
        }}

        .status-pill {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            background: rgba(41, 211, 152, 0.12);
            border: 1px solid rgba(41, 211, 152, 0.42);
            color: var(--success);
            font-size: 0.85rem;
            font-weight: 600;
        }}

        .status-pill-warn {{
            background: rgba(255, 184, 77, 0.14);
            border-color: rgba(255, 184, 77, 0.46);
            color: var(--warning);
        }}

        .policy-grid {{
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: var(--sp-sm);
            margin-top: var(--sp-md);
        }}

        .policy-card {{
            border: 1.5px solid var(--border-strong);
            border-radius: var(--sp-sm);
            background: var(--policy-card-bg);
            padding: var(--sp-sm);
            box-shadow: var(--inset-hairline);
        }}

        .policy-card-critical {{
            border-color: rgba(255, 107, 107, 0.58);
            background: var(--policy-card-critical-bg);
            box-shadow: 0 12px 28px rgba(255, 107, 107, 0.08);
        }}

        .policy-card-critical .policy-label,
        .policy-card-critical .policy-value {{
            color: var(--policy-card-critical-text);
        }}

        .policy-card-good {{
            border-color: rgba(41, 211, 152, 0.52);
            background: var(--policy-card-good-bg);
            box-shadow: 0 12px 28px rgba(41, 211, 152, 0.08);
        }}

        .policy-card-warn {{
            border-color: var(--warning);
            background: var(--policy-card-warn-bg);
            box-shadow: 0 12px 28px rgba(247, 201, 72, 0.08);
        }}

        .policy-card-warn .policy-label,
        .policy-card-warn .policy-value {{
            color: var(--policy-card-warn-text);
        }}

        .policy-card .policy-value {{
            margin-top: var(--sp-xs);
        }}

        .landing-shell {{
            max-width: 1120px;
            margin: 0 auto;
        }}

        .landing-hero {{
            display: grid;
            grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
            gap: var(--sp-lg);
            align-items: stretch;
            margin-bottom: var(--sp-lg);
        }}

        .landing-hero-panel,
        .landing-side-panel,
        .landing-step-panel,
        .framework-note-panel {{
            border: 1.5px solid var(--border-subtle);
            border-radius: 24px;
            background: var(--landing-panel-bg);
            box-shadow: var(--panel-shadow);
        }}

        .landing-hero-panel {{
            padding: 40px;
            background: var(--landing-hero-bg);
        }}

        .landing-side-panel,
        .landing-step-panel,
        .framework-note-panel {{
            padding: var(--sp-lg);
        }}

        .landing-badge {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 8px 14px;
            border-radius: 999px;
            border: 1px solid var(--landing-badge-border);
            background: var(--landing-badge-bg);
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--landing-badge-text);
            margin-bottom: var(--sp-md);
        }}

        .landing-badge-dot {{
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: #29d398;
            box-shadow: 0 0 0 6px rgba(41, 211, 152, 0.1);
        }}

        .landing-title {{
            font-family: var(--type-heading-family);
            font-size: clamp(36px, 4.8vw, 62px);
            font-weight: 700;
            letter-spacing: 0.08em;
            line-height: 0.98;
            text-transform: uppercase;
            color: var(--type-heading-color);
            margin-bottom: var(--sp-md);
            max-width: 720px;
        }}

        .landing-copy {{
            font-family: var(--type-value-family);
            font-size: 13px;
            font-weight: var(--type-value-weight);
            letter-spacing: 0.03em;
            color: var(--type-value-color);
            line-height: 1.85;
            max-width: 720px;
        }}

        .landing-card-grid {{
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: var(--sp-sm);
            margin-bottom: var(--sp-lg);
        }}

        .landing-card {{
            border: 1.5px solid var(--landing-card-border);
            border-radius: 18px;
            padding: var(--sp-md);
            background: var(--landing-card-bg);
            box-shadow: var(--inset-hairline);
        }}

        .landing-card-title,
        .landing-step-index {{
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            font-weight: var(--type-label-weight);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
        }}

        .landing-card-value,
        .landing-step-title {{
            font-family: var(--type-heading-family);
            font-size: 18px;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: var(--type-heading-color);
            margin-top: var(--sp-xs);
            margin-bottom: var(--sp-xs);
        }}

        .landing-card-copy,
        .landing-step-copy {{
            font-family: var(--type-value-family);
            font-size: var(--type-value-size);
            letter-spacing: var(--type-value-track);
            color: var(--type-value-color);
            line-height: 1.75;
        }}

        .landing-side-panel .policy-grid {{
            margin-top: 0;
        }}

        .landing-step-list {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: var(--sp-sm);
        }}

        .landing-step {{
            border: 1.5px solid var(--border-subtle);
            border-radius: 18px;
            padding: var(--sp-md);
            background: var(--landing-step-bg);
        }}

        .framework-note-panel {{
            margin-top: var(--sp-md);
            border-color: var(--input-border-focus);
            background: var(--framework-note-bg);
        }}

        .framework-note-strong {{
            color: var(--framework-note-strong);
        }}

        .landing-cta-wrap {{
            max-width: 420px;
            margin: var(--sp-lg) auto 0 auto;
        }}

        .landing-cta-note {{
            text-align: center;
            margin-top: var(--sp-sm);
            font-family: var(--type-value-family);
            font-size: var(--type-value-size);
            letter-spacing: var(--type-value-track);
            color: var(--type-value-color);
            opacity: 0.86;
        }}

        [data-testid="stMetric"] {{
            background: var(--metric-bg);
            border: 1.5px solid var(--metric-border);
            border-radius: 16px;
            padding: 14px;
            box-shadow: var(--inset-hairline);
        }}

        [data-testid="stMetricLabel"] p {{
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
        }}

        [data-testid="stMetricValue"] {{
            font-family: var(--type-heading-family);
            letter-spacing: 0.05em;
            color: var(--type-heading-color);
        }}

        label[data-testid="stWidgetLabel"] p {{
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            font-weight: var(--type-label-weight);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
        }}

        [data-testid="stTextInput"],
        [data-testid="stSelectbox"],
        [data-testid="stTextArea"],
        [data-testid="stNumberInput"] {{
            margin-bottom: var(--sp-md);
        }}

        div[data-baseweb="base-input"],
        div[data-baseweb="select"] > div,
        div[data-baseweb="textarea"] {{
            min-height: var(--sp-xl);
            width: 100%;
            display: flex !important;
            align-items: center !important;
            overflow: hidden !important;
            border: 1.5px solid var(--input-border-default) !important;
            border-radius: var(--sp-sm) !important;
            background: var(--input-bg) !important;
            box-shadow: none !important;
            transition:
                border-color var(--motion-fast) var(--ease-out),
                box-shadow var(--motion-fast) var(--ease-out),
                background var(--motion-fast) var(--ease-out);
        }}

        div[data-baseweb="base-input"]:hover,
        div[data-baseweb="select"] > div:hover,
        div[data-baseweb="textarea"]:hover {{
            background: var(--input-hover-bg) !important;
        }}

        div[data-baseweb="select"],
        div[data-baseweb="select"] *,
        div[data-baseweb="popover"] [role="listbox"],
        div[data-baseweb="popover"] [role="option"] {{
            color: var(--type-value-color) !important;
            -webkit-text-fill-color: var(--type-value-color) !important;
        }}

        div[data-baseweb="select"] svg,
        div[data-baseweb="popover"] svg {{
            color: var(--input-icon) !important;
            fill: currentColor !important;
        }}

        div[data-baseweb="popover"] [role="listbox"] {{
            background: var(--surface-raised) !important;
            border: 1.5px solid var(--border-strong) !important;
            border-radius: var(--sp-sm) !important;
            box-shadow: var(--panel-shadow) !important;
            overflow: hidden !important;
        }}

        div[data-baseweb="popover"],
        div[data-baseweb="popover"] ul {{
            background: var(--surface-raised) !important;
            border-color: var(--border-strong) !important;
            color: var(--type-value-color) !important;
            -webkit-text-fill-color: var(--type-value-color) !important;
        }}

        div[data-baseweb="popover"] li[role="option"] {{
            background: var(--surface-raised) !important;
            color: var(--type-value-color) !important;
            -webkit-text-fill-color: var(--type-value-color) !important;
        }}

        div[data-baseweb="popover"] li[role="option"] *,
        div[data-baseweb="popover"] li[role="option"] p,
        div[data-baseweb="popover"] li[role="option"] span {{
            color: var(--type-value-color) !important;
            -webkit-text-fill-color: var(--type-value-color) !important;
        }}

        div[data-baseweb="popover"] li[role="option"]:hover,
        div[data-baseweb="popover"] li[role="option"][aria-selected="true"],
        div[data-baseweb="popover"] li[role="option"][aria-highlighted="true"] {{
            background: var(--input-hover-bg) !important;
        }}

        div[data-baseweb="base-input"]:focus-within,
        div[data-baseweb="select"]:focus-within > div,
        div[data-baseweb="textarea"]:focus-within {{
            border-color: var(--input-border-focus) !important;
            box-shadow: var(--input-focus-shadow) !important;
        }}

        div[data-testid="stTextInputRootElement"] {{
            width: 100% !important;
            min-height: var(--sp-xl) !important;
            padding: 0 !important;
            display: flex !important;
            align-items: center !important;
            overflow: hidden !important;
            border: 1.5px solid var(--input-border-default) !important;
            border-radius: var(--sp-sm) !important;
            background: var(--input-bg) !important;
            box-shadow: none !important;
            transition:
                border-color var(--motion-fast) var(--ease-out),
                box-shadow var(--motion-fast) var(--ease-out),
                background var(--motion-fast) var(--ease-out);
        }}

        div[data-testid="stTextInputRootElement"]:hover {{
            background: var(--input-hover-bg) !important;
        }}

        div[data-testid="stTextInputRootElement"]:focus-within {{
            border-color: var(--input-border-focus) !important;
            box-shadow: var(--input-focus-shadow) !important;
        }}

        div[data-testid="stTextInputRootElement"] > div[data-baseweb="base-input"] {{
            flex: 1 1 auto !important;
            width: 100% !important;
            min-width: 0 !important;
            border: 0 !important;
            border-radius: 0 !important;
            background: transparent !important;
            box-shadow: none !important;
        }}

        div[data-baseweb="base-input"] input,
        div[data-baseweb="textarea"] textarea,
        div[data-baseweb="select"] input {{
            width: 100% !important;
            min-height: calc(var(--sp-xl) - 3px) !important;
            padding: 0 var(--sp-sm) !important;
            border: 0 !important;
            background: transparent !important;
            font-family: var(--type-value-family) !important;
            font-size: var(--type-value-size) !important;
            font-weight: var(--type-value-weight) !important;
            letter-spacing: var(--type-value-track) !important;
            color: var(--type-value-color) !important;
        }}

        div[data-baseweb="base-input"] input:focus,
        div[data-baseweb="textarea"] textarea:focus,
        div[data-baseweb="select"] input:focus {{
            outline: none !important;
            box-shadow: none !important;
        }}

        div[data-baseweb="base-input"] button {{
            align-self: stretch !important;
            width: var(--sp-xl) !important;
            min-width: var(--sp-xl) !important;
            min-height: calc(var(--sp-xl) - 3px) !important;
            height: auto !important;
            margin: 0 !important;
            border: 0 !important;
            border-left: 1px solid var(--border-subtle) !important;
            border-radius: 0 !important;
            background: var(--input-button-bg) !important;
            color: var(--input-icon) !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            box-shadow: none !important;
        }}

        div[data-baseweb="base-input"] button:hover {{
            background: var(--input-button-hover-bg) !important;
            transform: none !important;
            box-shadow: none !important;
        }}

        div[data-baseweb="base-input"] button:focus-visible {{
            outline: 3px solid var(--focus-ring) !important;
            outline-offset: -3px !important;
            box-shadow: var(--focus-shadow) !important;
        }}

        div[data-baseweb="base-input"] button svg {{
            color: var(--input-icon) !important;
            fill: currentColor !important;
        }}

        div[data-baseweb="base-input"] input::placeholder,
        div[data-baseweb="textarea"] textarea::placeholder,
        div[data-baseweb="select"] input::placeholder {{
            color: var(--placeholder-text) !important;
            opacity: 1 !important;
        }}

        [data-testid="stButton"] > button,
        [data-testid="stFormSubmitButton"] > button {{
            min-height: var(--sp-xl);
            width: 100%;
            border: 0;
            border-radius: var(--sp-sm);
            background: linear-gradient(90deg, var(--accent) 0%, var(--accent-strong) 100%);
            color: var(--button-text);
            font-family: var(--type-heading-family);
            font-size: var(--type-heading-size);
            font-weight: var(--type-heading-weight);
            letter-spacing: var(--type-heading-track);
            text-transform: uppercase;
            box-shadow: var(--button-shadow);
            transition:
                transform var(--motion-fast) var(--ease-out),
                box-shadow var(--motion-fast) var(--ease-out),
                filter var(--motion-fast) var(--ease-out),
                opacity var(--motion-fast) var(--ease-out);
        }}

        [data-testid="stButton"] > button:hover,
        [data-testid="stFormSubmitButton"] > button:hover {{
            transform: translateY(-1px);
            filter: saturate(1.05);
            box-shadow: var(--button-shadow-hover);
        }}

        [data-testid="stButton"] > button:active,
        [data-testid="stFormSubmitButton"] > button:active {{
            transform: translateY(0);
            box-shadow: inset 0 0 0 1px rgba(7, 16, 30, 0.18);
        }}

        [data-testid="stButton"] > button:disabled,
        [data-testid="stFormSubmitButton"] > button:disabled {{
            opacity: 1;
            background: var(--disabled-bg) !important;
            border: 1.5px solid var(--border-subtle) !important;
            filter: grayscale(0.25);
            box-shadow: none;
            color: var(--text-disabled) !important;
            cursor: not-allowed;
        }}

        [data-testid="stButton"] > button:focus-visible,
        [data-testid="stFormSubmitButton"] > button:focus-visible,
        [data-testid="stDownloadButton"] > button:focus-visible,
        [data-testid="stFileUploaderDropzone"] button:focus-visible,
        [data-baseweb="tab"]:focus-visible,
        [data-testid="stExpander"] summary:focus-visible {{
            outline: 3px solid var(--focus-ring) !important;
            outline-offset: 3px !important;
            box-shadow: var(--focus-shadow) !important;
        }}

        [data-testid="stDownloadButton"] > button {{
            min-height: 44px;
            width: 100%;
            border: 1.5px solid var(--border-strong);
            border-radius: var(--sp-sm);
            background: var(--download-bg);
            color: var(--download-text);
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            transition:
                border-color var(--motion-fast) var(--ease-out),
                transform var(--motion-fast) var(--ease-out);
        }}

        [data-testid="stDownloadButton"] > button:hover {{
            border-color: var(--input-border-focus);
            transform: translateY(-1px);
        }}

        [data-baseweb="tab-list"] {{
            gap: var(--sp-sm);
            margin-bottom: var(--sp-md);
        }}

        [data-baseweb="tab"] {{
            height: 46px;
            padding: 0 18px;
            border-radius: 999px;
            border: 1.5px solid var(--border-subtle);
            background: var(--tab-bg);
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
            transition:
                background var(--motion-fast) var(--ease-out),
                border-color var(--motion-fast) var(--ease-out),
                color var(--motion-fast) var(--ease-out);
        }}

        [data-baseweb="tab"][aria-selected="true"] {{
            background: linear-gradient(90deg, var(--accent) 0%, var(--accent-strong) 100%);
            color: var(--tab-active-text);
            border-color: transparent;
        }}

        [data-baseweb="tab-highlight"] {{
            display: none !important;
        }}

        [data-baseweb="tab-border"] {{
            background: var(--border-subtle) !important;
        }}

        [data-testid="stExpander"] {{
            border: 1.5px solid var(--border-subtle);
            border-radius: 18px;
            background: var(--expander-bg);
            overflow: hidden;
        }}

        [data-testid="stExpander"] summary p {{
            font-family: var(--type-heading-family);
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: var(--type-heading-color);
        }}

        [data-testid="stFileUploaderDropzone"] {{
            border: 1.5px dashed var(--uploader-border) !important;
            background: var(--uploader-bg) !important;
            border-radius: 18px !important;
            padding: var(--sp-md) !important;
            transition:
                border-color var(--motion-fast) var(--ease-out),
                box-shadow var(--motion-fast) var(--ease-out);
        }}

        [data-testid="stFileUploaderDropzone"]:hover {{
            border-color: var(--input-border-focus) !important;
        }}

        [data-testid="stFileUploaderDropzone"] button {{
            min-height: 44px !important;
            border: 1.5px solid var(--border-strong) !important;
            border-radius: var(--sp-sm) !important;
            background: var(--secondary-button-bg) !important;
            color: var(--secondary-button-text) !important;
            box-shadow: none !important;
        }}

        [data-testid="stFileUploaderDropzone"] button:hover {{
            border-color: var(--input-border-focus) !important;
            transform: none !important;
        }}

        [data-testid="stFileUploaderDropzone"] small,
        [data-testid="stFileUploaderDropzone"] span,
        [data-testid="stFileUploaderDropzone"] p {{
            color: var(--text-secondary) !important;
        }}

        [data-testid="stAlert"] {{
            border: 1.5px solid var(--border-subtle);
            border-radius: 16px;
            background: var(--alert-bg);
            color: var(--type-value-color);
        }}

        [data-testid="stAlert"] *,
        [data-testid="stCaptionContainer"],
        [data-testid="stCaptionContainer"] * {{
            color: var(--type-value-color) !important;
        }}

        .empty-state {{
            border: 1.5px dashed var(--border-subtle);
            border-radius: 20px;
            padding: var(--sp-lg);
            margin-top: var(--sp-md);
            background: var(--empty-bg);
        }}

        .empty-state__title {{
            font-family: var(--type-heading-family);
            font-size: 20px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--text-primary);
            margin: 0 0 var(--sp-xs) 0;
        }}

        .empty-state__body {{
            font-family: var(--type-value-family);
            color: var(--text-secondary);
            line-height: 1.6;
            margin: 0;
            max-width: 720px;
        }}

        .status-text {{
            color: var(--text-secondary);
            font-family: var(--type-value-family);
            line-height: 1.6;
        }}

        [data-testid="stCodeBlock"] pre,
        .stCodeBlock pre,
        pre,
        [data-testid="stJson"],
        [data-testid="stJson"] pre,
        [data-testid="stJson"] code {{
            border: 1.5px solid var(--border-subtle);
            border-radius: 18px;
            background: var(--code-bg) !important;
            color: var(--text-primary) !important;
        }}

        [data-testid="stJson"],
        [data-testid="stJson"] * {{
            background-color: transparent !important;
            color: var(--text-primary) !important;
            -webkit-text-fill-color: var(--text-primary) !important;
        }}

        pre code {{
            border: 0 !important;
            background: transparent !important;
        }}

        div[data-testid="stDataFrame"] {{
            border: 1.5px solid var(--dataframe-border);
            border-radius: 16px;
            overflow: hidden;
            background: var(--table-bg) !important;
            color: var(--table-text) !important;
        }}

        div[data-testid="stDataFrame"] *,
        div[data-testid="stDataFrameResizable"] *,
        [data-testid="stTable"] *,
        .stDataFrame *,
        .stTable * {{
            color: var(--table-text) !important;
            -webkit-text-fill-color: var(--table-text) !important;
        }}

        div[data-testid="stDataFrame"] > div,
        div[data-testid="stDataFrameResizable"] > div,
        [data-testid="stTable"],
        [data-testid="stTable"] table {{
            background: var(--table-bg) !important;
        }}

        [data-testid="stTable"] th,
        div[data-testid="stDataFrame"] [role="columnheader"] {{
            background: var(--table-header-bg) !important;
            color: var(--table-text) !important;
            border-color: var(--dataframe-border) !important;
        }}

        [data-testid="stTable"] td,
        [data-testid="stTable"] th,
        div[data-testid="stDataFrame"] [role="gridcell"] {{
            border-color: var(--dataframe-border) !important;
        }}

        [data-testid="stTable"] tr:nth-child(odd) td {{
            background: var(--table-row-bg) !important;
        }}

        [data-testid="stTable"] tr:nth-child(even) td {{
            background: var(--table-row-alt-bg) !important;
        }}

        [data-testid="stTable"] tr:hover td {{
            background: var(--table-hover-bg) !important;
        }}

        [data-testid="stForm"] {{
            border: 1.5px solid var(--border-subtle) !important;
            border-radius: 18px !important;
            background: var(--form-bg) !important;
            padding: var(--sp-md) !important;
            box-shadow: var(--inset-hairline) !important;
        }}

        [data-testid="stForm"] [data-testid="stVerticalBlock"] {{
            gap: var(--sp-sm);
        }}

        .admin-table-wrap {{
            width: 100%;
            max-width: 100%;
            overflow-x: auto;
            border: 1.5px solid var(--dataframe-border);
            border-radius: 18px;
            background: var(--table-bg);
            box-shadow: var(--inset-hairline);
            margin: var(--sp-sm) 0 var(--sp-md) 0;
        }}

        .admin-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            table-layout: fixed;
            color: var(--table-text);
            font-family: var(--type-value-family);
            font-size: 13px;
            line-height: 1.45;
        }}

        .admin-table th,
        .admin-table td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--dataframe-border);
            border-right: 1px solid var(--dataframe-border);
            vertical-align: top;
            text-align: left;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .admin-table th:last-child,
        .admin-table td:last-child {{
            border-right: 0;
        }}

        .admin-table tr:last-child td {{
            border-bottom: 0;
        }}

        .admin-table th {{
            position: sticky;
            top: 0;
            z-index: 1;
            background: var(--table-header-bg);
            color: var(--text-muted);
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            font-weight: var(--type-label-weight);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
        }}

        .admin-table tbody tr:nth-child(odd) {{
            background: var(--table-row-bg);
        }}

        .admin-table tbody tr:nth-child(even) {{
            background: var(--table-row-alt-bg);
        }}

        .admin-table tbody tr:hover {{
            background: var(--table-hover-bg);
        }}

        .admin-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 68px;
            padding: 4px 9px;
            border-radius: 999px;
            border: 1px solid var(--border-subtle);
            font-family: var(--type-label-family);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }}

        .admin-badge--success {{
            color: var(--success);
            background: var(--policy-card-good-bg);
        }}

        .admin-badge--danger {{
            color: var(--danger);
            background: var(--policy-card-critical-bg);
        }}

        div[data-baseweb="menu"],
        div[data-baseweb="menu"] ul,
        div[data-baseweb="popover"] {{
            background: var(--surface-raised) !important;
            color: var(--text-primary) !important;
        }}

        div[data-baseweb="menu"] li,
        div[data-baseweb="menu"] [role="option"] {{
            background: var(--surface-raised) !important;
            color: var(--text-primary) !important;
        }}

        div[data-baseweb="menu"] li:hover,
        div[data-baseweb="menu"] [role="option"]:hover,
        div[data-baseweb="menu"] [aria-selected="true"] {{
            background: var(--table-hover-bg) !important;
            color: var(--text-primary) !important;
        }}

        *::-webkit-scrollbar {{
            width: 12px;
            height: 12px;
        }}

        *::-webkit-scrollbar-track {{
            background: var(--scrollbar-track);
        }}

        *::-webkit-scrollbar-thumb {{
            background: var(--scrollbar-thumb);
            border: 3px solid var(--scrollbar-track);
            border-radius: 999px;
        }}

        .login-shell {{
            width: 100%;
            max-width: none;
            margin: var(--sp-md) 0 var(--sp-md) 0;
        }}

        .login-kicker {{
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            font-weight: var(--type-label-weight);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
            margin-bottom: var(--sp-xs);
        }}

        .login-title {{
            font-family: var(--type-heading-family);
            font-size: clamp(32px, 4vw, 48px);
            font-weight: var(--type-heading-weight);
            letter-spacing: var(--type-heading-track);
            text-transform: uppercase;
            color: var(--type-heading-color);
            margin-bottom: var(--sp-sm);
        }}

        .login-copy,
        .login-note,
        .login-status-detail,
        .login-meta-value {{
            font-family: var(--type-value-family);
            font-size: var(--type-value-size);
            font-weight: var(--type-value-weight);
            letter-spacing: var(--type-value-track);
            color: var(--type-value-color);
            line-height: 1.7;
        }}

        .login-copy {{
            margin-bottom: var(--sp-md);
        }}

        .login-status-card {{
            border: 1.5px solid var(--border-strong);
            border-radius: 18px;
            background: var(--login-card-bg);
            padding: var(--sp-md);
            margin: 0 0 var(--sp-md) 0;
            box-shadow: var(--panel-shadow);
        }}

        .login-status-card.tone-active {{
            border-color: var(--input-border-focus);
            box-shadow: 0 0 0 1px rgba(247, 201, 72, 0.14), 0 18px 44px rgba(247, 201, 72, 0.12);
        }}

        .login-status-card.tone-success {{
            border-color: rgba(41, 211, 152, 0.54);
        }}

        .login-status-card.tone-error {{
            border-color: rgba(255, 107, 107, 0.58);
        }}

        .login-status-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--sp-sm);
            margin-bottom: var(--sp-sm);
        }}

        .login-status-label,
        .login-meta-label,
        .login-field-label {{
            font-family: var(--type-label-family);
            font-size: var(--type-label-size);
            font-weight: var(--type-label-weight);
            letter-spacing: var(--type-label-track);
            text-transform: uppercase;
            color: var(--type-label-color);
        }}

        .login-status-value {{
            font-family: var(--type-value-family);
            font-size: var(--type-value-size);
            font-weight: var(--type-value-weight);
            letter-spacing: var(--type-value-track);
            color: var(--type-value-color);
        }}

        .login-status-track {{
            height: var(--sp-xs);
            border-radius: 999px;
            background: var(--login-track-bg);
            border: 1.5px solid var(--login-track-border);
            overflow: hidden;
            margin-bottom: var(--sp-sm);
        }}

        .login-status-fill {{
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, #1f4c77 0%, #f7c948 100%);
            transition: width var(--motion-fast) var(--ease-out);
        }}

        .tone-active .login-status-fill {{
            background: linear-gradient(90deg, #2d658d 0%, #f7c948 100%);
        }}

        .tone-success .login-status-fill {{
            background: linear-gradient(90deg, #17654e 0%, #29d398 100%);
        }}

        .tone-error .login-status-fill {{
            background: linear-gradient(90deg, #7a2334 0%, #ff6b6b 100%);
        }}

        .login-note-panel {{
            border: 1.5px solid var(--border-strong);
            border-radius: 18px;
            background: var(--login-note-bg);
            padding: var(--sp-md);
            margin-bottom: var(--sp-md);
        }}

        .login-field-label {{
            margin: 0 0 var(--sp-xs) 0;
        }}

        .login-meta-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: var(--sp-sm);
            margin-top: var(--sp-md);
        }}

        .login-meta-card {{
            border: 1.5px solid var(--border-strong);
            border-radius: 18px;
            background: var(--login-meta-bg);
            padding: var(--sp-sm);
        }}

        .login-meta-card-critical {{
            border-color: rgba(255, 107, 107, 0.6);
            background: var(--login-critical-bg);
            box-shadow: 0 12px 28px rgba(255, 107, 107, 0.08);
        }}

        .login-meta-card-critical .login-meta-label,
        .login-meta-card-critical .login-meta-value {{
            color: var(--login-critical-text);
        }}

        .login-processing-indicator {{
            min-height: var(--sp-xl);
            border: 1.5px solid rgba(247, 201, 72, 0.52);
            border-radius: var(--sp-sm);
            background: var(--login-processing-bg);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: var(--sp-sm);
            box-shadow: 0 12px 30px rgba(247, 201, 72, 0.12);
        }}

        .login-processing-text {{
            font-family: var(--type-heading-family);
            font-size: var(--type-heading-size);
            font-weight: var(--type-heading-weight);
            letter-spacing: var(--type-heading-track);
            text-transform: uppercase;
            color: var(--type-heading-color);
        }}

        .login-processing-dot {{
            width: var(--sp-xs);
            height: var(--sp-xs);
            border-radius: 999px;
            background: var(--accent);
            animation: loginPulse 1.15s ease-in-out infinite;
        }}

        .login-processing-dot:nth-child(2) {{
            animation-delay: 0.18s;
        }}

        .login-processing-dot:nth-child(3) {{
            animation-delay: 0.36s;
        }}

        @keyframes loginPulse {{
            0%, 100% {{
                transform: scale(0.86);
                opacity: 0.46;
            }}
            50% {{
                transform: scale(1);
                opacity: 1;
            }}
        }}

        @media (max-width: 900px) {{
            .policy-grid {{
                grid-template-columns: 1fr;
            }}

            .app-title {{
                font-size: 32px;
            }}

            .landing-hero,
            .landing-card-grid,
            .landing-step-list {{
                grid-template-columns: 1fr;
            }}

            .login-shell {{
                margin-top: var(--sp-lg);
            }}

            .login-meta-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        @media (prefers-reduced-motion: reduce) {{
            *, *::before, *::after {{
                animation-duration: 1ms !important;
                animation-iteration-count: 1 !important;
                scroll-behavior: auto !important;
                transition-duration: 1ms !important;
            }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_login_css(processing: bool = False) -> None:
    _ = processing


def _render_login_status(target: Any, *, title: str, detail: str, progress: int, tone: str = "neutral") -> None:
    safe_progress = max(0, min(100, int(progress)))
    safe_tone = tone if tone in {"neutral", "active", "success", "error"} else "neutral"
    target.markdown(
        f"""
        <div class="login-status-card tone-{safe_tone}">
            <div class="login-status-header">
                <div class="login-status-label">{escape(title)}</div>
                <div class="login-status-value">{safe_progress:03d}%</div>
            </div>
            <div class="login-status-track">
                <div class="login-status-fill" style="width:{safe_progress}%"></div>
            </div>
            <div class="login-status-detail">{escape(detail)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_login_processing_indicator(target: Any) -> None:
    target.markdown(
        """
        <div class="login-processing-indicator">
            <span class="login-processing-dot"></span>
            <span class="login-processing-dot"></span>
            <span class="login-processing-dot"></span>
            <span class="login-processing-text">Processing</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _process_login_attempt(status_placeholder: Any) -> None:
    username = str(st.session_state.get("login_username", "")).strip()
    password = str(st.session_state.get("login_password", ""))

    if not username or not password:
        st.session_state.login_processing = False
        st.session_state.login_notice = {
            "tone": "error",
            "title": "Missing Credentials",
            "detail": "Enter your username and password, then sign in.",
        }
        st.rerun()

    _render_login_status(
        status_placeholder,
        title="Checking Your Details",
        detail="We are checking your username and password.",
        progress=24,
        tone="active",
    )
    time.sleep(0.08)
    _render_login_status(
        status_placeholder,
        title="Verifying Account",
        detail="We are checking that this account can use the tool.",
        progress=61,
        tone="active",
    )

    try:
        user = authenticate_user(username, password, session_id=_browser_session_id())
    except AuthError as exc:
        LOGGER.warning("Authentication attempt blocked: %s", exc)
        st.session_state.login_processing = False
        st.session_state.login_clear_password = True
        st.session_state.login_notice = {
            "tone": "error",
            "title": "Sign In Blocked",
            "detail": "We could not complete sign in. Check your username and password, then try again.",
        }
        st.rerun()

    if user is None:
        st.session_state.login_processing = False
        st.session_state.login_clear_password = True
        st.session_state.login_notice = {
            "tone": "error",
            "title": "Access Denied",
            "detail": "The username or password is not correct. Check both fields and try again.",
        }
        st.rerun()

    _render_login_status(
        status_placeholder,
        title="Sign In Complete",
        detail=f"Signed in as {user.username}. Opening the analysis workspace.",
        progress=100,
        tone="success",
    )
    time.sleep(0.16)

    now = time.time()
    session_id = _browser_session_id()
    browser_token = ""
    try:
        browser_token = create_browser_session(user.username, session_id=session_id)
        st.session_state.pending_auth_cookie = browser_token
    except AuthError as exc:
        LOGGER.warning("Persistent browser session was not created: %s", exc)
        log_event(
            "browser_session_create_failure",
            username=user.username,
            success=False,
            session_id=session_id,
            message="Persistent browser session could not be created.",
        )

    st.session_state.auth_user = {
        "username": user.username,
        "role": user.role,
        "session_id": session_id,
        "login_at": now,
        "last_activity_at": now,
        "browser_token": browser_token,
    }
    st.session_state.login_processing = False
    st.session_state.login_notice = None
    st.session_state.login_clear_password = True
    st.rerun()


def _render_bootstrap_required() -> None:
    st.markdown(
        """
        <div class="app-shell" style="max-width:760px;">
            <div class="app-kicker">Initial Bootstrap</div>
            <h1 class="app-title">Initial Admin Setup</h1>
            <div class="app-subtitle">
                No local users exist yet. Create the first admin account from a terminal, then refresh this page.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class="app-shell" style="max-width:760px;">
            <div class="policy-grid">
                {_policy_card_markup("Auth Database", str(AUTH_DB_PATH))}
                {_policy_card_markup("Required Step", "Create First Admin", tone="warn")}
                {_policy_card_markup("Next Action", "Refresh This Page")}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.code(
        f"cd \"{ROOT_DIR}\"\n"
        ".\\.venv-app\\Scripts\\python.exe .\\bootstrap_admin.py --username admin",
        language="powershell",
    )
    st.caption(f"Auth database will be created at: {AUTH_DB_PATH}")


def _render_auth_recovery_required(status: dict[str, Any]) -> None:
    latest_backup = latest_auth_db_backup()
    latest_backup_text = str(latest_backup) if latest_backup else "No backup found"
    st.markdown(
        f"""
        <div class="app-shell" style="max-width:860px;">
            <div class="app-kicker">Security Recovery Required</div>
            <h1 class="app-title">Authentication Store Integrity Check Failed</h1>
            <div class="app-subtitle">
                The app found evidence that this host was already initialized, but the local auth database is
                missing, empty, or unreadable. This is treated as a security-state change, not a first-run setup.
            </div>
            <div class="policy-grid">
                {_policy_card_markup("NIST Mapping", "CM-3 / SI-7 / AU-2", tone="warn")}
                {_policy_card_markup("Auth DB", str(status.get("auth_db_path", AUTH_DB_PATH)), tone="critical")}
                {_policy_card_markup("Install Seal", str(status.get("install_state_path", INSTALL_STATE_PATH)))}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.error("Access is blocked until a trusted auth database backup is restored.")
    st.info("Do not run first-admin bootstrap again. Restore a known-good backup or rebuild this host deliberately.")
    st.code(
        ".\\.venv-app\\Scripts\\python.exe .\\restore_auth_backup.py --list\n"
        ".\\.venv-app\\Scripts\\python.exe .\\restore_auth_backup.py --backup <backup.db> --confirm RESTORE_AUTH_DB",
        language="powershell",
    )
    st.caption(f"Latest backup: {latest_backup_text}")
    st.caption(f"Security event log: {SECURITY_EVENTS_PATH}")


def _render_landing_page() -> None:
    st.markdown(
        f"""
        <div class="landing-shell">
            <div class="landing-hero">
                <div class="landing-hero-panel">
                    <div class="landing-badge">
                        <span class="landing-badge-dot"></span>
                        Trusted Local Evidence Workflow
                    </div>
                    <h1 class="landing-title">DIFD Fine-Tuned BusterNet Copy-Move Analysis</h1>
                    <div class="landing-copy">
                        A secure local workspace for copy-move forensic review. The tool is designed for evidence upload,
                        fine-tuned self-hosted BusterNet inference, EXIF inspection, and exportable PDF reporting while
                        keeping the analysis workflow behind authenticated access.
                    </div>
                </div>
                <div class="landing-side-panel">
                    <div class="section-eyebrow">Operational Profile</div>
                    <h2 class="section-title">Secure Entry Conditions</h2>
                    <div class="section-copy">
                        New visitors can review the workflow here, but authentication is required before image upload,
                        metadata inspection, runtime interaction, or report export.
                    </div>
                    <div class="policy-grid">
                        {_policy_card_markup("Access Model", "Authenticated local workspace", tone="warn")}
                        {_policy_card_markup("Analysis Scope", "Copy-move evidence review")}
                        {_policy_card_markup("Deployment Style", "Local-only sidecar inference", tone="good")}
                    </div>
                </div>
            </div>
            <div class="landing-card-grid">
                <div class="landing-card">
                    <div class="landing-card-title">Evidence Intake</div>
                    <h3 class="landing-card-value">Upload Protected Images</h3>
                    <div class="landing-card-copy">Accepts PNG, JPEG, BMP, and TIFF evidence files after authenticated access.</div>
                </div>
                <div class="landing-card">
                    <div class="landing-card-title">Model Runtime</div>
                    <h3 class="landing-card-value">Fine-tuned BusterNet</h3>
                    <div class="landing-card-copy">Runs the local self-hosted model to generate source, target, and combined tamper masks.</div>
                </div>
                <div class="landing-card">
                    <div class="landing-card-title">Report Output</div>
                    <h3 class="landing-card-value">Case-Ready Exports</h3>
                    <div class="landing-card-copy">Bundles visual overlays, EXIF findings, and runtime context into a downloadable PDF.</div>
                </div>
            </div>
            <div class="landing-step-panel">
                <div class="section-eyebrow">Workflow Path</div>
                <h2 class="section-title">How The Tool Is Used</h2>
                <div class="section-copy">
                    The workspace follows a linear evidence-review flow so the investigator can authenticate,
                    upload, analyze, review metadata, and export the case file with minimal ambiguity.
                </div>
                <div class="landing-step-list">
                    <div class="landing-step">
                        <div class="landing-step-index">01</div>
                        <h3 class="landing-step-title">Sign In</h3>
                        <div class="landing-step-copy">Authenticate into the secured local session before touching evidence.</div>
                    </div>
                    <div class="landing-step">
                        <div class="landing-step-index">02</div>
                        <h3 class="landing-step-title">Upload</h3>
                        <div class="landing-step-copy">Submit the evidence image and validate type, size, and pixel-safety limits.</div>
                    </div>
                    <div class="landing-step">
                        <div class="landing-step-index">03</div>
                        <h3 class="landing-step-title">Analyze</h3>
                        <div class="landing-step-copy">Run the local BusterNet sidecar and inspect source and target localization masks.</div>
                    </div>
                    <div class="landing-step">
                        <div class="landing-step-index">04</div>
                        <h3 class="landing-step-title">Export</h3>
                        <div class="landing-step-copy">Review EXIF indicators and generate a final PDF case report.</div>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _, center_col, _ = st.columns([1, 0.9, 1])
    with center_col:
        st.markdown('<div class="landing-cta-wrap">', unsafe_allow_html=True)
        if st.button("Continue to Sign In", key="landing_to_login", use_container_width=True):
            st.session_state.show_login_screen = True
            st.rerun()
        st.markdown(
            """
            <div class="landing-cta-note">
                Sign in to upload an image, run analysis, review metadata, and export a report.
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)


def _render_login() -> None:
    st.session_state.show_login_screen = True
    if st.session_state.get("login_clear_password"):
        st.session_state.pop("login_password", None)
        st.session_state.login_clear_password = False

    processing = bool(st.session_state.get("login_processing", False))
    notice = st.session_state.get("login_notice") or {}
    _render_login_css(processing=processing)

    _, center_col, _ = st.columns([0.22, 2.56, 0.22])
    with center_col:
        st.markdown(
            """
            <div class="login-shell">
                <div class="login-kicker">Local Access Control</div>
                <h1 class="login-title">DIFD Secure Login</h1>
                <div class="login-copy">
                    Sign in before you upload evidence, run BusterNet analysis, review metadata, or export reports.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        form_col, context_col = st.columns([0.54, 0.46], gap="large")

        with context_col:
            status_placeholder = st.empty()
            if processing:
                _render_login_status(
                    status_placeholder,
                    title="Signing In",
                    detail="We are checking your account now.",
                    progress=12,
                    tone="active",
                )
            elif notice:
                _render_login_status(
                    status_placeholder,
                    title=str(notice.get("title", "Authentication Status")),
                    detail=str(notice.get("detail", "")),
                    progress=100 if notice.get("tone") in {"success", "error"} else 0,
                    tone=str(notice.get("tone", "neutral")),
                )
            else:
                _render_login_status(
                    status_placeholder,
                    title="Sign In Ready",
                    detail=(
                        f"Local authentication is active. Minimum password length is {MIN_PASSWORD_LENGTH} characters"
                        f" and lockout begins after {LOCKOUT_THRESHOLD} failed attempts."
                    ),
                    progress=0,
                    tone="neutral",
                )
            st.markdown(
                """
                <div class="login-note-panel">
                    <div class="login-field-label">Access Scope</div>
                    <div class="login-note">
                        A successful sign in unlocks evidence upload, local BusterNet execution, EXIF review,
                        and PDF export inside the same authenticated session.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                f"""
                <div class="login-meta-grid">
                    <div class="login-meta-card">
                        <div class="login-meta-label">Mode</div>
                        <div class="login-meta-value">Local Auth Database</div>
                    </div>
                    <div class="login-meta-card">
                        <div class="login-meta-label">Minimum Password</div>
                        <div class="login-meta-value">{MIN_PASSWORD_LENGTH} Characters</div>
                    </div>
                    <div class="login-meta-card login-meta-card-critical">
                        <div class="login-meta-label">Lockout Threshold</div>
                        <div class="login-meta-value">{LOCKOUT_THRESHOLD} Failed Attempts</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                f"""
                <div class="framework-note-panel">
                    <div class="section-eyebrow">Password Policy</div>
                    <h2 class="section-title">NIST-Aligned Local Control Profile</h2>
                    <div class="section-copy">
                        This local authentication policy follows a <span class="framework-note-strong">NIST-aligned security framework</span>
                        for academic forensic use: minimum password length of {MIN_PASSWORD_LENGTH} characters, common-password blocking,
                        inactivity timeout enforcement, and lockout after {LOCKOUT_THRESHOLD} failed attempts.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with form_col:
            _render_theme_selector(key_suffix="login")
            st.text_input(
                "Username",
                key="login_username",
                placeholder="Enter your username",
                disabled=processing,
            )
            st.text_input(
                "Password",
                key="login_password",
                type="password",
                placeholder="Enter your password",
                disabled=processing,
            )

            action_placeholder = st.empty()
            if processing:
                _render_login_processing_indicator(action_placeholder)
                _process_login_attempt(status_placeholder)
                return

            with action_placeholder.container():
                if st.button("Sign In", use_container_width=True, key="login_submit"):
                    st.session_state.login_notice = None
                    st.session_state.login_processing = True
                    st.rerun()


def _require_authenticated_user() -> dict[str, Any]:
    store_status = get_auth_store_status()
    if store_status["state"] == "recovery_required":
        issue_key = json.dumps(
            {
                "state": store_status.get("state"),
                "db_status": store_status.get("db_status"),
                "auth_db_path": store_status.get("auth_db_path"),
            },
            sort_keys=True,
        )
        if st.session_state.get("last_auth_store_issue") != issue_key:
            log_security_event(
                "auth_store_recovery_required",
                success=False,
                message=str(store_status.get("message", "Auth store recovery required.")),
                details=store_status,
            )
            st.session_state.last_auth_store_issue = issue_key
        _render_auth_recovery_required(store_status)
        st.stop()

    if store_status["state"] == "not_initialized":
        _render_bootstrap_required()
        st.stop()

    if store_status.get("needs_seal"):
        try:
            seal_installation(created_by="existing_auth_db", reason="existing_auth_db_detected")
            log_security_event(
                "install_seal_migrated",
                username="existing_auth_db",
                success=True,
                message="Install seal created for existing auth database.",
                details=store_status,
            )
        except Exception as exc:
            LOGGER.exception("Install seal migration failed.")
            log_security_event(
                "install_seal_migration_failed",
                username="existing_auth_db",
                success=False,
                message=str(exc),
                details=store_status,
            )
            st.error("The authentication database is present, but the setup seal could not be created.")
            st.info("Check file permissions in the security folder, then restart the app.")
            st.stop()

    init_db()
    auth_user = st.session_state.get("auth_user")
    if not auth_user:
        cookie_token = _read_auth_cookie()
        restored = restore_browser_session(cookie_token, session_id=_browser_session_id())
        if restored:
            now = time.time()
            st.session_state.auth_user = {
                "username": restored["username"],
                "role": restored["role"],
                "session_id": _browser_session_id(),
                "login_at": now,
                "last_activity_at": now,
                "browser_token": cookie_token,
            }
            log_event(
                "browser_session_restored",
                username=restored["username"],
                success=True,
                session_id=_browser_session_id(),
                message="Session restored from browser cookie.",
            )
            st.session_state.pending_auth_cookie = cookie_token
            auth_user = st.session_state.auth_user
        else:
            auth_user = None

    if not auth_user:
        if not bool(st.session_state.get("show_login_screen", False)):
            _render_landing_page()
            st.stop()
        _render_login()
        st.stop()

    now = time.time()
    last_activity = float(auth_user.get("last_activity_at", now))
    if now - last_activity > SESSION_TIMEOUT_SECONDS:
        browser_token = str(auth_user.get("browser_token") or _read_auth_cookie())
        revoke_browser_session(
            browser_token,
            username=auth_user.get("username"),
            session_id=auth_user.get("session_id"),
            reason="session_timeout",
        )
        log_event(
            "session_timeout",
            username=auth_user.get("username"),
            success=False,
            session_id=auth_user.get("session_id"),
            message="Session exceeded inactivity timeout.",
        )
        _clear_authenticated_state()
        st.session_state.clear_auth_cookie = True
        st.session_state.show_login_screen = True
        st.warning("Your session timed out. Log in again to continue.")
        _render_login()
        st.stop()

    auth_user["last_activity_at"] = now
    browser_token = str(auth_user.get("browser_token") or _read_auth_cookie())
    if browser_token:
        if refresh_browser_session(browser_token, session_id=auth_user.get("session_id")):
            auth_user["browser_token"] = browser_token
        else:
            _clear_authenticated_state()
            st.session_state.clear_auth_cookie = True
            st.session_state.show_login_screen = True
            st.warning("Your saved session expired. Log in again to continue.")
            _render_login()
            st.stop()
    st.session_state.auth_user = auth_user
    return dict(auth_user)


def _render_admin_panel(current_user: dict[str, Any]) -> None:
    if current_user.get("role") != "admin":
        return

    store_status = get_auth_store_status()
    latest_backup = latest_auth_db_backup()
    st.markdown(
        """
        <div class="section-eyebrow">NIST-Mapped Security Administration</div>
        <h2 class="section-title">Security Admin</h2>
        <div class="section-copy">
            Admin-only controls for local account lifecycle, audit review, bootstrap lock state, and recovery posture.
        </div>
        """,
        unsafe_allow_html=True,
    )
    status_cols = st.columns(4)
    status_cols[0].metric("Auth Store", str(store_status.get("state", "unknown")).replace("_", " ").title())
    status_cols[1].metric("Install Seal", "Present" if store_status.get("install_sealed") else "Missing")
    status_cols[2].metric("Users", str(store_status.get("user_count") or 0))
    status_cols[3].metric("Latest Backup", latest_backup.name if latest_backup else "None")
    st.caption(f"Auth DB: {AUTH_DB_PATH}")
    st.caption(f"Install seal: {INSTALL_STATE_PATH}")
    st.caption(f"Backup folder: {AUTH_BACKUP_DIR}")

    users_table = list_users()
    _render_admin_table(
        "User Accounts",
        users_table,
        [
            ("username", "Username"),
            ("role", "Role"),
            ("is_active", "Status"),
            ("failed_attempts", "Failed"),
            ("locked_until", "Locked Until"),
            ("last_login_at", "Last Login"),
        ],
        empty_title="No users found",
        empty_body="Restore a trusted auth DB backup before using this workspace.",
    )

    create_col, manage_col = st.columns(2)
    with create_col:
        with st.form("create_user_form"):
            st.markdown('<h3 class="section-title">Create User</h3>', unsafe_allow_html=True)
            new_username = st.text_input("New username", key="new_user_username")
            new_role = st.selectbox("Role", ["analyst", "admin"], key="new_user_role")
            new_password = st.text_input("Password", type="password", key="new_user_password")
            create_clicked = st.form_submit_button("Create User Account")
        if create_clicked:
            if not new_username.strip():
                st.error("Enter a username.")
            elif len(new_password) < MIN_PASSWORD_LENGTH:
                st.error(f"Use at least {MIN_PASSWORD_LENGTH} characters for the password.")
            else:
                try:
                    create_user(new_username, new_password, role=new_role, created_by=current_user["username"])
                    st.success("User account created. A local auth DB backup was created before the change.")
                    st.rerun()
                except AuthError as exc:
                    LOGGER.warning("Admin user creation failed: %s", exc)
                    st.error(_plain_auth_admin_error(exc))

    with manage_col:
        users = [user["username"] for user in users_table]
        if users:
            with st.form("manage_user_form"):
                st.markdown('<h3 class="section-title">Manage User</h3>', unsafe_allow_html=True)
                selected_user = st.selectbox("User", users, key="manage_user")
                status_action = st.selectbox("Action", ["Disable", "Enable", "Reset password"], key="manage_action")
                reset_password = st.text_input("New password", type="password", key="reset_user_password")
                manage_clicked = st.form_submit_button("Update User Account")
            if manage_clicked:
                if status_action == "Reset password" and len(reset_password) < MIN_PASSWORD_LENGTH:
                    st.error(f"Use at least {MIN_PASSWORD_LENGTH} characters for the new password.")
                else:
                    try:
                        if status_action == "Disable":
                            if selected_user == current_user["username"]:
                                raise AuthError("You cannot disable your own active session account.")
                            set_user_active(selected_user, False, changed_by=current_user["username"])
                        elif status_action == "Enable":
                            set_user_active(selected_user, True, changed_by=current_user["username"])
                        else:
                            update_password(selected_user, reset_password, changed_by=current_user["username"])
                        st.success("User account updated. A local auth DB backup was created before the change.")
                        st.rerun()
                    except AuthError as exc:
                        LOGGER.warning("Admin user update failed: %s", exc)
                        st.error(_plain_auth_admin_error(exc))
        else:
            _render_empty_state("No users found", "Restore a trusted auth DB backup before using this workspace.")

    audit_col, security_col = st.columns(2)
    with audit_col:
        _render_admin_table(
            "Recent Audit Events",
            recent_audit_events(20),
            [
                ("timestamp", "Time"),
                ("username", "User"),
                ("event_type", "Event"),
                ("success", "Result"),
                ("message", "Message"),
            ],
            empty_title="No audit events yet",
            empty_body="Login, upload, analysis, export, and admin actions will appear here.",
        )
    with security_col:
        security_events = recent_security_events(20)
        _render_admin_table(
            "Security Events",
            security_events,
            [
                ("timestamp", "Time"),
                ("event_type", "Event"),
                ("success", "Result"),
                ("username", "User"),
                ("message", "Message"),
            ],
            empty_title="No security events logged",
            empty_body="Critical recovery and bootstrap events will appear here.",
        )
        if security_events:
            st.caption(f"Detailed event payloads remain in the local log: {SECURITY_EVENTS_PATH}")


def _validate_uploaded_image(uploaded_file: Any) -> tuple[bytes, Image.Image, Image.Image]:
    file_size = int(getattr(uploaded_file, "size", 0) or 0)
    if file_size <= 0:
        raise ValueError("Uploaded file is empty.")
    if file_size > MAX_UPLOAD_BYTES:
        max_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
        raise ValueError(f"Uploaded file exceeds the {max_mb:.0f} MB limit.")

    file_bytes = uploaded_file.getvalue()
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        max_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
        raise ValueError(f"Uploaded file exceeds the {max_mb:.0f} MB limit.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            original_image = Image.open(io.BytesIO(file_bytes))
            original_image.load()
    except Image.DecompressionBombWarning as exc:
        raise ValueError(
            f"Image dimensions exceed the configured {MAX_IMAGE_PIXELS:,} pixel safety limit."
        ) from exc
    except Image.DecompressionBombError as exc:
        raise ValueError(
            f"Image dimensions exceed the configured {MAX_IMAGE_PIXELS:,} pixel safety limit."
        ) from exc

    pixel_count = int(original_image.width * original_image.height)
    if pixel_count > MAX_IMAGE_PIXELS:
        raise ValueError(f"Image dimensions exceed the configured {MAX_IMAGE_PIXELS:,} pixel safety limit.")

    image_format = (original_image.format or "").upper()
    if image_format not in ALLOWED_IMAGE_FORMATS:
        raise ValueError("Unsupported image format.")

    return file_bytes, original_image, original_image.convert("RGB")


class ExifAnalyzer:
    SUPPORTED_FORMATS = {"JPEG", "JPG", "PNG", "BMP", "TIFF", "TIF"}
    EXIF_SUPPORTED_FORMATS = {"JPEG", "JPG", "TIFF", "TIF"}

    def __init__(self, image: Image.Image) -> None:
        self.image = image
        self.raw_exif: dict[int, Any] = {}
        self.normalized_exif: dict[str, Any] = {}
        self.categories: dict[str, dict[str, Any]] = {}
        self.flags: dict[str, Any] = {}
        self._run_analysis()

    def _run_analysis(self) -> None:
        self.raw_exif = self.extract_exif()
        self.normalized_exif = self.normalize_tags(self.raw_exif)
        self.categories = self.categorize_metadata(self.normalized_exif)
        self.flags = self.detect_anomalies(self.normalized_exif)

    def extract_exif(self) -> dict[int, Any]:
        img_format = (self.image.format or "").upper()
        if img_format not in self.SUPPORTED_FORMATS or img_format not in self.EXIF_SUPPORTED_FORMATS:
            return {}

        exif_data = self.image.getexif()
        if exif_data is None:
            return {}
        return dict(exif_data)

    def normalize_tags(self, raw_exif: dict[int, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for tag_id, value in raw_exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, f"Unknown_{tag_id}")
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="ignore")
            normalized[str(tag_name)] = value
        return normalized

    def categorize_metadata(self, exif_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        categories = {
            "camera_info": {},
            "datetime_info": {},
            "software_info": {},
            "technical_info": {},
            "other_info": {},
        }
        camera_tags = {"Make", "Model", "SerialNumber", "LensMake", "LensModel", "CameraSerialNumber"}
        datetime_tags = {"DateTime", "DateTimeOriginal", "DateTimeDigitized"}
        software_tags = {"Software", "ProcessingSoftware", "HostComputer", "CreatorTool"}
        technical_tags = {
            "ISO",
            "ISOSpeedRatings",
            "ExposureTime",
            "FNumber",
            "ApertureValue",
            "FocalLength",
            "WhiteBalance",
            "Flash",
            "MeteringMode",
            "ColorSpace",
            "ExifImageWidth",
            "ExifImageHeight",
        }

        for tag, value in exif_data.items():
            if tag in camera_tags:
                categories["camera_info"][tag] = value
            elif tag in datetime_tags:
                categories["datetime_info"][tag] = value
            elif tag in software_tags:
                categories["software_info"][tag] = value
            elif tag in technical_tags:
                categories["technical_info"][tag] = value
            else:
                categories["other_info"][tag] = value

        return categories

    def detect_anomalies(self, exif_data: dict[str, Any]) -> dict[str, Any]:
        flags: dict[str, Any] = {
            "missing_exif": False,
            "missing_critical_tags": [],
            "software_detected": [],
            "datetime_inconsistencies": [],
            "severity": "low",
        }

        if not exif_data:
            flags["missing_exif"] = True
            flags["severity"] = "high"
            return flags

        for tag in ["DateTime", "Make", "Model"]:
            if tag not in exif_data:
                flags["missing_critical_tags"].append(tag)

        software_tag = str(exif_data.get("Software", ""))
        keywords = ["Adobe", "Photoshop", "GIMP", "Lightroom", "Snapseed", "Affinity"]
        if any(keyword.lower() in software_tag.lower() for keyword in keywords):
            flags["software_detected"].append(software_tag)

        dt_original = exif_data.get("DateTimeOriginal")
        dt_digitized = exif_data.get("DateTimeDigitized")
        if dt_original and dt_digitized and dt_original != dt_digitized:
            flags["datetime_inconsistencies"].append(
                f"DateTimeOriginal ({dt_original}) differs from DateTimeDigitized ({dt_digitized})"
            )

        if flags["missing_critical_tags"] or flags["software_detected"]:
            flags["severity"] = "medium"
        if len(flags["missing_critical_tags"]) >= 2 and flags["software_detected"]:
            flags["severity"] = "high"

        return flags

    def summary(self) -> dict[str, Any]:
        return {
            "has_exif": bool(self.normalized_exif),
            "total_tags": len(self.normalized_exif),
            "categories": self.categories,
            "flags": self.flags,
            "report_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }


class PDF(FPDF if FPDF is not None else object):
    def __init__(self, case_id: str = "", generated_at: str = "") -> None:
        super().__init__()
        self.case_id = case_id
        self.generated_at = generated_at

    def header(self) -> None:
        self.set_fill_color(24, 33, 48)
        self.rect(0, 0, self.w, 20, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Arial", "B", 13)
        self.set_xy(10, 6)
        self.cell(0, 8, "DIFD - Fine-Tuned BusterNet Forensic Report", 0, 0, "L")
        self.set_font("Arial", "", 9)
        self.set_xy(-70, 7)
        self.cell(60, 6, f"Case: {self.case_id}", 0, 0, "R")
        self.ln(16)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.set_y(-10)
        self.set_font("Arial", "I", 8)
        self.cell(0, 5, f"Generated: {self.generated_at} | Page {self.page_no()}", 0, 0, "C")


def validate_report_inputs(user_name: str, case_id: str) -> tuple[str, str]:
    user_name = str(user_name or "").strip()
    case_id = str(case_id or "").strip()
    if not user_name:
        raise ValueError("Investigator name is required.")
    if not case_id:
        raise ValueError("Case ID is required.")
    return user_name, case_id


def _image_to_png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _mask_to_png_bytes(mask: np.ndarray) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(np.asarray(mask, dtype=np.uint8), mode="L").save(buffer, format="PNG")
    return buffer.getvalue()


def _safe_pdf_text(value: Any, max_len: int = 400) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return "-"
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _pdf_safe_multicell(pdf: PDF, line: str, line_height: int = 6) -> None:
    epw = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(epw, line_height, _safe_pdf_text(line, 600))


def _pdf_output_bytes(pdf: PDF) -> bytes:
    raw_output = pdf.output(dest="S")
    if isinstance(raw_output, str):
        return raw_output.encode("latin-1")
    if isinstance(raw_output, (bytes, bytearray)):
        return bytes(raw_output)
    raise TypeError(f"Unexpected PDF output type: {type(raw_output).__name__}")


def _pdf_section_title(pdf: PDF, title: str) -> None:
    epw = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.ln(2)
    pdf.set_fill_color(235, 240, 247)
    pdf.set_font("Arial", "B", 11)
    pdf.set_x(pdf.l_margin)
    pdf.cell(epw, 8, _safe_pdf_text(title, 120), 0, 1, "L", True)


def _pdf_kv_row(pdf: PDF, key: str, value: Any) -> None:
    epw = pdf.w - pdf.l_margin - pdf.r_margin
    key_w = 58
    val_w = epw - key_w
    pdf.set_font("Arial", "B", 9)
    pdf.set_x(pdf.l_margin)
    pdf.cell(key_w, 6, _safe_pdf_text(key, 80), 1, 0, "L")
    pdf.set_font("Arial", "", 9)
    pdf.multi_cell(val_w, 6, _safe_pdf_text(value, 240), 1, "L")


def _compute_risk_summary(
    tampered_ratio: float,
    has_exif: bool,
    software_detected: bool,
    combined_confidence: float,
) -> tuple[str, int]:
    score = min(
        100,
        int(tampered_ratio * 100.0)
        + int(combined_confidence * 0.35)
        + (12 if software_detected else 0)
        + (8 if not has_exif else 0),
    )
    if score >= 70:
        return "HIGH", score
    if score >= 35:
        return "MEDIUM", score
    return "LOW", score


def create_overlay(image: Image.Image, source_mask: np.ndarray, target_mask: np.ndarray) -> Image.Image:
    base = image.convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))

    source_alpha = Image.fromarray(np.where(source_mask > 0, 110, 0).astype(np.uint8), mode="L")
    target_alpha = Image.fromarray(np.where(target_mask > 0, 110, 0).astype(np.uint8), mode="L")

    source_fill = Image.new("RGBA", base.size, (247, 201, 72, 0))
    target_fill = Image.new("RGBA", base.size, (255, 82, 82, 0))
    source_fill.putalpha(source_alpha)
    target_fill.putalpha(target_alpha)

    overlay = Image.alpha_composite(overlay, source_fill)
    overlay = Image.alpha_composite(overlay, target_fill)
    return Image.alpha_composite(base, overlay)


def create_mask_preview(mask: np.ndarray, color: tuple[int, int, int]) -> Image.Image:
    height, width = mask.shape
    base = Image.new("RGBA", (width, height), (8, 12, 18, 255))
    overlay = Image.new("RGBA", (width, height), color + (0,))
    alpha = Image.fromarray(np.where(mask > 0, 255, 0).astype(np.uint8), mode="L")
    overlay.putalpha(alpha)
    return Image.alpha_composite(base, overlay)


def build_prediction_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "algorithm": result["algorithm"],
        "model_name": result["model_name"],
        "input_width": result["file_info"]["width"],
        "input_height": result["file_info"]["height"],
        "source_pixels": result["source_pixels"],
        "target_pixels": result["target_pixels"],
        "tampered_pixels": result["tampered_pixels"],
        "tampered_ratio": result["tampered_ratio"],
        "source_regions": result["source_regions"],
        "target_regions": result["target_regions"],
        "combined_regions": result["combined_regions"],
        "source_confidence": result["source_confidence"],
        "target_confidence": result["target_confidence"],
        "combined_confidence": result["combined_confidence"],
        "processing_time": result["processing_time"],
        "evidence_sha256": result["evidence_sha256"],
        "model_runtime": result["model_runtime"],
        "file_info": result["file_info"],
    }


def build_pdf_report(
    *,
    user_name: str,
    case_id: str,
    original_image: Image.Image,
    overlay_image: Image.Image,
    exif_metadata: dict[str, Any],
    prediction_results: dict[str, Any],
    model_runtime: dict[str, Any],
    file_info: dict[str, Any],
    processing_time: float,
    evidence_sha256: str,
) -> bytes:
    if FPDF is None:
        raise RuntimeError("fpdf package is not installed.")

    user_name, case_id = validate_report_inputs(user_name, case_id)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    software_text = str(exif_metadata.get("Software", "")).lower()
    software_detected = any(
        keyword in software_text for keyword in ["photoshop", "adobe", "gimp", "lightroom", "affinity", "snapseed"]
    )
    risk_level, risk_score = _compute_risk_summary(
        tampered_ratio=float(prediction_results["tampered_ratio"]),
        has_exif=bool(exif_metadata),
        software_detected=software_detected,
        combined_confidence=float(prediction_results["combined_confidence"]),
    )

    pdf = PDF(case_id=case_id, generated_at=generated_at)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    _pdf_section_title(pdf, "1) Executive Summary")
    _pdf_kv_row(pdf, "Risk Level", f"{risk_level} ({risk_score}/100)")
    _pdf_kv_row(pdf, "Model", prediction_results["model_name"])
    _pdf_kv_row(pdf, "Tampered Area", f"{float(prediction_results['tampered_ratio']) * 100:.2f}%")
    _pdf_kv_row(pdf, "Combined Tampered Pixels", prediction_results["tampered_pixels"])
    _pdf_kv_row(pdf, "Processing Time", f"{processing_time:.2f} sec")

    _pdf_section_title(pdf, "2) Case Information")
    _pdf_kv_row(pdf, "Investigator", user_name)
    _pdf_kv_row(pdf, "Case ID", case_id)
    _pdf_kv_row(pdf, "Generated", generated_at)
    _pdf_kv_row(pdf, "Evidence SHA-256", evidence_sha256)
    _pdf_kv_row(pdf, "File Name", file_info.get("name", "-"))
    _pdf_kv_row(pdf, "File Type", file_info.get("type", "-"))
    _pdf_kv_row(pdf, "Dimensions", f"{file_info.get('width', 0)} x {file_info.get('height', 0)}")
    _pdf_kv_row(pdf, "File Size", f"{int(file_info.get('size', 0)) / 1024:.1f} KB")

    _pdf_section_title(pdf, "3) Model And Runtime")
    _pdf_safe_multicell(
        pdf,
        "This report is generated with a self-hosted fine-tuned BusterNet model. The deployed 3-channel output is decoded as class 0 target, class 1 source, and class 2 background. The combined tamper mask uses the validation-selected forged-pixel probability threshold from the deployed fine-tuning run.",
        5,
    )
    _pdf_kv_row(pdf, "Model Name", prediction_results["model_name"])
    _pdf_kv_row(pdf, "Model Stage", model_runtime.get("model_stage", "-"))
    _pdf_kv_row(pdf, "Run Name", model_runtime.get("model_run_name", "-"))
    _pdf_kv_row(pdf, "Forged Threshold", model_runtime.get("forged_threshold", "-"))
    _pdf_kv_row(pdf, "Sidecar URL", model_runtime.get("sidecar_url", get_sidecar_url()))
    _pdf_kv_row(pdf, "Weights Path", model_runtime.get("weights_path", "-"))
    _pdf_kv_row(pdf, "Class Order", model_runtime.get("class_order", "-"))
    _pdf_kv_row(pdf, "Python Version", model_runtime.get("python_version", "-"))
    _pdf_kv_row(pdf, "Keras Version", model_runtime.get("keras_version", "-"))
    _pdf_kv_row(pdf, "TensorFlow Version", model_runtime.get("tensorflow_version", "-"))

    _pdf_section_title(pdf, "4) Evidence Visualization")
    temp_original = ""
    temp_overlay = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_original:
            temp_original = tmp_original.name
            tmp_original.write(_image_to_png_bytes(original_image))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_overlay:
            temp_overlay = tmp_overlay.name
            tmp_overlay.write(_image_to_png_bytes(overlay_image))

        epw = pdf.w - pdf.l_margin - pdf.r_margin
        half_w = (epw - 4) / 2
        image_y = pdf.get_y()
        pdf.image(temp_original, x=pdf.l_margin, y=image_y, w=half_w)
        pdf.image(temp_overlay, x=pdf.l_margin + half_w + 4, y=image_y, w=half_w)
        pdf.ln((half_w * 0.75) + 6)
    finally:
        for path in (temp_original, temp_overlay):
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError as exc:
                    LOGGER.warning("Failed to remove temporary PDF image %s: %s", path, exc)

    _pdf_section_title(pdf, "5) BusterNet Findings")
    _pdf_kv_row(pdf, "Source Pixels", prediction_results["source_pixels"])
    _pdf_kv_row(pdf, "Target Pixels", prediction_results["target_pixels"])
    _pdf_kv_row(pdf, "Combined Regions", prediction_results["combined_regions"])
    _pdf_kv_row(pdf, "Source Regions", prediction_results["source_regions"])
    _pdf_kv_row(pdf, "Target Regions", prediction_results["target_regions"])
    _pdf_kv_row(pdf, "Source Confidence", f"{float(prediction_results['source_confidence']):.2f} / 100")
    _pdf_kv_row(pdf, "Target Confidence", f"{float(prediction_results['target_confidence']):.2f} / 100")
    _pdf_kv_row(pdf, "Combined Confidence", f"{float(prediction_results['combined_confidence']):.2f} / 100")

    _pdf_section_title(pdf, "6) Metadata Summary")
    _pdf_kv_row(pdf, "EXIF Tag Count", len(exif_metadata))
    for key in ["DateTimeOriginal", "DateTime", "Make", "Model", "Software"]:
        if key in exif_metadata:
            _pdf_kv_row(pdf, f"EXIF:{key}", exif_metadata[key])

    _pdf_section_title(pdf, "7) Limitations")
    _pdf_safe_multicell(
        pdf,
        "BusterNet provides automated segmentation-based forensic indicators only. False positives and false negatives remain possible, especially under strong compression, resizing, or complex post-processing. Final conclusions require analyst review and supporting context.",
        5,
    )

    _pdf_section_title(pdf, "8) Conclusion")
    _pdf_safe_multicell(
        pdf,
        f"Automated assessment completed with {risk_level} risk indication based on the predicted source and target copy-move regions. This report is decision-support material, not a standalone legal determination.",
        5,
    )

    return _pdf_output_bytes(pdf)

_render_global_css()
_render_auth_cookie_effects()
current_user = _require_authenticated_user()

with st.sidebar:
    st.markdown(
        f"""
        <div class="section-eyebrow">Session Control</div>
        <h2 class="section-title">Authenticated Workspace</h2>
        <div class="section-copy">User: {escape(current_user['username'])} | Role: {escape(current_user['role'])}</div>
        """,
        unsafe_allow_html=True,
    )
    remaining_minutes = max(
        0,
        int((SESSION_TIMEOUT_SECONDS - (time.time() - float(current_user.get("last_activity_at", time.time())))) / 60),
    )
    st.caption(f"Inactivity timeout: {remaining_minutes} minutes remaining")
    _render_theme_selector(key_suffix="sidebar")
    if st.button("Sign Out", use_container_width=True):
        browser_token = str(current_user.get("browser_token") or _read_auth_cookie())
        revoke_browser_session(
            browser_token,
            username=current_user["username"],
            session_id=current_user.get("session_id"),
            reason="logout",
        )
        log_event(
            "logout",
            username=current_user["username"],
            success=True,
            session_id=current_user.get("session_id"),
        )
        _clear_authenticated_state()
        st.session_state.clear_auth_cookie = True
        st.rerun()

    st.markdown("---")
    st.markdown(
        """
        <div class="section-eyebrow">Runtime Monitor</div>
        <h2 class="section-title">BusterNet Sidecar</h2>
        """,
        unsafe_allow_html=True,
    )
    runtime_health = _runtime_health_snapshot()

    runtime_ready = _runtime_ready_for_prediction(runtime_health)
    if runtime_ready:
        st.success("Status: Local sidecar online and token-protected")
    elif runtime_health.get("loaded"):
        st.error("Status: Sidecar online, but BUSTERNET_TOKEN is not configured.")
    elif runtime_health.get("available"):
        st.error("Status: Sidecar is reachable, but the model is not ready.")
    else:
        st.warning("Status: BusterNet sidecar is offline.")

    st.caption(f"URL: {get_sidecar_url()}")
    if runtime_health.get("token_required", is_sidecar_token_required()):
        token_text = "configured" if runtime_health.get("token_configured", is_sidecar_token_configured()) else "missing"
        st.caption(f"Prediction token: required and {token_text}")
    if runtime_health.get("loaded"):
        st.metric("Model", runtime_health.get("model_name", "Fine-tuned BusterNet"))
        if runtime_health.get("model_run_name"):
            st.caption(f"Run: {runtime_health.get('model_run_name')}")
        if runtime_health.get("forged_threshold") is not None:
            st.caption(f"Forged threshold: {runtime_health.get('forged_threshold')}")
        st.caption(
            f"Python {runtime_health.get('python_version', '-')}"
            f" | Keras {runtime_health.get('keras_version', '-')}"
            f" | TensorFlow {runtime_health.get('tensorflow_version', '-')}"
        )
    else:
        st.caption(f"Sidecar files: {SIDECAR_DIR}")
        st.caption("Start the legacy runtime sidecar before running analysis.")

    if not runtime_ready:
        sidecar_issue = runtime_health.get("error") or "BusterNet sidecar unavailable or model not loaded."
        if runtime_health.get("loaded"):
            sidecar_issue = "BUSTERNET_TOKEN is required before prediction requests are allowed."
        if st.session_state.get("last_sidecar_issue") != sidecar_issue:
            _audit("sidecar_health_failure", success=False, message=str(sidecar_issue))
            st.session_state.last_sidecar_issue = sidecar_issue
    else:
        st.session_state.last_sidecar_issue = ""

    st.markdown("---")


runtime_label, runtime_tone = _runtime_status_label(runtime_health)
system_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
st.markdown(
    f"""
    <div class="app-shell">
        <div class="app-kicker">Forensic Analysis Workspace</div>
        <h1 class="app-title">DIFD Fine-Tuned BusterNet Copy-Move Analysis</h1>
        <div class="app-subtitle">Self-hosted fine-tuned BusterNet inference with source and target localization for evidence review, metadata inspection, and exportable reporting.</div>
        <div class="policy-grid">
            {_policy_card_markup("Authenticated User", f"{current_user['username']} ({current_user['role']})")}
            {_policy_card_markup("Runtime Status", runtime_label, tone=runtime_tone)}
            {_policy_card_markup("UTC Snapshot", system_time)}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
theme_spacer, theme_control, logout_control = st.columns([0.62, 0.19, 0.19])
with theme_control:
    st.markdown('<div class="section-eyebrow">Display Theme</div>', unsafe_allow_html=True)
    _render_theme_selector(key_suffix="workspace")
with logout_control:
    st.markdown('<div class="section-eyebrow">Session</div>', unsafe_allow_html=True)
    if st.button("Sign Out", key="main_logout_button", help="End your session", use_container_width=True):
        browser_token = str(current_user.get("browser_token") or _read_auth_cookie())
        revoke_browser_session(browser_token, username=current_user["username"], session_id=current_user.get("session_id"), reason="logout")
        log_event("logout", username=current_user["username"], success=True, session_id=current_user.get("session_id"))
        _clear_authenticated_state()
        st.session_state.clear_auth_cookie = True
        st.rerun()
st.markdown("---")


if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0
if "analysis" not in st.session_state:
    st.session_state.analysis = {}
if "report_pdf_bytes" not in st.session_state:
    st.session_state.report_pdf_bytes = b""


tab_labels = ["BusterNet Lab", "Metadata Analysis", "Final Report"]
is_admin = current_user.get("role") == "admin"
if is_admin:
    tab1, tab2, tab3, tab4 = st.tabs([*tab_labels, "Security Admin"])
else:
    tab1, tab2, tab3 = st.tabs(tab_labels)
    tab4 = None


with tab1:
    st.markdown(
        """
        <div class="section-eyebrow">Evidence Intake</div>
        <h2 class="section-title">BusterNet Lab</h2>
        <div class="section-copy">Upload a PNG, JPEG, BMP, or TIFF evidence image to run the local copy-move analysis workflow and generate masks, metadata summaries, and a final report.</div>
        """,
        unsafe_allow_html=True,
    )
    uploaded_file = st.file_uploader(
        "Upload image (PNG, JPEG, BMP, TIFF)",
        type=["png", "jpg", "jpeg", "bmp", "tif", "tiff"],
        key=f"uploader_{st.session_state.uploader_key}",
    )

    if uploaded_file and st.button("Remove Uploaded Image"):
        _audit("upload_removed", success=True, message=str(uploaded_file.name))
        _clear_case_state()
        st.rerun()

    if not uploaded_file:
        _render_empty_state(
            "Upload an image to start",
            "Choose a PNG, JPEG, BMP, or TIFF file. The app validates the file before analysis.",
        )

    if uploaded_file:
        try:
            file_bytes, original_image, image = _validate_uploaded_image(uploaded_file)
        except Exception as exc:
            LOGGER.warning("Upload validation failed for %s: %s", uploaded_file.name, exc)
            _audit("upload_rejected", success=False, message=f"{uploaded_file.name}: {exc}")
            st.error("This image cannot be used. Upload a PNG, JPEG, BMP, or TIFF file under the size limit.")
            st.info("If the file is very large, resize it and try again.")
            st.stop()

        evidence_hash = sha256(file_bytes).hexdigest()
        if st.session_state.get("last_upload_hash") != evidence_hash:
            _audit(
                "upload_accepted",
                success=True,
                message=f"{uploaded_file.name}; size={uploaded_file.size}; sha256={evidence_hash}",
            )
            st.session_state.last_upload_hash = evidence_hash
        if st.session_state.analysis and st.session_state.analysis.get("evidence_sha256") != evidence_hash:
            st.session_state.analysis = {}
            st.session_state.report_pdf_bytes = b""

        c1, c2 = st.columns([0.64, 0.36])

        with c1:
            st.image(image, caption="Original Evidence Image", use_container_width=True)
            runtime_ready = _runtime_ready_for_prediction(runtime_health)
            if not runtime_health.get("loaded"):
                st.warning("Status: BusterNet runtime is offline. Start the local sidecar to enable image analysis.")
            elif not runtime_ready:
                st.error("Status: BusterNet runtime needs BUSTERNET_TOKEN before analysis is allowed.")

            if st.button(
                "Analyze Image",
                key="start_busternet_btn",
                disabled=not runtime_ready,
            ):
                try:
                    with st.spinner("Analyzing image with fine-tuned BusterNet..."):
                        _audit("analysis_start", success=True, message=f"{uploaded_file.name}; sha256={evidence_hash}")
                        start_time = time.time()
                        prediction = detect_copy_move(
                            file_bytes,
                            filename=uploaded_file.name,
                            content_type=uploaded_file.type or "application/octet-stream",
                        )
                        overlay = create_overlay(image, prediction["source_mask"], prediction["target_mask"])
                        exif_analyzer = ExifAnalyzer(original_image)
                        elapsed = time.time() - start_time

                        st.session_state.report_pdf_bytes = b""
                        st.session_state.analysis = {
                            "image": image,
                            "overlay": overlay,
                            "algorithm": prediction["algorithm"],
                            "model_name": prediction["model_name"],
                            "source_mask": prediction["source_mask"],
                            "target_mask": prediction["target_mask"],
                            "combined_mask": prediction["combined_mask"],
                            "source_pixels": prediction["source_pixels"],
                            "target_pixels": prediction["target_pixels"],
                            "tampered_pixels": prediction["tampered_pixels"],
                            "tampered_ratio": prediction["tampered_ratio"],
                            "source_regions": prediction["source_regions"],
                            "target_regions": prediction["target_regions"],
                            "combined_regions": prediction["combined_regions"],
                            "source_confidence": prediction["source_confidence"],
                            "target_confidence": prediction["target_confidence"],
                            "combined_confidence": prediction["combined_confidence"],
                            "processing_time": elapsed,
                            "runtime_seconds": prediction["runtime_seconds"],
                            "evidence_sha256": evidence_hash,
                            "exif_analyzer": exif_analyzer,
                            "model_runtime": prediction["model_runtime"],
                            "file_info": {
                                "name": uploaded_file.name,
                                "type": uploaded_file.type,
                                "size": uploaded_file.size,
                                "width": image.width,
                                "height": image.height,
                            },
                        }
                        _audit(
                            "analysis_complete",
                            success=True,
                            message=f"{uploaded_file.name}; tampered_ratio={prediction['tampered_ratio']}",
                        )
                    st.rerun()
                except BusterNetClientError as exc:
                    LOGGER.warning("BusterNet analysis failed: %s", exc)
                    _audit("analysis_failure", success=False, message=str(exc))
                    st.error(f"Analysis failed: {exc}")
                    st.info("Ensure the sidecar is running and BUSTERNET_TOKEN is correctly set.")

        with c2:
            st.markdown(
                """
                <div class="section-eyebrow">Evidence Snapshot</div>
                <h2 class="section-title">Quick Stats</h2>
                """,
                unsafe_allow_html=True,
            )
            st.metric("Runtime", "Ready" if _runtime_ready_for_prediction(runtime_health) else "Not Ready")
            st.metric("File Type", (uploaded_file.type or "unknown").split("/")[-1].upper())
            st.metric("Dimensions", f"{image.width} x {image.height}")
            st.metric("File Size", f"{uploaded_file.size / 1024:.1f} KB")
            if runtime_health.get("loaded"):
                st.caption(f"Model: {runtime_health.get('model_name', 'Fine-tuned BusterNet')}")
                if runtime_health.get("model_run_name"):
                    st.caption(f"Run: {runtime_health.get('model_run_name')}")
                if runtime_health.get("forged_threshold") is not None:
                    st.caption(f"Forged threshold: {runtime_health.get('forged_threshold')}")
                st.caption(
                    f"Python {runtime_health.get('python_version', '-')}"
                    f" | Keras {runtime_health.get('keras_version', '-')}"
                    f" | TensorFlow {runtime_health.get('tensorflow_version', '-')}"
                )
            else:
                st.caption("Start the local BusterNet sidecar in its Python 3.6 runtime to enable analysis.")

        if st.session_state.analysis:
            result = st.session_state.analysis
            tampered_percent = float(result["tampered_ratio"]) * 100.0
            verdict = "FORGED" if result["tampered_pixels"] > 0 else "NO FORGERY DETECTED"
            confidence = float(result["combined_confidence"])

            if result["tampered_pixels"] > 0:
                st.error(f"### {verdict} ({confidence:.2f}% Confidence)")
                st.info(
                    f"BusterNet localized {result['combined_regions']} tampered region(s) covering "
                    f"{tampered_percent:.2f}% of the image in {result['processing_time']:.2f} seconds."
                )
                if result["target_pixels"] > 0 and result["source_pixels"] == 0:
                    st.warning(
                        "**Forensic Note:** Manipulation artifacts (Target) were detected without a matching "
                        "Source region. This often occurs when the model identifies 'pasted' characteristics "
                        "but cannot clearly isolate the original source area."
                    )
            else:
                st.success(f"### {verdict} ({confidence:.2f}% Confidence)")
                st.info("BusterNet did not localize a copy-move region in this image.")

            row1 = st.columns(4)
            row1[0].metric("Tampered Area", f"{tampered_percent:.2f}%")
            row1[1].metric("Source Pixels", f"{result['source_pixels']:,}")
            row1[2].metric("Target Pixels", f"{result['target_pixels']:,}")
            row1[3].metric("Combined Regions", f"{result['combined_regions']:,}")

            row2 = st.columns(4)
            row2[0].metric("Source Confidence", f"{result['source_confidence']:.2f}/100")
            row2[1].metric("Target Confidence", f"{result['target_confidence']:.2f}/100")
            row2[2].metric("Combined Confidence", f"{result['combined_confidence']:.2f}/100")
            row2[3].metric("Runtime", f"{result['runtime_seconds']:.2f} sec")

            st.caption(
                f"Model runtime: {result['model_runtime'].get('python_version', '-')}"
                f" / Keras {result['model_runtime'].get('keras_version', '-')}"
                f" / TensorFlow {result['model_runtime'].get('tensorflow_version', '-')}"
            )
            if result["model_runtime"].get("model_run_name"):
                st.caption(
                    f"Fine-tuned run: {result['model_runtime'].get('model_run_name')}"
                    f" | threshold {result['model_runtime'].get('forged_threshold', '-')}"
                )

            preview_cols = st.columns(2)
            with preview_cols[0]:
                st.image(
                    result["overlay"],
                    caption="Overlay: yellow = source region, red = target region",
                    use_container_width=True,
                )
            with preview_cols[1]:
                st.image(
                    create_mask_preview(result["combined_mask"], (255, 82, 82)),
                    caption="Combined Tamper Mask",
                    use_container_width=True,
                )

            detail_cols = st.columns(2)
            with detail_cols[0]:
                st.image(
                    create_mask_preview(result["source_mask"], (247, 201, 72)),
                    caption="Source Mask",
                    use_container_width=True,
                )
            with detail_cols[1]:
                st.image(
                    create_mask_preview(result["target_mask"], (255, 82, 82)),
                    caption="Target Mask",
                    use_container_width=True,
                )

            summary_payload = build_prediction_summary(result)

            export_cols = st.columns(6)
            with export_cols[0]:
                if st.download_button(
                    "Overlay PNG",
                    data=_image_to_png_bytes(result["overlay"]),
                    file_name="overlay.png",
                    mime="image/png",
                    key="download_overlay_png",
                ):
                    _audit("export_download", success=True, message="overlay.png")
            with export_cols[1]:
                if st.download_button(
                    "Combined Mask",
                    data=_mask_to_png_bytes(result["combined_mask"]),
                    file_name="combined_mask.png",
                    mime="image/png",
                    key="download_combined_mask",
                ):
                    _audit("export_download", success=True, message="combined_mask.png")
            with export_cols[2]:
                if st.download_button(
                    "Source Mask",
                    data=_mask_to_png_bytes(result["source_mask"]),
                    file_name="source_mask.png",
                    mime="image/png",
                    key="download_source_mask",
                ):
                    _audit("export_download", success=True, message="source_mask.png")
            with export_cols[3]:
                if st.download_button(
                    "Target Mask",
                    data=_mask_to_png_bytes(result["target_mask"]),
                    file_name="target_mask.png",
                    mime="image/png",
                    key="download_target_mask",
                ):
                    _audit("export_download", success=True, message="target_mask.png")
            with export_cols[4]:
                if st.download_button(
                    "Prediction JSON",
                    data=json.dumps(summary_payload, indent=2, default=str),
                    file_name="prediction_summary.json",
                    mime="application/json",
                    key="download_prediction_json",
                ):
                    _audit("export_download", success=True, message="prediction_summary.json")
            with export_cols[5]:
                if st.download_button(
                    "EXIF JSON",
                    data=json.dumps(result["exif_analyzer"].normalized_exif, indent=2, default=str),
                    file_name="exif_data.json",
                    mime="application/json",
                    key="download_exif_json",
                ):
                    _audit("export_download", success=True, message="exif_data.json")
with tab2:
    st.markdown(
        """
        <div class="section-eyebrow">Metadata Review</div>
        <h2 class="section-title">Metadata Analysis</h2>
        <div class="section-copy">Review EXIF availability, software traces, timestamps, and anomaly flags generated from the uploaded evidence image.</div>
        """,
        unsafe_allow_html=True,
    )
    if not st.session_state.analysis:
        _render_empty_state(
            "Run analysis to review metadata",
            "Upload an image and analyze it first. Metadata findings will appear here.",
        )
    else:
        result = st.session_state.analysis
        analyzer: ExifAnalyzer = result["exif_analyzer"]
        summary = analyzer.summary()

        top_metrics = st.columns(4)
        top_metrics[0].metric("Has EXIF", "Yes" if summary["has_exif"] else "No")
        top_metrics[1].metric("EXIF Tags", summary["total_tags"])
        top_metrics[2].metric("Flag Severity", analyzer.flags.get("severity", "low").upper())
        top_metrics[3].metric("Software Entries", len(analyzer.flags.get("software_detected", [])))

        st.markdown('<h3 class="section-title">File Summary</h3>', unsafe_allow_html=True)
        st.json(result["file_info"])

        if not analyzer.normalized_exif:
            _render_empty_state(
                "No EXIF metadata found",
                "This image does not include readable EXIF data. You can still use the visual analysis result.",
            )
        else:
            st.markdown('<h3 class="section-title">EXIF Categories</h3>', unsafe_allow_html=True)
            for title, values in analyzer.categories.items():
                if values:
                    st.markdown(f'<div class="section-eyebrow">{escape(title.replace("_", " ").title())}</div>', unsafe_allow_html=True)
                    st.json(values)

        st.markdown('<h3 class="section-title">Metadata Flags</h3>', unsafe_allow_html=True)
        st.json(analyzer.flags)
with tab3:
    st.markdown(
        """
        <div class="section-eyebrow">Export Builder</div>
        <h2 class="section-title">Final Report</h2>
        <div class="section-copy">Prepare the case metadata and generate a PDF report containing the evidence snapshot, masks, runtime details, and EXIF findings.</div>
        """,
        unsafe_allow_html=True,
    )
    if not st.session_state.analysis:
        st.markdown("**Status:** <span class='status-pill status-pill-warn'>Analysis required</span>", unsafe_allow_html=True)
        _render_empty_state(
            "Create a report after analysis",
            "Analyze an image first. The report will include masks, metadata, runtime details, and the evidence hash.",
        )
    else:
        st.markdown("**Status:** <span class='status-pill'>Ready for export</span>", unsafe_allow_html=True)
        result = st.session_state.analysis
        default_case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        investigator_name = st.text_input("Investigator Name", key="investigator_name")
        case_id = st.text_input("Case ID", value=default_case_id, key="case_id")
        generate_clicked = st.button("Create PDF Report", key="generate_pdf_btn")

        if generate_clicked:
            if not investigator_name.strip():
                st.warning("Enter the investigator name to create the report.")
            elif not case_id.strip():
                st.warning("Enter a case ID to create the report.")
            else:
                try:
                    pdf_bytes = build_pdf_report(
                        user_name=investigator_name,
                        case_id=case_id,
                        original_image=result["image"],
                        overlay_image=result["overlay"],
                        exif_metadata=result["exif_analyzer"].normalized_exif,
                        prediction_results=build_prediction_summary(result),
                        model_runtime=result["model_runtime"],
                        file_info=result["file_info"],
                        processing_time=result["processing_time"],
                        evidence_sha256=result["evidence_sha256"],
                    )
                    st.session_state.report_pdf_bytes = pdf_bytes
                    _audit("report_generated", success=True, message=f"case_id={case_id}")
                    st.success("PDF report created. You can download it now.")
                except Exception as exc:
                    LOGGER.exception("PDF report generation failed.")
                    st.session_state.report_pdf_bytes = b""
                    _audit("report_generation_failure", success=False, message=str(exc))
                    st.warning("The report could not be created. Check the report fields and try again.")

        if st.session_state.report_pdf_bytes:
            safe_case_id = (case_id.strip() or "case").replace(" ", "_")
            if st.download_button(
                "Download Report",
                data=st.session_state.report_pdf_bytes,
                file_name=f"busternet_report_{safe_case_id}.pdf",
                mime="application/pdf",
                key="download_pdf_btn",
                use_container_width=True,
            ):
                _audit("export_download", success=True, message=f"busternet_report_{safe_case_id}.pdf")

if tab4 is not None:
    with tab4:
        _render_admin_panel(current_user)
