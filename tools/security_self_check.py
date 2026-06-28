from __future__ import annotations

import ast
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _requirements_are_pinned(path: str) -> bool:
    text = _read(path)
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return bool(lines) and all("==" in line and not line.startswith("-") for line in lines)


def _literal_int_from_assignment(path: str, name: str) -> int | None:
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            continue
        call = node.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "int"
            and call.args
            and isinstance(call.args[0], ast.Call)
            and isinstance(call.args[0].func, ast.Attribute)
            and call.args[0].func.attr == "getenv"
            and len(call.args[0].args) >= 2
            and isinstance(call.args[0].args[1], ast.Constant)
        ):
            return int(call.args[0].args[1].value)
    return None


def run_checks() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    min_password = _literal_int_from_assignment("security_auth.py", "MIN_PASSWORD_LENGTH")
    checks.append(
        {
            "control": "IA-5",
            "check": "New/reset password minimum length is at least 15 characters",
            "status": "PASS" if min_password is not None and min_password >= 15 else "FAIL",
            "evidence": f"MIN_PASSWORD_LENGTH default={min_password}",
        }
    )

    auth_text = _read("security_auth.py")
    composition_removed = "Password must include both letters and numbers" not in auth_text
    checks.append(
        {
            "control": "IA-5",
            "check": "Password policy avoids composition-rule dependency",
            "status": "PASS" if composition_removed else "FAIL",
            "evidence": "No letter+number-only composition error remains.",
        }
    )

    pipeline_text = _read("cmfd_pipeline.py")
    sidecar_text = _read("busternet_sidecar/sidecar_server.py")
    token_required = (
        'DIFD_REQUIRE_SIDECAR_TOKEN", "1"' in pipeline_text
        and 'DIFD_REQUIRE_SIDECAR_TOKEN", "1"' in sidecar_text
        and "BUSTERNET_TOKEN" in pipeline_text
        and "BUSTERNET_TOKEN" in sidecar_text
    )
    checks.append(
        {
            "control": "SC-7 / SC-8",
            "check": "Sidecar prediction token is required by default",
            "status": "PASS" if token_required else "FAIL",
            "evidence": "DIFD_REQUIRE_SIDECAR_TOKEN defaults to 1 in app client and sidecar.",
        }
    )

    host_local = 'BUSTERNET_HOST", "127.0.0.1"' in sidecar_text
    checks.append(
        {
            "control": "SC-7",
            "check": "Sidecar host defaults to localhost",
            "status": "PASS" if host_local else "FAIL",
            "evidence": "BUSTERNET_HOST default is 127.0.0.1.",
        }
    )

    for req in ["requirements.txt", "busternet_sidecar/requirements-legacy.txt"]:
        checks.append(
            {
                "control": "SA-12 / SR-4",
                "check": f"{req} has exact pinned dependencies",
                "status": "PASS" if _requirements_are_pinned(req) else "FAIL",
                "evidence": "Every active requirement line uses ==.",
            }
        )

    gitignore = _read(".gitignore")
    ignored = all(
        pattern in gitignore
        for pattern in [
            "security/*.db",
            "security/backups/",
            "security/install_state.json",
            "security/security_events.jsonl",
            "security/sidecar_token",
            ".env",
            ".streamlit/secrets.toml",
        ]
    )
    checks.append(
        {
            "control": "SC-28 / MP-6",
            "check": "Host-local secrets and auth artifacts are excluded from source control",
            "status": "PASS" if ignored else "FAIL",
            "evidence": ".gitignore includes auth DB, backups, install seal, logs, .env, and secrets.",
        }
    )

    token_helpers = (
        (ROOT / "tools" / "sidecar_token.py").exists()
        and "export_sidecar_token_env" in _read("run_app.py")
        and "export_sidecar_token_env" in _read("run_app_https.py")
        and "security\\sidecar_token" in _read("busternet_sidecar/start_sidecar.ps1")
    )
    checks.append(
        {
            "control": "SC-7 / SC-8",
            "check": "App and sidecar launchers share an automatic host-local token",
            "status": "PASS" if token_helpers else "FAIL",
            "evidence": "Launchers create/read security/sidecar_token when BUSTERNET_TOKEN is not set.",
        }
    )

    docs_text = _read("SECURITY_POLICY.md") + "\n" + _read("README.md")
    https_documented = bool(re.search(r"HTTPS", docs_text, re.IGNORECASE))
    checks.append(
        {
            "control": "SC-8",
            "check": "HTTPS deployment requirement is documented",
            "status": "PASS" if https_documented else "FAIL",
            "evidence": "README.md and SECURITY_POLICY.md describe HTTPS for professional deployment.",
        }
    )

    https_launcher = _read("run_app_https.py")
    cert_script_exists = (ROOT / "tools" / "create_local_https_cert.py").exists()
    launcher_uses_tls = "--server.sslCertFile" in https_launcher and "--server.sslKeyFile" in https_launcher
    checks.append(
        {
            "control": "SC-8",
            "check": "Local HTTPS launcher configures Streamlit TLS",
            "status": "PASS" if cert_script_exists and launcher_uses_tls else "FAIL",
            "evidence": "run_app_https.py uses a generated localhost cert and key.",
        }
    )

    gitignore = _read(".gitignore")
    tls_ignored = "security/local_tls/" in gitignore
    checks.append(
        {
            "control": "SC-12 / SC-28",
            "check": "Local TLS private key directory is excluded from source control",
            "status": "PASS" if tls_ignored else "FAIL",
            "evidence": ".gitignore contains security/local_tls/.",
        }
    )

    return checks


def main() -> None:
    checks = run_checks()
    failures = [check for check in checks if check["status"] != "PASS"]
    print(json.dumps({"checks": checks, "failure_count": len(failures)}, indent=2))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
