# DIFD Security Test Report

Date: 2026-05-09

Scope: local Streamlit app, SQLite auth layer, BusterNet sidecar client/server contract, pinned runtime dependencies, and deployment documentation.

## Summary

This project is NIST-aligned for local academic deployment. It is not a formal NIST authorization package. The modern Streamlit app dependency set currently has no known vulnerabilities reported by `pip-audit`; the legacy BusterNet sidecar has known vulnerabilities because it intentionally preserves Python 3.6-era TensorFlow/Keras compatibility for the official model.

## Local Control Self-Check

Command:

```powershell
python .\tools\security_self_check.py
```

Result: PASS, 0 failed checks.

Covered checks:

| NIST area | Check | Result |
| --- | --- | --- |
| IA-5 | New/reset passwords require at least 15 characters by default. | PASS |
| IA-5 | Password policy does not depend on letter/number composition rules. | PASS |
| SC-7 / SC-8 | Sidecar prediction token is required by default. | PASS |
| SC-7 / SC-8 | App and sidecar launchers share an automatic host-local token. | PASS |
| SC-7 | Sidecar host defaults to `127.0.0.1`. | PASS |
| SA-12 / SR-4 | Main app dependencies are pinned exactly. | PASS |
| SA-12 / SR-4 | Legacy sidecar dependencies are pinned exactly. | PASS |
| SC-28 / MP-6 | Local secrets, auth DB, backups, install seal, and logs are excluded from source control. | PASS |
| SC-8 | HTTPS requirement for professional deployment is documented. | PASS |
| SC-8 | Local HTTPS launcher configures Streamlit TLS with a generated localhost certificate. | PASS |
| SC-12 / SC-28 | Local TLS private key directory is excluded from source control. | PASS |

## Dependency Audit

Commands:

```powershell
python -m pip_audit -r .\requirements.txt -f json -o .\security_reports\pip-audit-app.json
python -m pip_audit -r .\busternet_sidecar\requirements-legacy.txt --no-deps --disable-pip --timeout 60 -f json -o .\security_reports\pip-audit-legacy-sidecar.json
```

Results:

| Dependency set | Result | Evidence file |
| --- | --- | --- |
| Main Streamlit app | 0 known vulnerabilities found after adding the HTTPS certificate generator dependency. | `security_reports/pip-audit-app.json` |
| Legacy BusterNet sidecar | 594 known vulnerabilities across 6 pinned packages. | `security_reports/pip-audit-legacy-sidecar.json` |

## Local HTTPS Test

Commands:

```powershell
python .\tools\create_local_https_cert.py
python .\run_app_https.py
```

Expected result:

- The app serves over `https://localhost:8501`.
- The certificate is stored at `security/local_tls/localhost.crt`.
- The private key is stored at `security/local_tls/localhost.key`.
- The generated key material is excluded from source control.

Browser note: a warning is expected until the self-signed certificate is trusted on the host. For local Windows development, trust only your own generated certificate:

```powershell
Import-Certificate -FilePath .\security\local_tls\localhost.crt -CertStoreLocation Cert:\CurrentUser\Root
```

Legacy sidecar vulnerable packages reported:

| Package | Version | Vulnerability count |
| --- | ---: | ---: |
| numpy | 1.14.5 | 5 |
| Pillow | 8.4.0 | 13 |
| scipy | 1.1.0 | 2 |
| protobuf | 3.19.6 | 2 |
| Keras | 2.2.2 | 5 |
| tensorflow | 1.8.0 | 567 |

## Accepted Legacy Runtime Risk

The sidecar risk is accepted only for local academic use because the official BusterNet model depends on legacy TensorFlow/Keras behavior. Compensating controls are:

- The sidecar runs in a separate Python 3.6 environment.
- The sidecar binds to `127.0.0.1` by default.
- `/predict` requires `BUSTERNET_TOKEN` by default.
- App and sidecar launchers create/read `security/sidecar_token` automatically when `BUSTERNET_TOKEN` is not set.
- The Streamlit app validates file type, size, pixel count, and image parsing before forwarding data.
- The sidecar is not exposed to the internet.
- Professional deployment must modernize or container-isolate the model runtime before claiming production compliance.

The sidecar remains HTTP on loopback by design. HTTPS is terminated at the Streamlit web boundary; the sidecar is not browser-facing and must remain bound to `127.0.0.1`.

## Remaining Gaps

- No formal NIST RMF authorization, control assessment, or continuous monitoring program exists.
- No MFA or external identity provider is implemented.
- Audit logs are local and not tamper-resistant against a host administrator.
- HTTPS is documented as required for professional deployment but not enabled by the default localhost command.
- The legacy ML runtime remains the largest security risk.
