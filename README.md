# DIFD — Digital Image Forgery Detector

DIFD is a Streamlit web application for copy-move forgery detection and pixel-level localization. It drives a self-hosted, fine-tuned BusterNet inference sidecar and wraps it with an authenticated multi-user frontend, local audit logging, and session management.

The project is NIST-aligned for local academic and team-hosted deployment. It does not claim formal NIST RMF authorization or production certification. Security controls, assumptions, and accepted risks are documented in [`SECURITY_POLICY.md`](./SECURITY_POLICY.md). Evidence from local security self-checks and dependency audits is recorded in [`SECURITY_TEST_REPORT.md`](./SECURITY_TEST_REPORT.md).

---

## Table of Contents

1. [Requirements](#requirements)
2. [Main App Setup](#main-app-setup)
3. [BusterNet Sidecar Setup](#busternet-sidecar-setup)
4. [Sidecar Token](#sidecar-token)
5. [HTTPS](#https)
6. [Account Management](#account-management)
7. [Auth Database Recovery](#auth-database-recovery)
8. [Security Summary](#security-summary)

---

## Requirements

- Windows host
- Python 3.12 for the Streamlit app
- Python 3.6.8 x64 exclusively for the `busternet_sidecar` environment
- Local port `7861` available for the sidecar
- Local port `8501` available for the Streamlit app (configurable)

---

## Main App Setup

From the project root, create and activate the virtual environment, then install dependencies:

```powershell
py -3.12 -m venv .venv-app
.\.venv-app\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```

Create the first admin account. No users may exist before this step runs:

```powershell
python .\bootstrap_admin.py --username admin
```

The password is prompted interactively. Do not pass it on the command line. The minimum length for new and reset passwords is 15 characters by default (NIST SP 800-63B).

After the first admin is created, `security\install_state.json` seals the installation. If `security\auth.db` is later deleted or made unreadable, the app refuses normal operation and shows a recovery screen. See [Auth Database Recovery](#auth-database-recovery).

The sidecar token is created automatically by the launcher. To create it manually:

```powershell
python .\tools\sidecar_token.py
```

Start the app over plain HTTP (local development only):

```powershell
python .\run_app.py
```

Start the app over local HTTPS:

```powershell
python .\run_app_https.py
```

The HTTPS launcher generates a self-signed localhost certificate at `security\local_tls\localhost.crt` and a private key at `security\local_tls\localhost.key`. Both are host-local and excluded from source control.

If port `8501` is already in use:

```powershell
$env:DIFD_STREAMLIT_PORT = "8502"
python .\run_app_https.py
```

---

## BusterNet Sidecar Setup

The sidecar must run in its own Python 3.6 virtual environment, separate from the main app:

```powershell
cd .\busternet_sidecar
.\bootstrap_legacy_env.ps1 -PythonExe C:\Path\To\Python36\python.exe
.\start_sidecar.ps1
```

Verify the sidecar is loaded before submitting analysis requests:

```powershell
Invoke-WebRequest http://127.0.0.1:7861/health | Select-Object -Expand Content
```

The response should include `"loaded": true`. The active checkpoint path and forged-pixel threshold are also reported in `/health`.

The default deployed checkpoint is:
`busternet_sidecar\finetuned_model\production_weights_best.hd5`

The sidecar binds to `127.0.0.1` only and must not be exposed to the network. See [`SECURITY_POLICY.md`](./SECURITY_POLICY.md) for the rationale and compensating controls around the legacy runtime.

---

## Sidecar Token

The `/predict` endpoint requires a shared local token by default (NIST SP 800-53 SC-7, SC-8). The app and sidecar launchers automatically create and read this token from `security\sidecar_token` when `BUSTERNET_TOKEN` is not already set in the environment.

To set the token manually:

```powershell
$env:BUSTERNET_TOKEN = "replace-with-a-long-random-token"
```

When active, the Streamlit app sends `X-BusterNet-Token` on every prediction call. Requests without a valid token are rejected by the sidecar.

The token file is host-local and excluded from source control. Do not disable token enforcement on shared hosts. For isolated classroom debugging only:

```powershell
$env:DIFD_REQUIRE_SIDECAR_TOKEN = "0"
```

---

## HTTPS

Use `run_app_https.py` for local HTTPS testing at `https://localhost:8501`. The browser will warn that the certificate is self-signed until it is explicitly trusted on the host.

Optional trust step for local Windows development:

```powershell
Import-Certificate -FilePath .\security\local_tls\localhost.crt -CertStoreLocation Cert:\CurrentUser\Root
```

Only trust certificates you generated on your own machine.

For professional or multi-user deployment, replace the self-signed certificate with an organization-managed certificate, or place Streamlit behind an HTTPS reverse proxy. The BusterNet sidecar must remain bound to `127.0.0.1` and must not be placed behind a public-facing proxy. See [`SECURITY_POLICY.md — Transport Security`](./SECURITY_POLICY.md) for the full boundary rationale.

---

## Account Management

- Login is required before upload, analysis, metadata review, and report export.
- New and reset passwords require at least 15 characters (NIST SP 800-63B).
- Common passwords are blocked. Account lockout is enforced after repeated failed attempts.
- Session timeout is enforced for idle sessions.
- Admin users manage accounts from the `Security Admin` tab. Analyst-role users cannot access or view the admin surface (NIST SP 800-53 AC-2).
- Raw passwords, uploaded image bytes, and model outputs are never stored in the auth database.
- All account lifecycle events are logged locally to `security\security_events.jsonl` (NIST SP 800-53 AU-2, AU-6).

---

## Auth Database Recovery

If `security\auth.db` is deleted, emptied, or becomes unreadable after initial setup, the app blocks normal operation and presents a recovery screen.

*Ensure your `.venv-app` is activated before running these commands.*

List available backups:

```powershell
python .\restore_auth_backup.py --list
```

Restore from a trusted backup:

```powershell
python .\restore_auth_backup.py --backup <backup.db> --confirm RESTORE_AUTH_DB
```

Do not delete `security\install_state.json` to bypass recovery. If both the auth database and the install seal are removed, treat the host as compromised or as a deliberate rebuild from scratch.

Preserve `security\security_events.jsonl` and auth DB backups if you need incident evidence.

---

## Security Summary

| Area | Status |
|------|--------|
| Authentication required for all app functions | Yes |
| Password minimum length (new/reset) | 15 characters |
| Common-password blocking | Yes |
| Account lockout | Yes |
| Session timeout | Yes |
| Sidecar token enforcement | Yes (default) |
| Sidecar network binding | `127.0.0.1` only |
| HTTPS for local testing | `run_app_https.py` |
| HTTPS for production | Required — see `SECURITY_POLICY.md` |
| Dependency audit — main app | 0 known vulnerabilities |
| Dependency audit — sidecar | 594 known vulnerabilities (accepted legacy risk) |
| NIST alignment | CSF 2.0, SP 800-63B, SP 800-53 Rev. 5, SP 800-218 |
| Formal NIST authorization | Not claimed |

### Legacy Runtime Risk

The legacy BusterNet sidecar runs Python 3.6.x, TensorFlow 1.8.0, and Keras 2.2.2. These versions carry 594 known CVEs across six pinned packages. This risk is accepted for local academic use only under the compensating controls described in [`SECURITY_POLICY.md`](./SECURITY_POLICY.md).

### Documentation References

Full security control mapping, account lifecycle rules, recovery procedures, transport security rationale, and host-compromise limits are in [`SECURITY_POLICY.md`](./SECURITY_POLICY.md).

Local self-check results, dependency audit output, and accepted risk statements are in [`SECURITY_TEST_REPORT.md`](./SECURITY_TEST_REPORT.md).

### Sensitive File Exclusion

Do not include `security\auth.db`, `security\sidecar_token`, `security\install_state.json`, or `security\local_tls\` in shared archives or public repositories. These paths are excluded from source control.