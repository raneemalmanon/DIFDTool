# DIFD Security Policy

This project is NIST-aligned for a local or team-hosted graduation project. It does not claim formal production certification or full NIST compliance.

## Applicable Guidance

- NIST Cybersecurity Framework 2.0: used to structure risk outcomes across Govern, Identify, Protect, Detect, Respond, and Recover.
- NIST SP 800-63B: used for password, session, and authenticator lifecycle expectations. New and reset passwords require at least 15 characters by default for password-only local authentication.
- NIST SP 800-53 Rev. 5: used to map relevant controls for local account management, audit, configuration integrity, backup, and recovery.
- NIST SP 800-218 and SP 800-218A: used for secure software and AI-system handling considerations.

## Implemented Control Mapping

| NIST reference | Project control |
| --- | --- |
| AC-2 Account Management | Admin-only user creation, account disable/enable, password reset, role separation, and user lifecycle audit events. |
| IA-2 / IA-5 Identification, Authentication, Authenticator Management | Login required before upload, salted adaptive password hashes, 15-character minimum for new/reset passwords, common-password blocking, account lockout, session timeout, and blocked re-bootstrap after setup. |
| AU-2 / AU-6 Event Logging and Review | Login, logout, timeout, upload, analysis, export, admin changes, refused bootstrap, DB recovery state, and backup events are logged locally. |
| CM-3 / CM-5 / CM-6 Configuration Control | Deleted, empty, or unreadable auth DB after setup is treated as a security-state change and blocks normal operation. |
| SI-7 Integrity | A host-local install seal detects mismatch between initialized state and the current auth DB. The seal is a tamper signal, not tamper-proof storage. |
| CP-9 Backup | Local timestamped auth DB backups are created before privileged account-management changes. |
| SC-7 / SC-8 Boundary and Communications Protection | The BusterNet sidecar remains bound to `127.0.0.1`; `BUSTERNET_TOKEN` protects `/predict` from direct local calls by default; launchers automatically create/read a host-local token file. |
| SA-12 / SR-4 Supply Chain Risk Management | Runtime dependencies are pinned in requirements files and `pip-audit` evidence is maintained in `SECURITY_TEST_REPORT.md`. |

## Account Lifecycle

- The first admin is created with `bootstrap_admin.py --username <name>` only when no users exist and no install seal exists.
- `bootstrap_admin.py` prompts for the password interactively. Passwords must not be passed on the command line.
- After first-admin creation, `security/install_state.json` seals the local installation.
- If `security/auth.db` is deleted, emptied, or unreadable after setup, the app refuses normal bootstrap and shows a recovery screen.
- Admin users manage accounts from the `Security Admin` tab. Analysts cannot see or use the admin surface.
- Raw passwords, uploaded image bytes, and model outputs are not stored in the auth database.
- Existing passwords continue to verify, but new accounts and password resets must meet the current minimum length.

## Recovery

- List available backups:

```powershell
.\.venv-app\Scripts\python.exe .\restore_auth_backup.py --list
```

- Restore a trusted backup:

```powershell
.\.venv-app\Scripts\python.exe .\restore_auth_backup.py --backup <backup.db> --confirm RESTORE_AUTH_DB
```

- Do not delete the install seal to bypass recovery. If both the auth DB and seal are removed, treat the host as compromised or deliberately rebuilt.
- Preserve `security/security_events.jsonl` and auth DB backups if incident evidence is needed.

## Legacy Runtime Risk

The deployed fine-tuned BusterNet model depends on a legacy sidecar runtime:

- Python 3.6.x
- TensorFlow 1.8.0
- Keras 2.2.2

The current default checkpoint is `busternet_sidecar/finetuned_model/phase5_final_seed42_finetuned_best.hd5`. These versions are old and should be treated as a known risk.

Compensating controls:

- Keep the model in a separate sidecar environment.
- Bind the sidecar to localhost only.
- Do not add user-authentication logic to the legacy sidecar.
- Validate uploads in the modern Streamlit app before forwarding them.
- Use the required shared sidecar token for prediction calls. The app and sidecar launchers automatically create/read `security/sidecar_token` when `BUSTERNET_TOKEN` is not set. Only disable token enforcement for isolated classroom debugging.
- Do not expose the sidecar directly to the internet.

## Transport Security

The default development workflow can use `run_app_https.py` to launch Streamlit at `https://localhost:8501` with a host-local self-signed certificate. The generated private key is stored under `security/local_tls/` and is excluded from source control.

The BusterNet sidecar intentionally remains plain HTTP on `127.0.0.1` because it is not a browser-facing or network-facing service. The browser communicates with Streamlit over HTTPS, and Streamlit communicates with the sidecar through loopback plus the shared token. Adding TLS inside the Python 3.6 sidecar would increase legacy-runtime complexity without improving the external attack boundary, as long as the sidecar remains bound to localhost.

For professional or multi-user deployment, replace the self-signed certificate with an organization-managed certificate or place Streamlit behind an HTTPS reverse proxy. The BusterNet sidecar must remain localhost-only and must not be exposed as a public network service.

## Security Test Evidence

`SECURITY_TEST_REPORT.md` records the current local security checks, including password policy, token-required sidecar behavior, dependency pinning, dependency audit status, and accepted legacy runtime risks.

## Host-Compromise Limit

This app cannot protect itself from an attacker who controls the machine, can edit source code, or can freely delete local security files. NIST-aligned operation requires host controls outside the app: OS account separation, filesystem permissions, endpoint protection, backups, code integrity controls, and incident response procedures.

For production or internet-facing use, replace local SQLite auth with an external identity provider, enable HTTPS, add MFA, centralize logging, run vulnerability scanning, and modernize or container-isolate the ML runtime.
