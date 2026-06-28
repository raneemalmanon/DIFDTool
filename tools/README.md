# 🛠️ Development & Security Tools

This directory contains automated scripts used to validate the security baseline of the Digital Image Forgery Detection (DIFD) tool. 

> **Note:** These scripts are intended strictly for development and Continuous Integration (CI) environments. End-users running the DIFD tool do not need to use these files.

## 📄 Included Scripts

* **`security_self_check.py`**
  A static analysis auditor. It scans the project's core files to ensure the security baseline is intact (e.g., verifying that the minimum password length is exactly 15 characters, ensuring TLS configurations are present, and checking that secrets are excluded from `.gitignore`).
* **`run_security_checks.ps1`**
  A PowerShell automation wrapper. It executes the self-check auditor and runs `pip-audit` to scan all project dependencies (`requirements.txt`) against known CVE databases. 

## ⚙️ Prerequisites

To execute these tests, you must have `pip-audit` installed in your active Python environment:

```bash
pip install pip-audit
```

## 🚀 Usage

From the root directory of the repository, execute the PowerShell script:
```PowerShell
.\tools\run_security_checks.ps1
```

* Success (Exit Code 0): The script will run silently and complete without throwing errors.
* Failure (Exit Code 1+): An error indicates either a failed internal security policy check or a newly discovered vulnerable package dependency. Detailed logs will be generated in the security_reports/ directory.