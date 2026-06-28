$ErrorActionPreference = "Stop"

Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)

python .\tools\security_self_check.py

New-Item -ItemType Directory -Force -Path .\security_reports | Out-Null

python -m pip_audit -r .\requirements.txt -f json -o .\security_reports\pip-audit-app.json
$appExit = $LASTEXITCODE
if ($appExit -notin @(0, 1)) {
    throw "Main app pip-audit failed with exit code $appExit"
}

python -m pip_audit -r .\busternet_sidecar\requirements-legacy.txt --no-deps --disable-pip --timeout 60 -f json -o .\security_reports\pip-audit-legacy-sidecar.json
$legacyExit = $LASTEXITCODE
if ($legacyExit -notin @(0, 1)) {
    throw "Legacy sidecar pip-audit failed with exit code $legacyExit"
}

Write-Host "Security checks completed. pip-audit exit code 1 means vulnerabilities were reported; see security_reports and SECURITY_TEST_REPORT.md."
