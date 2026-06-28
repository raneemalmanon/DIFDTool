param(
    [Parameter(Mandatory = $true)]
    [string]$PythonExe,
    [string]$VenvPath = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $ScriptRoot) {
    $ScriptRoot = (Get-Location).Path
}

if (-not $VenvPath) {
    $VenvPath = Join-Path $ScriptRoot ".venv36"
}

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python executable not found: $PythonExe"
}

& $PythonExe -m venv $VenvPath

$venvPython = Join-Path $VenvPath "Scripts\\python.exe"
$deadline = (Get-Date).AddSeconds(10)
while ((-not (Test-Path -LiteralPath $venvPython)) -and ((Get-Date) -lt $deadline)) {
    Start-Sleep -Milliseconds 250
}

if (-not (Test-Path -LiteralPath $venvPython)) {
    throw "Virtual environment Python was not created successfully at $venvPython."
}

& $venvPython -m pip install --upgrade "pip<22" "setuptools<60" wheel
& $venvPython -m pip install -r (Join-Path $ScriptRoot "requirements-legacy.txt")

Write-Host ""
Write-Host "Legacy BusterNet environment is ready."
Write-Host "Start the sidecar with:"
Write-Host "  $venvPython $(Join-Path $ScriptRoot 'run_sidecar.py')"
