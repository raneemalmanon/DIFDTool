$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot
$pythonExe = Join-Path $scriptRoot '.venv36\Scripts\python.exe'
$entrypoint = Join-Path $scriptRoot 'run_sidecar.py'
$tokenPath = Join-Path $projectRoot 'security\sidecar_token'

if (-not (Test-Path $pythonExe)) {
    throw "Missing sidecar venv interpreter: $pythonExe"
}

if (-not $env:BUSTERNET_TOKEN) {
    if (-not (Test-Path $tokenPath)) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $tokenPath) | Out-Null
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        Set-Content -LiteralPath $tokenPath -Value $token -NoNewline -Encoding ascii
    }
    $env:BUSTERNET_TOKEN = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
}

Set-Location $scriptRoot
& $pythonExe $entrypoint
