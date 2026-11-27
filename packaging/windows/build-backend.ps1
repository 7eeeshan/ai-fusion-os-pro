<#
Builds the self-contained backend the desktop app ships: the official Windows embeddable Python, the locked
dependencies (hash-checked) and fusion_os, in build\backend\python. Nothing is installed on the build machine.

The Python download is verified with its Sigstore bundle against the CPython release manager's identity, as
python.org documents. Requires a Python 3.12 on PATH to run pip and sigstore (the GitHub runner has one).
#>
param(
  [string]$PythonVersion = "3.12.10",
  [string]$SigIdentity = "thomas@python.org",
  [string]$SigIssuer = "https://accounts.google.com"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$out = Join-Path $root "build\backend"
$py = Join-Path $out "python"
$dl = Join-Path $root "build\downloads"
New-Item -ItemType Directory -Force -Path $dl | Out-Null
if (Test-Path $py) { Remove-Item -Recurse -Force $py }
New-Item -ItemType Directory -Force -Path $py | Out-Null

$zipName = "python-$PythonVersion-embed-amd64.zip"
$zip = Join-Path $dl $zipName
$base = "https://www.python.org/ftp/python/$PythonVersion"
Invoke-WebRequest "$base/$zipName" -OutFile $zip
Invoke-WebRequest "$base/$zipName.sigstore" -OutFile "$zip.sigstore"
python -m pip install --quiet "sigstore==4.5.1"
python -m sigstore verify identity --bundle "$zip.sigstore" --cert-identity $SigIdentity --cert-oidc-issuer $SigIssuer $zip
if ($LASTEXITCODE -ne 0) { throw "Sigstore verification of $zipName failed" }

Expand-Archive $zip -DestinationPath $py
$tag = ($PythonVersion.Split(".")[0..1] -join "")
# Lib\site-packages holds the app and its dependencies. 'import site' stays off: no user site, no .pth hooks.
Set-Content -Path (Join-Path $py "python$tag._pth") -Encoding ascii -Value @("python$tag.zip", ".", "Lib\site-packages")
$site = Join-Path $py "Lib\site-packages"
New-Item -ItemType Directory -Force -Path $site | Out-Null

python -m pip install --quiet --no-cache-dir --require-hashes --only-binary=:all: --platform win_amd64 `
  --python-version $PythonVersion.Substring(0, 4) --implementation cp --target $site -r "$PSScriptRoot\requirements.txt"
if ($LASTEXITCODE -ne 0) { throw "dependency install failed" }
python -m pip install --quiet --no-cache-dir --no-deps --target $site $root
if ($LASTEXITCODE -ne 0) { throw "app install failed" }
Get-ChildItem $site -Directory -Filter "*.dist-info" | ForEach-Object { Remove-Item -Recurse -Force (Join-Path $_.FullName "RECORD") -ErrorAction SilentlyContinue }
Get-ChildItem $site -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
& (Join-Path $py "python.exe") -I -m compileall -q $site | Out-Null

# Smoke tests with the bundled interpreter, exactly as the app runs it.
$exe = Join-Path $py "python.exe"
& $exe -I -m fusion_os --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw "bundled backend does not start" }
& $exe -I -c "from fusion_os.sandbox import ProcessSandbox, SandboxSpec; r = ProcessSandbox().run(SandboxSpec(image='python:3.12-slim', command=['python', '-c', 'print(6*7)'])); assert r.stdout.strip() == '42', r; r = ProcessSandbox().run(SandboxSpec(image='python:3.12-slim', command=['python', '-c', 'import socket'])); assert r.exit_code != 0 and 'sandbox:' in r.stderr, r; print('process sandbox ok')"
if ($LASTEXITCODE -ne 0) { throw "process sandbox smoke test failed" }
Write-Host "backend ready in $py"
