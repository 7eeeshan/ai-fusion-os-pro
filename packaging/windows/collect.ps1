<#
Collects the release files into dist\: setup exe, MSI, portable zip, dependency manifest and SHA-256 checksums.
#>
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$rel = Join-Path $root "desktop\src-tauri\target\release"
$dist = Join-Path $root "dist"
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Path $dist | Out-Null

$nsis = Get-ChildItem (Join-Path $rel "bundle\nsis") -Filter "*-setup.exe" | Select-Object -First 1
$msi = Get-ChildItem (Join-Path $rel "bundle\msi") -Filter "*.msi" | Select-Object -First 1
if (-not $nsis -or -not $msi) { throw "installer outputs not found" }
Copy-Item $nsis.FullName (Join-Path $dist "AI-Fusion-OS-Pro-Setup.exe")
Copy-Item $msi.FullName (Join-Path $dist "AI-Fusion-OS-Pro-x64.msi")

# Portable edition: the app exe with its backend and tor folders next to it. Data still goes to the user profile.
$stage = Join-Path $root "build\portable\AI-Fusion-OS-Pro"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item (Join-Path $rel "ai-fusion-os-pro.exe") (Join-Path $stage "AI Fusion OS Pro.exe")
Copy-Item -Recurse (Join-Path $root "build\backend") (Join-Path $stage "backend")
Copy-Item -Recurse (Join-Path $root "build\tor") (Join-Path $stage "tor")
Copy-Item (Join-Path $root "packaging\windows\PORTABLE.txt") (Join-Path $stage "README.txt")
Compress-Archive -Path $stage -DestinationPath (Join-Path $dist "AI-Fusion-OS-Pro-Portable-x64.zip")

$py = & (Join-Path $root "build\backend\python\python.exe") -I -c "import sys; print(sys.version.split()[0])"
$tor = Get-Content (Join-Path $root "build\tor\VERSION")
$lines = @("AI Fusion OS Pro dependency manifest", "", "Embedded Python: $py (python.org embeddable, Sigstore-verified)",
  "Tor Expert Bundle: $tor (GPG-verified checksum list)", "Tauri CLI: $(Get-Content (Join-Path $root 'desktop\package.json') | Select-String '@tauri-apps/cli')",
  "", "Python packages (hash-locked):")
$lines += Get-Content (Join-Path $root "packaging\windows\requirements.txt") | Where-Object { $_ -match "^[a-z0-9].*==" } | ForEach-Object { "  " + $_.Trim(" \") }
$lines += @("", "Rust crates (direct):")
Push-Location (Join-Path $root "desktop\src-tauri")
$lines += (cargo tree --depth 1 --prefix none --edges normal 2>$null)
Pop-Location
Set-Content -Path (Join-Path $dist "DEPENDENCIES.txt") -Value $lines -Encoding utf8

$sums = Get-ChildItem $dist -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name | ForEach-Object {
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
Set-Content -Path (Join-Path $dist "SHA256SUMS.txt") -Value $sums -Encoding ascii
Get-ChildItem $dist | Format-Table Name, Length
