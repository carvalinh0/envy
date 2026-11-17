# Installs Envy (the `envy` binary).
#
# 1. If Cargo is available, it runs `cargo install dot-envy`.
# 2. Otherwise (or if that fails) it downloads the prebuilt binary of the latest GitHub release.
#
# Usage: powershell -c "irm https://raw.githubusercontent.com/carvalinh0/envy/main/scripts/install.ps1|iex"
#
# Optional environment variables:
#   ENVY_INSTALL_DIR  where the prebuilt binary is copied to (default: %LOCALAPPDATA%\envy\bin)
#   ENVY_VERSION      release tag to download, e.g. v1.2.3 (default: the latest release)
#   ENVY_REPO         GitHub repository (default: carvalinh0/envy)
#   ENVY_GITHUB_URL   GitHub base URL (default: https://github.com)
#
# When minisign is installed, the archive must carry the release key's signature
# (key id FFEFC84D5F45A95F, the same key `envy update` checks).
$ErrorActionPreference = "Stop"

$Crate = "dot-envy"
$Repo = if ($env:ENVY_REPO) { $env:ENVY_REPO } else { "carvalinh0/envy" }
$GithubUrl = if ($env:ENVY_GITHUB_URL) { $env:ENVY_GITHUB_URL } else { "https://github.com" }
$InstallDir = if ($env:ENVY_INSTALL_DIR) { $env:ENVY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "envy\bin" }
$ReleaseKey = "RWRfqUVfTcjv/06FBkCOswn6uHfKptnnu9z6h0mEaGqnqHS6bJHSqNeR"

function Install-WithCargo {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { return $false }

    Write-Host "==> Cargo found, running: cargo install $Crate"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    cargo install $Crate
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $previous
    return $ok
}

function Get-LatestTag {
    if ($env:ENVY_VERSION) { return $env:ENVY_VERSION }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if (-not $release.tag_name) { throw "No release was found for $Repo." }
    return $release.tag_name
}

# Checks the minisign signature of the archive and that it was made for this tag and archive.
function Test-Signature($Archive, $Url, $Tag, $Asset) {
    if (-not (Get-Command minisign -ErrorAction SilentlyContinue)) {
        Write-Warning "minisign is not installed, so the signature of $Asset was not checked (https://jedisct1.github.io/minisign/)."
        return
    }
    try {
        Invoke-WebRequest -Uri "$Url.minisig" -OutFile "$Archive.minisig"
    } catch {
        throw "Could not download the signature of $Asset; nothing was installed."
    }
    $comment = & minisign -V -P $ReleaseKey -m $Archive -x "$Archive.minisig" -Q
    if ($LASTEXITCODE -ne 0) { throw "The signature of $Asset is not valid; nothing was installed." }
    if ("$comment".Trim() -ne "envy-release $Tag $Asset") {
        throw "The signature of $Asset was made for another release; nothing was installed."
    }
    Write-Host "==> Signature of $Asset checked."
}

function Install-WithBinary {
    if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
        throw "There is no prebuilt binary for $($env:PROCESSOR_ARCHITECTURE). Install Rust (https://rustup.rs) and run: cargo install $Crate"
    }

    $target = "x86_64-pc-windows-msvc"
    $tag = Get-LatestTag
    $name = "envy-$tag-$target"
    $url = "$GithubUrl/$Repo/releases/download/$tag/$name.zip"

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "==> Downloading $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp "envy.zip")
        } catch {
            throw "Could not download $url (does release $tag have a binary for $target?)"
        }
        Test-Signature (Join-Path $tmp "envy.zip") $url $tag "$name.zip"
        Expand-Archive -Path (Join-Path $tmp "envy.zip") -DestinationPath $tmp

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item (Join-Path $tmp "$name\envy.exe") (Join-Path $InstallDir "envy.exe") -Force
        Write-Host "==> Installed to $InstallDir\envy.exe"
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }

    if (($env:PATH -split ";") -notcontains $InstallDir) {
        Write-Warning "$InstallDir is not in your PATH. Add it to run 'envy' from anywhere."
    }
}

if (Install-WithCargo) {
    Write-Host "==> Done. Run 'envy --version' to check (make sure the Cargo bin folder is in your PATH)."
    exit 0
}

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Warning "cargo install failed, falling back to the prebuilt binary."
} else {
    Write-Host "==> Cargo not found, using the prebuilt binary."
}

Install-WithBinary
Write-Host "==> Done. Run 'envy --version' to check."
