# Genesect Installer (Windows)
$ErrorActionPreference = "Stop"

Write-Host "=========================================="
Write-Host "  Genesect Installer (Windows) "
Write-Host "=========================================="

if ($env:IDAUSR) {
    $IdaPlugins = Join-Path $env:IDAUSR "plugins"
} elseif ($env:APPDATA) {
    $IdaPlugins = Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"
} else {
    Write-Error "Could not determine IDA plugins directory."
    exit 1
}

if (!(Test-Path $IdaPlugins)) {
    New-Item -ItemType Directory -Force -Path $IdaPlugins | Out-Null
}

Write-Host "Target Directory: $IdaPlugins"

Write-Host "[*] Cleaning up legacy installations..."
$LegacyEntryName = "Pseudo" + "NoteExtended.py"
$LegacyBaseName = "pseudo" + "note"
$OldFiles = @(
    (Join-Path $IdaPlugins "Genesect.py"),
    (Join-Path $IdaPlugins $LegacyEntryName),
    (Join-Path $IdaPlugins ($LegacyBaseName + ".py")),
    (Join-Path $IdaPlugins $LegacyBaseName),
    (Join-Path $IdaPlugins ($LegacyBaseName + ".ini")),
    (Join-Path $env:USERPROFILE ("." + $LegacyBaseName + ".ini"))
)
foreach ($File in $OldFiles) {
    if (Test-Path $File) {
        Remove-Item -Recurse -Force $File -ErrorAction SilentlyContinue
    }
}

function Get-InstallerScriptDir {
    $Candidates = @(
        $PSScriptRoot,
        $PSCommandPath,
        $MyInvocation.MyCommand.Path,
        $MyInvocation.MyCommand.Definition
    )

    foreach ($Candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($Candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $Candidate -PathType Leaf -ErrorAction SilentlyContinue) {
            $Candidate = Split-Path -Parent $Candidate
        }

        if (Test-Path -LiteralPath $Candidate -PathType Container -ErrorAction SilentlyContinue) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }

    return $null
}

function Get-LatestReleaseZipUri {
    $ApiUri = "https://api.github.com/repos/fareedfauzi/Genesect-Extended/releases/latest"
    $Release = Invoke-RestMethod -Uri $ApiUri -Headers @{ "User-Agent" = "Genesect-Extended-Installer" } -ErrorAction Stop
    $Asset = $Release.assets |
        Where-Object { $_.name -match '^Genesect-Extended(?:-[0-9][A-Za-z0-9._-]*)?\.zip$' } |
        Select-Object -First 1

    if ($Asset -and $Asset.browser_download_url) {
        return $Asset.browser_download_url
    }

    return $null
}

$ScriptDir = Get-InstallerScriptDir

if ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "Genesect.py")) -and (Test-Path (Join-Path $ScriptDir "genesect"))) {
    Write-Host "[*] Local installation detected."
    Copy-Item -Force (Join-Path $ScriptDir "Genesect.py") -Destination $IdaPlugins
    
    $TargetPkg = Join-Path $IdaPlugins "genesect"
    if (Test-Path $TargetPkg) { Remove-Item -Recurse -Force $TargetPkg }
    Copy-Item -Recurse -Force (Join-Path $ScriptDir "genesect") -Destination $TargetPkg
} else {
    Write-Host "[*] Remote installation detected. Downloading latest release from GitHub..."
    $TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    
    try {
        $ZipPath = Join-Path $TmpDir "Genesect-Extended.zip"
        $FallbackUri = "https://github.com/fareedfauzi/Genesect-Extended/archive/refs/heads/main.zip"

        $OldProgressPreference = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        try {
            try {
                $ReleaseUri = Get-LatestReleaseZipUri
                if (-not $ReleaseUri) {
                    throw "No Genesect release zip asset found."
                }
                Write-Host "[*] Downloading release asset: $ReleaseUri"
                Invoke-WebRequest -Uri $ReleaseUri -OutFile $ZipPath -ErrorAction Stop
            } catch {
                Write-Host "[!] Release zip unavailable. Falling back to source archive..."
                Invoke-WebRequest -Uri $FallbackUri -OutFile $ZipPath -ErrorAction Stop
            }
        } finally {
            $ProgressPreference = $OldProgressPreference
        }
        
        Write-Host "[*] Extracting..."
        Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

        $CandidateDirs = @((Get-Item -LiteralPath $TmpDir)) + @(Get-ChildItem -Path $TmpDir -Directory -Recurse)
        $ExtractedDir = $CandidateDirs | Where-Object {
            (Test-Path (Join-Path $_.FullName "Genesect.py")) -and
            (Test-Path (Join-Path $_.FullName "genesect"))
        } | Select-Object -First 1

        if (-not $ExtractedDir) {
            Write-Error "Downloaded archive does not contain Genesect.py and genesect."
            exit 1
        }

        $SourceDir = $ExtractedDir.FullName
        Copy-Item -Force (Join-Path $SourceDir "Genesect.py") -Destination $IdaPlugins
        
        $TargetPkg = Join-Path $IdaPlugins "genesect"
        if (Test-Path $TargetPkg) { Remove-Item -Recurse -Force $TargetPkg }
        
        # PowerShell Copy-Item -Recurse copies the folder itself into the destination, so destination should be $IdaPlugins
        Copy-Item -Recurse -Force (Join-Path $SourceDir "genesect") -Destination $IdaPlugins
    } finally {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
}

Write-Host "[*] Installation completed successfully."
Write-Host "[!] Please ensure Python dependencies are installed:"
Write-Host "    pip install openai httpx PySide6"
Write-Host "[*] Restart IDA Pro to load the updated plugin."
