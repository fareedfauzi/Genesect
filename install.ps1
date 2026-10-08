# PseudoNote Extended Installer (Windows)
$ErrorActionPreference = "Stop"

Write-Host "=========================================="
Write-Host "  PseudoNote Extended Installer (Windows) "
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

Write-Host "[*] Cleaning up classic PseudoNote installations..."
$OldFiles = @(
    (Join-Path $IdaPlugins "pseudonote.py"),
    (Join-Path $IdaPlugins "pseudonote"),
    (Join-Path $IdaPlugins "pseudonote.ini"),
    (Join-Path $env:USERPROFILE ".pseudonote.ini")
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

$ScriptDir = Get-InstallerScriptDir

if ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "PseudoNoteExtended.py")) -and (Test-Path (Join-Path $ScriptDir "pseudonote_extended"))) {
    Write-Host "[*] Local installation detected."
    Copy-Item -Force (Join-Path $ScriptDir "PseudoNoteExtended.py") -Destination $IdaPlugins
    
    $TargetPkg = Join-Path $IdaPlugins "pseudonote_extended"
    if (Test-Path $TargetPkg) { Remove-Item -Recurse -Force $TargetPkg }
    Copy-Item -Recurse -Force (Join-Path $ScriptDir "pseudonote_extended") -Destination $TargetPkg
} else {
    Write-Host "[*] Remote installation detected. Downloading latest release from GitHub..."
    $TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    
    try {
        $ZipPath = Join-Path $TmpDir "PseudoNote-Extended.zip"
        $ReleaseUri = "https://github.com/fareedfauzi/PseudoNote-Extended/releases/latest/download/PseudoNote-Extended.zip"
        $FallbackUri = "https://github.com/fareedfauzi/PseudoNote-Extended/archive/refs/heads/main.zip"

        $OldProgressPreference = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        try {
            try {
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
            (Test-Path (Join-Path $_.FullName "PseudoNoteExtended.py")) -and
            (Test-Path (Join-Path $_.FullName "pseudonote_extended"))
        } | Select-Object -First 1

        if (-not $ExtractedDir) {
            Write-Error "Downloaded archive does not contain PseudoNoteExtended.py and pseudonote_extended."
            exit 1
        }

        $SourceDir = $ExtractedDir.FullName
        Copy-Item -Force (Join-Path $SourceDir "PseudoNoteExtended.py") -Destination $IdaPlugins
        
        $TargetPkg = Join-Path $IdaPlugins "pseudonote_extended"
        if (Test-Path $TargetPkg) { Remove-Item -Recurse -Force $TargetPkg }
        
        # PowerShell Copy-Item -Recurse copies the folder itself into the destination, so destination should be $IdaPlugins
        Copy-Item -Recurse -Force (Join-Path $SourceDir "pseudonote_extended") -Destination $IdaPlugins
    } finally {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
}

Write-Host "[*] Installation completed successfully."
Write-Host "[!] Please ensure Python dependencies are installed:"
Write-Host "    pip install openai httpx PySide6"
Write-Host "[*] Restart IDA Pro to load the updated plugin."
