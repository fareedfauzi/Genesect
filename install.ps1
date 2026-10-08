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
    Write-Host "[*] Remote installation detected. Downloading latest version from GitHub..."
    $TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    
    $ZipPath = Join-Path $TmpDir "main.zip"
    Invoke-WebRequest -Uri "https://github.com/fareedfauzi/PseudoNote-Extended/archive/refs/heads/main.zip" -OutFile $ZipPath
    
    Write-Host "[*] Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
    
    $ExtractedDir = Join-Path $TmpDir "PseudoNote-Extended-main"
    Copy-Item -Force (Join-Path $ExtractedDir "PseudoNoteExtended.py") -Destination $IdaPlugins
    
    $TargetPkg = Join-Path $IdaPlugins "pseudonote_extended"
    if (Test-Path $TargetPkg) { Remove-Item -Recurse -Force $TargetPkg }
    
    # PowerShell Copy-Item -Recurse copies the folder itself into the destination, so destination should be $IdaPlugins
    Copy-Item -Recurse -Force (Join-Path $ExtractedDir "pseudonote_extended") -Destination $IdaPlugins
    
    Remove-Item -Recurse -Force $TmpDir
}

Write-Host "[*] Installation completed successfully."
Write-Host "[!] Please ensure Python dependencies are installed:"
Write-Host "    pip install openai httpx PySide6"
Write-Host "[*] Restart IDA Pro to load the updated plugin."
