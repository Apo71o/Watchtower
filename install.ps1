# Watchtower installer for Windows.
# Creates an isolated venv under %LOCALAPPDATA%\Watchtower and a desktop shortcut.
# Does not require or request Administrator rights.
$ErrorActionPreference = "Stop"
$Src     = $PSScriptRoot
$AppHome = Join-Path $env:LOCALAPPDATA "Watchtower"
$Venv    = Join-Path $AppHome "venv"

function Find-Python {
    foreach ($cand in @(@("py", "-3"), @("python"))) {
        try {
            $exe = $cand[0]; $rest = @($cand | Select-Object -Skip 1)
            & $exe @rest -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>$null
            if ($LASTEXITCODE -eq 0) { return ,$cand }
        } catch {}
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Write-Host "Python 3.11+ not found. Install it with:" -ForegroundColor Yellow
    Write-Host "    winget install Python.Python.3.12"
    Write-Host "then re-run this script."
    exit 1
}

Write-Host "==> Creating venv in $Venv"
$exe = $py[0]; $pyArgs = @($py | Select-Object -Skip 1)
& $exe @pyArgs -m venv $Venv
& "$Venv\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
& "$Venv\Scripts\python.exe" -m pip install $Src

$Target = Join-Path $Venv "Scripts\watchtower-gui.exe"
$Lnk = Join-Path ([Environment]::GetFolderPath("Desktop")) "Watchtower.lnk"
$sh = (New-Object -ComObject WScript.Shell).CreateShortcut($Lnk)
$sh.TargetPath = $Target
$sh.WorkingDirectory = $AppHome
$sh.Description = "Watchtower security audit (reporting only)"
$sh.Save()

Write-Host "==> Installed. Desktop shortcut: $Lnk" -ForegroundColor Green
Write-Host "    Next: install Nmap (includes the Npcap driver):  winget install Insecure.Nmap"
