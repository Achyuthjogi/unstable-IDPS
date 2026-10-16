# ─────────────────────────────────────────────────────────────
# Nexus Enterprise IDPS - Windows Prerequisites & Setup Installer
# Automatically installs: Npcap, Python, Node.js, Go, Suricata (optional)
# Must be executed in PowerShell as Administrator
# ─────────────────────────────────────────────────────────────

$Host.UI.RawUI.WindowTitle = "Nexus Enterprise IDPS - Windows Setup"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Nexus Enterprise IDPS - Windows Dependency Installer   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Administrator Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[X] ERROR: This setup script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "    Please right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Check winget availability
$hasWinget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $hasWinget) {
    Write-Host "[!] 'winget' (Windows Package Manager) was not found." -ForegroundColor Yellow
    Write-Host "    Please ensure Windows 10/11 App Installer is updated from the Microsoft Store," -ForegroundColor Yellow
    Write-Host "    or install dependencies manually." -ForegroundColor Yellow
}

# Function to check and install winget package
function Install-Dependency {
    param (
        [string]$Name,
        [string]$WingetId,
        [scriptblock]$CheckCommand,
        [switch]$Optional
    )

    Write-Host "`n--> Checking $Name..." -ForegroundColor Cyan
    $isInstalled = & $CheckCommand
    if ($isInstalled) {
        Write-Host "    [✓] $Name is already installed." -ForegroundColor Green
        return
    }

    if ($Optional) {
        $choice = Read-Host "    [?] $Name is optional. Would you like to install it? (y/N)"
        if ($choice -ne 'y' -and $choice -ne 'Y') {
            Write-Host "    [-] Skipping $Name." -ForegroundColor Gray
            return
        }
    }

    if ($hasWinget) {
        Write-Host "    [+] Installing $Name via winget ($WingetId)..." -ForegroundColor Yellow
        winget install --id $WingetId --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    [✓] $Name installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "    [!] Warning: winget install returned code $LASTEXITCODE. You may need to complete installation manually." -ForegroundColor Yellow
        }
    } else {
        Write-Host "    [!] Please download and install $Name manually." -ForegroundColor Yellow
    }
}

# 1. Npcap (Required for Windows Packet Capture)
Install-Dependency -Name "Npcap (Packet Capture Driver)" `
    -WingetId "Insecure.Npcap" `
    -CheckCommand {
        (Test-Path "$env:SystemRoot\System32\drivers\npcap.sys") -or 
        (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") -or
        (Test-Path "$env:SystemRoot\System32\wpcap.dll")
    }

# 2. Python 3 (Required for ML Service)
Install-Dependency -Name "Python 3.12" `
    -WingetId "Python.Python.3.12" `
    -CheckCommand {
        (Get-Command python -ErrorAction SilentlyContinue) -ne $null
    }

# 3. Node.js & npm (Required for React SOC Dashboard)
Install-Dependency -Name "Node.js (LTS)" `
    -WingetId "OpenJS.NodeJS.LTS" `
    -CheckCommand {
        (Get-Command node -ErrorAction SilentlyContinue) -ne $null
    }

# 4. Suricata IDS/IPS (Primary DPI & Threat Detection Engine)
Install-Dependency -Name "Suricata IDS/IPS Engine (Primary Engine)" `
    -WingetId "OISF.Suricata" `
    -CheckCommand {
        (Get-Command suricata -ErrorAction SilentlyContinue) -ne $null -or
        (Test-Path "C:\Program Files\Suricata\suricata.exe") -or
        (Test-Path "C:\Suricata\suricata.exe")
    }

# Ensure Suricata logging directory and rules exist
$suricataPaths = @("C:\Program Files\Suricata", "C:\Suricata", "C:\ProgramData\Suricata")
foreach ($sPath in $suricataPaths) {
    if (Test-Path $sPath) {
        $logDir = Join-Path $sPath "log"
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir | Out-Null
            Write-Host "    [+] Created Suricata EVE log directory: $logDir" -ForegroundColor Green
        }
        $updater = Join-Path $sPath "suricata-update.exe"
        if (Test-Path $updater) {
            Write-Host "    --> Updating Suricata Emerging Threats (ET) rules..." -ForegroundColor Cyan
            & $updater --quiet
            Write-Host "    [✓] Suricata rules synchronized." -ForegroundColor Green
        }
        break
    }
}

# 5. Go (Optional if compiling from source; pre-compiled idps-backend.exe is included)
Install-Dependency -Name "Go Programming Language" `
    -WingetId "GoLang.Go" `
    -CheckCommand {
        (Get-Command go -ErrorAction SilentlyContinue) -ne $null
    } -Optional

# ── Setup Project Python Virtual Environment ──────────────────
Write-Host "`n--> Configuring Python Virtual Environment for ML Microservice..." -ForegroundColor Cyan
if (Get-Command python -ErrorAction SilentlyContinue) {
    if (-not (Test-Path ".venv")) {
        Write-Host "    Creating .venv..." -ForegroundColor Gray
        python -m venv .venv
    }
    Write-Host "    Installing Python dependencies (fastapi, scikit-learn, joblib, etc.)..." -ForegroundColor Gray
    & .venv\Scripts\Activate.ps1
    pip install --quiet fastapi uvicorn joblib numpy pydantic scikit-learn pandas
    Write-Host "    [✓] Python ML dependencies installed." -ForegroundColor Green
} else {
    Write-Host "    [!] Python not yet detected in current session PATH. Restart PowerShell after installation." -ForegroundColor Yellow
}

# ── Setup Frontend Node Modules ──────────────────────────────
Write-Host "`n--> Configuring React SOC Dashboard Dependencies..." -ForegroundColor Cyan
if (Get-Command npm -ErrorAction SilentlyContinue) {
    if (-not (Test-Path "frontend\node_modules")) {
        Write-Host "    Running 'npm install' in frontend directory..." -ForegroundColor Gray
        Set-Location "$ScriptDir\frontend"
        npm install
        Set-Location $ScriptDir
        Write-Host "    [✓] Frontend packages installed." -ForegroundColor Green
    } else {
        Write-Host "    [✓] frontend\node_modules already exists." -ForegroundColor Green
    }
} else {
    Write-Host "    [!] npm not yet detected in current session PATH. Restart PowerShell after installation." -ForegroundColor Yellow
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "   Setup complete! You can now start Nexus IDPS with:    " -ForegroundColor Green
Write-Host "   .\start_all.ps1                                       " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
