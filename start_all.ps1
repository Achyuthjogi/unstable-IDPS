# ─────────────────────────────────────────────────────────────
# Nexus Enterprise IDPS - Windows PowerShell Launcher
# Runs: Python ML Microservice, React SOC Dashboard, Go Engine
# Must be executed in PowerShell as Administrator
# ─────────────────────────────────────────────────────────────

$Host.UI.RawUI.WindowTitle = "Nexus Enterprise IDPS - Console"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   Nexus Enterprise IDPS - Windows Launcher (v2.0)    " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 1. Administrator Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running as Administrator!" -ForegroundColor Red
    Write-Host "    Raw packet capture (Npcap) and Windows Firewall (netsh/WFP)" -ForegroundColor Yellow
    Write-Host "    require elevated privileges. Please re-run PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host ""
}

# Check Npcap Driver
$hasNpcap = (Test-Path "$env:SystemRoot\System32\drivers\npcap.sys") -or 
            (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") -or 
            (Test-Path "$env:SystemRoot\System32\wpcap.dll")

if (-not $hasNpcap) {
    Write-Host "[!] NOTICE: Npcap packet capture driver was not detected." -ForegroundColor Yellow
    Write-Host "    Nexus IDPS will attempt raw socket fallback, but Npcap is recommended." -ForegroundColor Yellow
    Write-Host "    Tip: Run '.\setup_windows.ps1' to automatically install all Windows dependencies." -ForegroundColor Cyan
    Write-Host ""
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Prepare logs folder
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

$BackgroundJobs = @()

# 2. Start Python ML Microservice
Write-Host "--> [1/3] Starting Python ML Microservice (port 5001)..." -ForegroundColor Green
if (Test-Path ".venv\Scripts\Activate.ps1") {
    $mlJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        & .venv\Scripts\Activate.ps1
        python backend\ml_server.py
    } -ArgumentList $ScriptDir
    $BackgroundJobs += $mlJob
} else {
    Write-Host "    Virtual environment not found. Attempting direct python launch..." -ForegroundColor Yellow
    $mlJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        python backend\ml_server.py
    } -ArgumentList $ScriptDir
    $BackgroundJobs += $mlJob
}

# 3. Start React SOC Dashboard
Write-Host "--> [2/3] Starting React SOC Dashboard (port 5173)..." -ForegroundColor Green
$npmPath = (Get-Command npm -ErrorAction SilentlyContinue)
if ($npmPath) {
    $uiJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location "$dir\frontend"
        npm run dev
    } -ArgumentList $ScriptDir
    $BackgroundJobs += $uiJob
} else {
    Write-Host "    [!] 'npm' not found in PATH. Web Dashboard bypassed." -ForegroundColor Yellow
    Write-Host "    Core engine & REST APIs will run in Headless mode." -ForegroundColor Gray
}

# 4. Start Suricata Primary DPI Engine
Write-Host "--> [3/4] Starting Suricata Primary DPI Engine..." -ForegroundColor Green
$suricataRunning = Get-Process suricata -ErrorAction SilentlyContinue
if ($suricataRunning) {
    Write-Host "    [✓] Active Suricata process detected (PID: $($suricataRunning.Id))." -ForegroundColor Green
} else {
    $suricataBin = (Get-Command suricata.exe -ErrorAction SilentlyContinue)
    $binPath = $null
    if ($suricataBin) {
        $binPath = $suricataBin.Source
    } else {
        $candidates = @("C:\Program Files\Suricata\suricata.exe", "C:\Suricata\suricata.exe", "C:\ProgramData\Suricata\suricata.exe")
        foreach ($c in $candidates) {
            if (Test-Path $c) { $binPath = $c; break }
        }
    }

    if ($binPath) {
        $suricataJob = Start-Job -ScriptBlock {
            param($bin)
            $cfg = "C:\Program Files\Suricata\suricata.yaml"
            if (Test-Path $cfg) {
                & $bin -c $cfg
            } else {
                & $bin
            }
        } -ArgumentList $binPath
        $BackgroundJobs += $suricataJob
        Write-Host "    [✓] Suricata active as background DPI engine." -ForegroundColor Green
    } else {
        Write-Host "    [!] Notice: suricata.exe not found. Run '.\setup_windows.ps1' to install Suricata." -ForegroundColor Yellow
    }
}

# 5. Compile or verify Windows Go binary
Write-Host "--> [4/4] Starting Nexus Enterprise Controller (Firewall & Dashboard)..." -ForegroundColor Green
Set-Location "$ScriptDir\backend"
if (-not (Test-Path "idps-backend.exe")) {
    Write-Host "    Compiling idps-backend.exe..." -ForegroundColor Gray
    go build -o idps-backend.exe .
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   NEXUS ENTERPRISE IDPS (SURICATA PRIMARY ENGINE)    " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  [+] Primary Engine:   SURICATA IDS/IPS (Deep Packet Inspection)" -ForegroundColor Green
Write-Host "  [+] Go Core Backend:  http://localhost:8000" -ForegroundColor Green
Write-Host "  [+] Sensor Health:    http://localhost:8000/api/health" -ForegroundColor Green
Write-Host "  [+] Telemetry Stream: ws://localhost:8000/ws" -ForegroundColor Green
Write-Host "  [+] SOC Dashboard:    http://localhost:5173" -ForegroundColor Green
Write-Host "  [+] ML Inference:     http://localhost:5001/health" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to terminate all services safely." -ForegroundColor Yellow
Write-Host ""

try {
    # Run the Windows Go backend in the foreground
    .\idps-backend.exe
}
finally {
    Write-Host "`n[*] Terminating background services..." -ForegroundColor Red
    foreach ($job in $BackgroundJobs) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -ErrorAction SilentlyContinue
    }
    Write-Host "[+] All services stopped safely." -ForegroundColor Green
    Set-Location $ScriptDir
}
