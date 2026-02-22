# Navigate to script directory so docker-compose finds its config
Set-Location $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Secure CCTV - Full Pipeline Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Step 1: Clean up old frames
Write-Host "`n[1/4] Cleaning shared folders..." -ForegroundColor Yellow
Remove-Item shared\raw\* -ErrorAction SilentlyContinue
Remove-Item shared\frames\* -ErrorAction SilentlyContinue
Remove-Item shared\decrypted\* -ErrorAction SilentlyContinue

# Step 2: Build and start Docker containers
Write-Host "[2/4] Building & starting Docker containers..." -ForegroundColor Yellow
docker-compose down 2>$null
docker-compose up --build -d
Start-Sleep -Seconds 8
Write-Host "  Containers ready!" -ForegroundColor Green

# Step 3: Launch webcam capture in a new window
Write-Host "[3/4] Launching Webcam Capture..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; Write-Host 'WEBCAM CAPTURE - Press ESC to stop' -ForegroundColor Cyan; python capture_host.py"

# Step 4: Launch decrypted display in a new window
Write-Host "[4/4] Launching Decrypted Stream Viewer..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; Write-Host 'DECRYPTED STREAM VIEWER' -ForegroundColor Cyan; python display_host.py"

# Show Docker logs in this window
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  ALL SYSTEMS RUNNING!" -ForegroundColor Green
Write-Host "  - Docker: Camera + Gateway + Cloud" -ForegroundColor Green
Write-Host "  - Webcam: New window" -ForegroundColor Green
Write-Host "  - Viewer: New window" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nShowing Docker logs below (Ctrl+C to stop):`n" -ForegroundColor Yellow
docker-compose logs -f
