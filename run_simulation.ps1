param(
	[switch]$QueryConsole
)

# Navigate to script directory so docker-compose finds its config
Set-Location $PSScriptRoot

if ($QueryConsole) {
	Write-Host "========================================" -ForegroundColor Cyan
	Write-Host "  CCTV Event Query Console" -ForegroundColor Cyan
	Write-Host "========================================" -ForegroundColor Cyan
	Write-Host "Ask natural-language questions over recent events." -ForegroundColor Yellow
	Write-Host "Examples:" -ForegroundColor Yellow
	Write-Host "  - show suspicious events from last 10 minutes" -ForegroundColor Gray
	Write-Host "  - list high risk events in last 30 minutes" -ForegroundColor Gray
	Write-Host "  - any repeated person activity near entrance" -ForegroundColor Gray
	Write-Host "Type 'exit' to close this console." -ForegroundColor Yellow

	while ($true) {
		$query = Read-Host "`nQuery"

		if ([string]::IsNullOrWhiteSpace($query)) {
			continue
		}

		if ($query.Trim().ToLower() -eq "exit") {
			break
		}

		$minutesRaw = Read-Host "Lookback minutes (default 10)"
		$minutes = 10
		if (-not [string]::IsNullOrWhiteSpace($minutesRaw)) {
			$parsed = 0
			if ([int]::TryParse($minutesRaw, [ref]$parsed) -and $parsed -gt 0) {
				$minutes = $parsed
			}
		}

		python query_events.py "$query" --minutes $minutes
	}

	return
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Secure CCTV - Full Pipeline Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Step 1: Clean up old artifacts
Write-Host "`n[1/6] Cleaning shared folders..." -ForegroundColor Yellow
Remove-Item shared\raw\* -ErrorAction SilentlyContinue
Remove-Item shared\frames\* -ErrorAction SilentlyContinue
Remove-Item shared\decrypted\* -ErrorAction SilentlyContinue
Remove-Item shared\metadata\* -ErrorAction SilentlyContinue

# Step 2: Build and start Docker containers
Write-Host "[2/6] Building & starting Docker containers..." -ForegroundColor Yellow
docker-compose down 2>$null
docker-compose up --build -d
Start-Sleep -Seconds 8
Write-Host "  Containers ready!" -ForegroundColor Green

# Step 3: Start Ollama model on host
Write-Host "[3/6] Starting Ollama model (mistral)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host 'OLLAMA (HOST) - mistral' -ForegroundColor Cyan; ollama run mistral"

# Step 4: Launch YOLO host detector
Write-Host "[4/6] Launching YOLO detector..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; Write-Host 'YOLO DETECTOR - Press ESC to stop' -ForegroundColor Cyan; python detect_and_send.py"

# Step 5: Launch decrypted display in a new window
Write-Host "[5/6] Launching Decrypted Stream Viewer..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; Write-Host 'DECRYPTED STREAM VIEWER' -ForegroundColor Cyan; python display_host.py"

# Step 6: Launch natural-language query console
Write-Host "[6/6] Launching Event Query Console..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSCommandPath", "-QueryConsole"

# Show Docker logs in this window
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  ALL SYSTEMS LINKED & RUNNING!" -ForegroundColor Green
Write-Host "  - Docker: Camera + Gateway + Cloud" -ForegroundColor Green
Write-Host "  - Ollama: Host model server" -ForegroundColor Green
Write-Host "  - YOLO: Host detection producer" -ForegroundColor Green
Write-Host "  - Viewer: Host decrypted output" -ForegroundColor Green
Write-Host "  - Query: Natural language event search" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nShowing Docker logs below (Ctrl+C to stop):`n" -ForegroundColor Yellow
docker-compose logs -f
