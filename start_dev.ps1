$ErrorActionPreference = "Stop"

Write-Host "Starting Tempris Development Environment..." -ForegroundColor Cyan

# 1. Start FreeLLMAPI
Write-Host "Starting FreeLLMAPI on port 3001..." -ForegroundColor Green
Start-Process "powershell" -ArgumentList "-NoExit -Command `"cd c:\Tempris\freellmapi; npm run dev`"" -WindowStyle Normal

# 2. Start Tempris API
Write-Host "Starting Tempris API on port 8000..." -ForegroundColor Green
Start-Process "powershell" -ArgumentList "-NoExit -Command `"cd c:\Tempris\tempris\api; .\venv\Scripts\activate; uvicorn index:app --reload`"" -WindowStyle Normal

# 3. Start Tempris Frontend
Write-Host "Starting Tempris Frontend on port 5173..." -ForegroundColor Green
Start-Process "powershell" -ArgumentList "-NoExit -Command `"cd c:\Tempris\tempris; npm run dev`"" -WindowStyle Normal

Write-Host "All services started in separate windows." -ForegroundColor Cyan
