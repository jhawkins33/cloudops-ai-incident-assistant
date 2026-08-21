$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$lambdaDir = Join-Path $PSScriptRoot "lambda"

$processorZip = Join-Path $lambdaDir "lambda_function.zip"
$workerZip    = Join-Path $lambdaDir "ai_worker.zip"

$processorCheck = Join-Path $PSScriptRoot "zip-check-processor"
$workerCheck    = Join-Path $PSScriptRoot "zip-check-worker"

Write-Host "Checking Python syntax..."

python -m py_compile `
    (Join-Path $lambdaDir "lambda_function.py") `
    (Join-Path $lambdaDir "incident_rules.py") `
    (Join-Path $lambdaDir "ai_worker.py") `
    (Join-Path $lambdaDir "agent.py") `
    (Join-Path $lambdaDir "tools.py")

if ($LASTEXITCODE -ne 0) {
    throw "Python syntax validation failed."
}

Write-Host "Removing old deployment packages..."

Remove-Item $processorZip -Force -ErrorAction SilentlyContinue
Remove-Item $workerZip -Force -ErrorAction SilentlyContinue
Remove-Item $processorCheck -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $workerCheck -Recurse -Force -ErrorAction SilentlyContinue

# -------------------------------------------------
# Processor Lambda package
# -------------------------------------------------

Write-Host ""
Write-Host "Creating processor Lambda package..."

Compress-Archive `
    -Path `
        (Join-Path $lambdaDir "lambda_function.py"),
        (Join-Path $lambdaDir "incident_rules.py") `
    -DestinationPath $processorZip `
    -Force

Expand-Archive `
    -Path $processorZip `
    -DestinationPath $processorCheck `
    -Force

$processorExpected = @(
    "lambda_function.py",
    "incident_rules.py"
)

$processorActual = Get-ChildItem $processorCheck -File |
    Select-Object -ExpandProperty Name

foreach ($file in $processorExpected) {
    if ($file -notin $processorActual) {
        throw "Missing expected processor file from ZIP: $file"
    }
}

Write-Host "Processor ZIP verification passed."

# -------------------------------------------------
# AI Worker Lambda package
# -------------------------------------------------

Write-Host ""
Write-Host "Creating AI worker Lambda package..."

Compress-Archive `
    -Path `
        (Join-Path $lambdaDir "ai_worker.py"),
        (Join-Path $lambdaDir "agent.py"),
        (Join-Path $lambdaDir "tools.py") `
    -DestinationPath $workerZip `
    -Force

Expand-Archive `
    -Path $workerZip `
    -DestinationPath $workerCheck `
    -Force

$workerExpected = @(
    "ai_worker.py",
    "agent.py",
    "tools.py"
)

$workerActual = Get-ChildItem $workerCheck -File |
    Select-Object -ExpandProperty Name

foreach ($file in $workerExpected) {
    if ($file -notin $workerActual) {
        throw "Missing expected worker file from ZIP: $file"
    }
}

Write-Host "Worker ZIP verification passed."

# -------------------------------------------------
# Display package contents
# -------------------------------------------------

Write-Host ""
Write-Host "Processor Package Contents:"
Write-Host "---------------------------"

Get-ChildItem $processorCheck -File |
    Sort-Object Name |
    ForEach-Object {
        Write-Host ("  {0,-25} {1,8:N1} KB" -f $_.Name, ($_.Length / 1KB))
    }

Write-Host ""
Write-Host "AI Worker Package Contents:"
Write-Host "---------------------------"

Get-ChildItem $workerCheck -File |
    Sort-Object Name |
    ForEach-Object {
        Write-Host ("  {0,-25} {1,8:N1} KB" -f $_.Name, ($_.Length / 1KB))
    }

Write-Host ""
Write-Host "Cleaning up temporary files..."

Remove-Item $processorCheck -Recurse -Force
Remove-Item $workerCheck -Recurse -Force

$processorInfo = Get-Item $processorZip
$workerInfo    = Get-Item $workerZip

Write-Host ""
Write-Host "Build completed successfully."
Write-Host "Processor Package : $($processorInfo.FullName)"
Write-Host ("Processor ZIP Size: {0:N1} KB" -f ($processorInfo.Length / 1KB))
Write-Host ""
Write-Host "Worker Package    : $($workerInfo.FullName)"
Write-Host ("Worker ZIP Size   : {0:N1} KB" -f ($workerInfo.Length / 1KB))