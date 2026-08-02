$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$lambdaDir = Join-Path $PSScriptRoot "lambda"
$zipPath = Join-Path $lambdaDir "lambda_function.zip"
$zipCheck = Join-Path $PSScriptRoot "zip-check"

Write-Host "Checking Python syntax..."
python -m py_compile `
    (Join-Path $lambdaDir "lambda_function.py") `
    (Join-Path $lambdaDir "incident_rules.py")

if ($LASTEXITCODE -ne 0) {
    throw "Python syntax validation failed."
}

Write-Host "Removing old deployment package..."
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item $zipCheck -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Creating Lambda deployment package..."
Compress-Archive `
    -Path `
        (Join-Path $lambdaDir "lambda_function.py"),
        (Join-Path $lambdaDir "incident_rules.py") `
    -DestinationPath $zipPath `
    -Force

Write-Host "Verifying ZIP contents..."
Expand-Archive `
    -Path $zipPath `
    -DestinationPath $zipCheck `
    -Force

$expectedFiles = @(
    "lambda_function.py",
    "incident_rules.py"
)

$actualFiles = Get-ChildItem $zipCheck -File |
    Select-Object -ExpandProperty Name

foreach ($file in $expectedFiles) {
    if ($file -notin $actualFiles) {
        throw "Missing expected file from ZIP: $file"
    }
}

Write-Host "ZIP verification passed."
Write-Host ""

Write-Host ""
Write-Host "Package Contents:"
Write-Host "-----------------"

Get-ChildItem $zipCheck -File |
    Sort-Object Name |
    ForEach-Object {
        Write-Host ("  {0,-25} {1,8:N1} KB" -f $_.Name, ($_.Length / 1KB))
    }

Write-Host ""
Write-Host "Cleaning up temporary files..."

if (Test-Path $zipCheck) {
    Remove-Item $zipCheck -Recurse -Force
}

$zipInfo = Get-Item $zipPath

Write-Host ""
Write-Host "Build completed successfully."
Write-Host "Package : $($zipInfo.FullName)"
Write-Host ("ZIP Size: {0:N1} KB" -f ($zipInfo.Length / 1KB))