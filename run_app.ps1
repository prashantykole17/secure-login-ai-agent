$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
  & $venvPython "$PSScriptRoot\app.py"
  exit $LASTEXITCODE
}

$candidates = @("python", "py -3", "py")

foreach ($candidate in $candidates) {
  try {
    Invoke-Expression "$candidate `"$PSScriptRoot\app.py`""
    exit $LASTEXITCODE
  } catch {
    continue
  }
}

throw "Python or the project virtual environment was not found. Run setup.ps1 first."
