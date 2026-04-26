$python = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
  $python = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
  $python = "py -3"
}

if (-not $python) {
  throw "Python was not found. Install Python 3.10+ first."
}

Invoke-Expression "$python -m venv `"$PSScriptRoot\.venv`""
& "$PSScriptRoot\.venv\Scripts\python.exe" -m pip install --upgrade pip
& "$PSScriptRoot\.venv\Scripts\python.exe" -m pip install -r "$PSScriptRoot\requirements.txt"
