# Airlock installer — one command, Windows (PowerShell).
#   irm https://raw.githubusercontent.com/airlock-agent/airlock/main/install.ps1 | iex
#
# Installs the `airlock` CLI, then tells you the one command that proves it works.
$ErrorActionPreference = 'Stop'
function Say($m){ Write-Host $m -ForegroundColor White }
function Dim($m){ Write-Host $m -ForegroundColor DarkGray }
function Err($m){ Write-Host $m -ForegroundColor Red }

# --- find a Python >= 3.11 ---------------------------------------------------
$py = $null
foreach ($c in @('python','python3','py')) {
  $exe = Get-Command $c -ErrorAction SilentlyContinue
  if ($exe) {
    $args = if ($c -eq 'py') { @('-3') } else { @() }
    try {
      & $exe.Source @args -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)' 2>$null
      if ($LASTEXITCODE -eq 0) { $py = $exe.Source; $pyArgs = $args; break }
    } catch {}
  }
}
if (-not $py) {
  Err "Airlock needs Python 3.11 or newer. Install it from https://python.org (check 'Add to PATH'), then re-run this."
  exit 1
}
Say ("Using " + (& $py @pyArgs --version))

$pkg = if ($env:AIRLOCK_PACKAGE) { $env:AIRLOCK_PACKAGE } else { 'airlock-agent' }

# --- install: pipx (preferred) -> pip ---------------------------------------
& $py @pyArgs -m pipx --version 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
  Say "Installing $pkg with pipx..."
  & $py @pyArgs -m pipx install $pkg
} else {
  Say "pipx not found - installing $pkg with pip..."
  & $py @pyArgs -m pip install --upgrade $pkg
}

# --- verify + point at the demo ---------------------------------------------
$bin = if (Get-Command airlock -ErrorAction SilentlyContinue) { 'airlock' } else { "$py -m airlock.cli" }

Write-Host ""
Say "Installed. See it stop a key-theft in one command:"
Dim  "    $bin demo"
Write-Host ""
Say "Then wire it into your agents:"
Dim  "    $bin init      # gates Claude Code, Cursor, Windsurf, Cline, Kimi, grok, mimo, DeepSeek..."
Dim  "    $bin doctor    # confirms what is actually enforcing"
Write-Host ""
Dim  "Note on Windows: the core gate runs natively; interactive approval prompts are POSIX-only (use WSL for those)."
