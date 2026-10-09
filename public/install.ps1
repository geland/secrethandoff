# Installs the secrethandoff binary for AI agents into your user profile,
# then installs the agent plugin in Claude Code and Codex if they are on PATH.
# No administrator rights are needed.
#
#   irm https://secrethandoff.com/install.ps1 | iex
#
# Settings: $env:SECRETHANDOFF_VERSION (default: latest),
# $env:SECRETHANDOFF_REPO (default: geland/secrethandoff),
# $env:SECRETHANDOFF_BIN_DIR (default: LocalAppData\Programs\secrethandoff),
# $env:SECRETHANDOFF_NO_SETUP=1 (install the binary only),
# $env:SECRETHANDOFF_MARKETPLACE (plugin source for setup: owner/repo or a folder).
$ErrorActionPreference = 'Stop'

$repo = if ($env:SECRETHANDOFF_REPO) { $env:SECRETHANDOFF_REPO } else { 'geland/secrethandoff' }
$version = if ($env:SECRETHANDOFF_VERSION) { $env:SECRETHANDOFF_VERSION } else { 'latest' }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw "Unsupported CPU: $env:PROCESSOR_ARCHITECTURE" } }

if ($version -eq 'latest') {
  $tag = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
  if ($tag -notmatch '^cli-v([0-9.]+)$') { throw 'Could not find the latest release.' }
  $version = $Matches[1]
}
$base = if ($env:SECRETHANDOFF_DOWNLOAD_URL) { $env:SECRETHANDOFF_DOWNLOAD_URL } else { "https://github.com/$repo/releases/download/cli-v$version" }
$name = "secrethandoff_${version}_windows_$arch.zip"

$work = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work | Out-Null
try {
  Invoke-WebRequest "$base/$name" -OutFile (Join-Path $work $name) -UseBasicParsing
  Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $work 'SHA256SUMS') -UseBasicParsing
  $line = Get-Content (Join-Path $work 'SHA256SUMS') | Where-Object { ($_ -split '\s+')[1] -eq $name }
  if (-not $line) { throw "$name is not listed in SHA256SUMS." }
  $expected = ($line -split '\s+')[0]
  $actual = (Get-FileHash (Join-Path $work $name) -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected) { throw "Checksum mismatch for $name. Nothing was installed." }

  Expand-Archive (Join-Path $work $name) -DestinationPath $work -Force
  # The binary owns installation, user PATH, and agent setup on every OS.
  $setupArgs = @('setup', '--no-init')
  if ($env:SECRETHANDOFF_BIN_DIR) { $setupArgs += @('--bin-dir', $env:SECRETHANDOFF_BIN_DIR) }
  if ($env:SECRETHANDOFF_NO_SETUP) { $setupArgs += '--binary-only' }
  if ($env:SECRETHANDOFF_MARKETPLACE) { $setupArgs += @('--marketplace', $env:SECRETHANDOFF_MARKETPLACE) }
  & (Join-Path $work 'secrethandoff.exe') @setupArgs
  if ($LASTEXITCODE -ne 0) { throw "Secret Handoff setup needs attention (exit $LASTEXITCODE). Review the checks above." }

} finally {
  Remove-Item -Recurse -Force $work
}
