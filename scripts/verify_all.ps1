# verify_all.ps1 — Full local verification for moon-httpsig.
#
# Runs fmt check, check/build/test on wasm, wasm-gc, js, and native, the code line
# counter, the RFC fixture generator and verifier, representative CLI smoke
# tests, and every example. Any failure stops the script.

$ErrorActionPreference = "Stop"

# Resolve the project root from the script's own location, so the script works
# from any checkout directory (not only D:\Moonbit\projects\project8).
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project

# Resolve the MoonBit binary: MOON_BIN env var first, then PATH, then a
# Windows-local fallback. Fail loudly if none is available.
function Resolve-Moon {
    if ($env:MOON_BIN -and (Test-Path $env:MOON_BIN)) {
        return $env:MOON_BIN
    }
    $cmd = Get-Command moon -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $fallback = "D:\Moonbit\bin\moon.exe"
    if (Test-Path $fallback) {
        return $fallback
    }
    Write-Error "moon not found. Set MOON_BIN, add moon to PATH, or run on the usual dev machine."
    exit 1
}
$moon = Resolve-Moon

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "command failed with exit code $LASTEXITCODE`: $Program $($Arguments -join ' ')"
    }
}

function Invoke-Smoke {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    $output = & $Program @Arguments
    $exitCode = $LASTEXITCODE
    $output | Write-Host
    if ($exitCode -ne 0 -or -not (($output -join "`n").Contains($Expected))) {
        throw "$Label failed: exit=$exitCode, missing expected text '$Expected'"
    }
}

# Python is taken from PATH.
$python = "python"
$pyCmd = Get-Command $python -ErrorAction SilentlyContinue
if (-not $pyCmd) {
    Write-Error "python not found on PATH; required by scripts\count_code.py and the fixture scripts."
    exit 1
}

Write-Host "== moon clean =="
Invoke-Checked $moon clean

Write-Host "== moon fmt --check =="
Invoke-Checked $moon fmt --check

Write-Host "== moon info =="
Invoke-Checked $moon info

foreach ($target in @("wasm", "wasm-gc", "js", "native")) {
    Write-Host "== target: $target =="
    Invoke-Checked $moon check --target $target --deny-warn
    Invoke-Checked $moon build --target $target
    Invoke-Checked $moon test --target $target --deny-warn
}

Write-Host "== python count_code =="
Invoke-Checked $python scripts\count_code.py

Write-Host "== python generate_rfc_fixtures =="
Invoke-Checked $python scripts\generate_rfc_fixtures.py

Write-Host "== python verify_rfc_fixtures =="
Invoke-Checked $python scripts\verify_rfc_fixtures.py

Write-Host "== CLI smoke tests =="
Invoke-Smoke -Label "CLI help" -Program $moon -Arguments @("run", "cmd/httpsig-tool", "help") -Expected '"help"'
Invoke-Smoke -Label "CLI version" -Program $moon -Arguments @("run", "cmd/httpsig-tool", "version") -Expected '"version":"0.1.1"'
Invoke-Smoke -Label "CLI parse-signature" -Program $moon -Arguments @("run", "cmd/httpsig-tool", "--", "parse-signature", "--signature", "sig1=:dGVzdA==:") -Expected '"labels":["sig1"]'
Invoke-Smoke -Label "CLI sign-hmac" -Program $moon -Arguments @("run", "cmd/httpsig-tool", "--", "sign-hmac", "--method", "POST", "--path", "/foo", "--header", "content-type=application/json", "--secret-hex", "736563726574", "--keyid", "k1", "--created", "1700000000", "--component", "@method") -Expected '"signature_input"'
Invoke-Smoke -Label "CLI RFC example" -Program $moon -Arguments @("run", "cmd/httpsig-tool", "--", "rfc-example") -Expected '"match":true'

Write-Host "== examples =="
Invoke-Checked $moon run examples/sign_request
Invoke-Checked $moon run examples/verify_request
Invoke-Checked $moon run examples/sign_response
Invoke-Checked $moon run examples/multiple_signatures
Invoke-Checked $moon run examples/replay_policy
Invoke-Checked $moon run examples/content_digest_binding

Write-Host "== moon package --list =="
Invoke-Checked $moon package --list

Write-Host "All verification steps passed."
