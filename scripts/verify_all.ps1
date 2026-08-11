# verify_all.ps1 — Full local verification for moon-httpsig.
#
# Runs fmt check, check/build/test on wasm-gc, js, and native, the code line
# counter, the RFC fixture generator and verifier, a CLI smoke test of every
# subcommand, and every example. Any failure stops the script.

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

# Python is taken from PATH.
$python = "python"
$pyCmd = Get-Command $python -ErrorAction SilentlyContinue
if (-not $pyCmd) {
    Write-Error "python not found on PATH; required by scripts\count_code.py and the fixture scripts."
    exit 1
}

Write-Host "== moon clean =="
& $moon clean

Write-Host "== moon fmt --check =="
& $moon fmt --check

foreach ($target in @("wasm-gc", "js", "native")) {
    Write-Host "== target: $target =="
    & $moon check --target $target
    & $moon build --target $target
    & $moon test --target $target
}

Write-Host "== python count_code =="
& $python scripts\count_code.py

Write-Host "== python generate_rfc_fixtures =="
& $python scripts\generate_rfc_fixtures.py

Write-Host "== python verify_rfc_fixtures =="
& $python scripts\verify_rfc_fixtures.py

Write-Host "== CLI smoke tests =="
& $moon run cmd/httpsig-tool -- --help
& $moon run cmd/httpsig-tool -- --version
& $moon run cmd/httpsig-tool -- parse-input --signature-input 'sig1=("@method" "@target-uri");created=1618884473;keyid="k1"'
& $moon run cmd/httpsig-tool -- parse-signature --signature 'sig1=:dGVzdA==:'
& $moon run cmd/httpsig-tool -- parse-accept --accept-signature 'a=("@method");created;keyid="k"'
& $moon run cmd/httpsig-tool -- build-base --method POST --path /foo --header 'content-type=application/json' --signature-input 'sig1=("@method" "content-type");created=1618884473;keyid="k1";alg="hmac-sha256"'
& $moon run cmd/httpsig-tool -- sign-hmac --method POST --path /foo --header 'content-type=application/json' --secret-hex 736563726574 --keyid k1 --created 1700000000 --component @method
& $moon run cmd/httpsig-tool -- verify-hmac --method POST --path /foo --header 'content-type=application/json' --secret-hex 736563726574 --keyid k1 --now 1700000000 --signature-input 'sig1=("@method");created=1700000000;keyid="k1";alg="hmac-sha256"' --signature 'sig1=:dGVzdA==:'
& $moon run cmd/httpsig-tool -- inspect --signature-input 'sig1=("@method" "content-type");created=1618884473;keyid="k1"'
& $moon run cmd/httpsig-tool -- check-policy --signature-input 'sig1=("@method" "content-type");created=1618884473;keyid="k1"' --required-component @method
& $moon run cmd/httpsig-tool -- rfc-example

Write-Host "== examples =="
& $moon run examples/sign_request
& $moon run examples/verify_request
& $moon run examples/sign_response
& $moon run examples/multiple_signatures
& $moon run examples/replay_policy
& $moon run examples/content_digest_binding

Write-Host "== moon package --list =="
& $moon package --list

Write-Host "All verification steps passed."
