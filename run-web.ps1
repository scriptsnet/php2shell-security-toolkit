$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root "dist\PHP2ShellScanner-Web.exe"
if (Test-Path -LiteralPath $exe) {
    & $exe @args
} else {
    & python (Join-Path $root "web_app.py") @args
}
