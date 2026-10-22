$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root "dist\PHP2ShellScanner-PC.exe"
if (Test-Path -LiteralPath $exe) {
    Start-Process -FilePath $exe
} else {
    & python (Join-Path $root "pc_app.py")
}
