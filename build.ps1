$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
$build = Join-Path $root "build"
$webSrc = (Resolve-Path (Join-Path $root "web")).Path
$dirs = @(
    $dist,
    $build,
    (Join-Path $build "pc-work"),
    (Join-Path $build "pc-spec"),
    (Join-Path $build "web-work"),
    (Join-Path $build "web-spec")
)
New-Item -ItemType Directory -Force -Path $dirs | Out-Null

Push-Location $root
try {
    pyinstaller --noconfirm --onefile --windowed `
        --name PHP2ShellScanner-PC `
        --distpath $dist `
        --workpath (Join-Path $build "pc-work") `
        --specpath (Join-Path $build "pc-spec") `
        pc_app.py
    if ($LASTEXITCODE -ne 0) { throw "PC build failed with exit code $LASTEXITCODE" }

    pyinstaller --noconfirm --onefile --console `
        --name PHP2ShellScanner-Web `
        --add-data "$webSrc;web" `
        --distpath $dist `
        --workpath (Join-Path $build "web-work") `
        --specpath (Join-Path $build "web-spec") `
        web_app.py
    if ($LASTEXITCODE -ne 0) { throw "Web build failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

Get-ChildItem -LiteralPath $dist -Filter "PHP2ShellScanner-*.exe" |
    Select-Object Name, Length, LastWriteTime
