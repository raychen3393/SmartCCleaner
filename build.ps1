$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path $projectRoot "src"
$testDir = Join-Path $projectRoot "tests"
$assetsDir = Join-Path $projectRoot "assets"
$distDir = Join-Path $projectRoot "dist"
$testBuildDir = Join-Path $projectRoot "build\tests"
$shareStageDir = Join-Path $projectRoot "build\share_stage"

New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
New-Item -ItemType Directory -Force -Path $testBuildDir | Out-Null

# Clean legacy test executable out of dist\ if present
$legacyDistTest = Join-Path $distDir "SmartCCleaner.Tests.exe"
if (Test-Path $legacyDistTest) {
    Remove-Item -Force $legacyDistTest
}

$fw = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
$csc = Join-Path $fw "csc.exe"
$wpf = Join-Path $fw "WPF"

Add-Type -AssemblyName System.Drawing

function New-RoundedBadgeIcon {
    param(
        [string]$OutputPath,
        [System.Drawing.Color]$Color1,
        [System.Drawing.Color]$Color2,
        [string]$Glyph,
        [bool]$DrawShieldCorner
    )
    $bmp = New-Object System.Drawing.Bitmap 64, 64
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::Transparent)

    $rect = New-Object System.Drawing.Rectangle 4, 4, 56, 56
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $r = 16
    $path.AddArc($rect.X, $rect.Y, $r, $r, 180, 90)
    $path.AddArc($rect.Right - $r, $rect.Y, $r, $r, 270, 90)
    $path.AddArc($rect.Right - $r, $rect.Bottom - $r, $r, $r, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $r, $r, $r, 90, 90)
    $path.CloseFigure()

    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $Color1, $Color2, 45.0)
    $g.FillPath($grad, $path)

    $font = New-Object System.Drawing.Font("Segoe UI", 30, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString($Glyph, $font, [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF 4, 4, 56, 56), $sf)

    if ($DrawShieldCorner) {
        # Small subtle shield accent in bottom-right corner
        $sb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(245, 255, 255, 255))
        $g.FillEllipse($sb, 41, 41, 18, 18)
        $inner = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 220, 38, 38))
        $g.FillEllipse($inner, 44, 44, 12, 12)
    } else {
        $sparkBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 255, 255, 255))
        $g.FillEllipse($sparkBrush, 45, 12, 8, 8)
    }

    $hIcon = $bmp.GetHicon()
    $icon = [System.Drawing.Icon]::FromHandle($hIcon)
    $fs = New-Object System.IO.FileStream($OutputPath, [System.IO.FileMode]::Create)
    $icon.Save($fs)
    $fs.Close()
    $icon.Dispose()
    $g.Dispose()
    $bmp.Dispose()
}

# 1. Generate app.ico and uninstall.ico
$appIconPath = Join-Path $assetsDir "app.ico"
$uninstallIconPath = Join-Path $assetsDir "uninstall.ico"

New-RoundedBadgeIcon -OutputPath $appIconPath `
    -Color1 ([System.Drawing.Color]::FromArgb(255, 37, 99, 235)) `
    -Color2 ([System.Drawing.Color]::FromArgb(255, 16, 185, 129)) `
    -Glyph "C" -DrawShieldCorner $false

New-RoundedBadgeIcon -OutputPath $uninstallIconPath `
    -Color1 ([System.Drawing.Color]::FromArgb(255, 239, 68, 68)) `
    -Color2 ([System.Drawing.Color]::FromArgb(255, 245, 158, 11)) `
    -Glyph "×" -DrawShieldCorner $true

Write-Host "Generated icons: app.ico & uninstall.ico"

# 2. Compile SmartCCleaner.exe (v2.0)
$exePath = Join-Path $distDir "SmartCCleaner.exe"
$manifestPath = Join-Path $srcDir "App.manifest"

$compileArgs = @(
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/utf8output",
    "/out:$exePath",
    "/win32icon:$appIconPath",
    "/win32manifest:$manifestPath",
    "/r:$wpf\PresentationFramework.dll",
    "/r:$wpf\PresentationCore.dll",
    "/r:$wpf\WindowsBase.dll",
    "/r:$fw\System.Xaml.dll",
    "/r:$fw\System.Runtime.Serialization.dll",
    "/r:$fw\System.ServiceProcess.dll",
    "/r:$fw\System.Windows.Forms.dll",
    "/r:$fw\System.Drawing.dll",
    (Join-Path $srcDir "AssemblyInfo.cs"),
    (Join-Path $srcDir "Models.cs"),
    (Join-Path $srcDir "NativeFileScanner.cs"),
    (Join-Path $srcDir "SafetyGuard.cs"),
    (Join-Path $srcDir "RulesEngine.cs"),
    (Join-Path $srcDir "CleanerEngine.cs"),
    (Join-Path $srcDir "UiTheme.cs"),
    (Join-Path $srcDir "MainWindow.cs"),
    (Join-Path $srcDir "App.cs")
)

Write-Host "Compiling SmartCCleaner.exe v2.0..."
& $csc @compileArgs
if ($LASTEXITCODE -ne 0) {
    throw "Compilation of SmartCCleaner.exe failed with exit code $LASTEXITCODE"
}
$exeInfo = Get-Item $exePath
Write-Host ("Built: {0} ({1:N1} KB)" -f $exeInfo.FullName, ($exeInfo.Length / 1KB))

# 3. Compile Uninstall.exe
$uninstallExePath = Join-Path $distDir "Uninstall.exe"
$uninstallManifestPath = Join-Path $srcDir "Uninstaller.manifest"

$uninstallArgs = @(
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/utf8output",
    "/out:$uninstallExePath",
    "/win32icon:$uninstallIconPath",
    "/win32manifest:$uninstallManifestPath",
    "/r:$wpf\PresentationFramework.dll",
    "/r:$wpf\PresentationCore.dll",
    "/r:$wpf\WindowsBase.dll",
    "/r:$fw\System.Xaml.dll",
    "/r:$fw\System.Runtime.Serialization.dll",
    "/r:$fw\System.Drawing.dll",
    (Join-Path $srcDir "UninstallerAssemblyInfo.cs"),
    (Join-Path $srcDir "Models.cs"),
    (Join-Path $srcDir "UiTheme.cs"),
    (Join-Path $srcDir "Uninstaller.cs")
)

Write-Host "Compiling Uninstall.exe..."
& $csc @uninstallArgs
if ($LASTEXITCODE -ne 0) {
    throw "Compilation of Uninstall.exe failed with exit code $LASTEXITCODE"
}
$unInfo = Get-Item $uninstallExePath
Write-Host ("Built: {0} ({1:N1} KB)" -f $unInfo.FullName, ($unInfo.Length / 1KB))

# 4. Build ready-to-share ZIP bundle in dist\
if (Test-Path $shareStageDir) { Remove-Item -Recurse -Force $shareStageDir }
New-Item -ItemType Directory -Force -Path $shareStageDir | Out-Null

Copy-Item $exePath (Join-Path $shareStageDir "SmartCCleaner.exe")
Copy-Item $uninstallExePath (Join-Path $shareStageDir "Uninstall.exe")

$quickGuide = @"
C盘智清 (SmartCCleaner v2.0) 绿色免安装版
================================================

【使用方法】
1. 解压本压缩包到任意目录（例如 D:\C盘智清）。
2. 双击 SmartCCleaner.exe 即可开始自动扫描 C 盘可释放空间。
3. 点击左侧任意清理项可在右侧逐条预览待删文件，并可一键加入白名单。
4. 首次使用建议先勾选「演练模式」试跑一次，核对审计日志后再正式清理。
5. 如需深度清理 Windows 更新缓存，可点击软件右上角「点击提权深度清理」。

【如何卸载】
不再使用时，双击同目录下的 Uninstall.exe，可一键彻底清除主程序、桌面快捷方式及本地配置/日志，无任何残留。

【首次打开提示说明】
由于本工具为个人绿色编译软件，Windows 若弹出蓝色提示「Windows 已保护你的电脑」，点击「更多信息」->「仍要运行」即可。
"@
[System.IO.File]::WriteAllText((Join-Path $shareStageDir "使用说明.txt"), $quickGuide, (New-Object System.Text.UTF8Encoding $true))

$zipPath = Join-Path $distDir "C盘智清_v2.0_绿色分享版.zip"
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($shareStageDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
Remove-Item -Recurse -Force $shareStageDir

$zipInfo = Get-Item $zipPath
Write-Host ("Packaged share bundle: {0} ({1:N1} KB)" -f $zipInfo.FullName, ($zipInfo.Length / 1KB))

# 5. Compile & run automated test suite (isolated in build\tests\)
$testExe = Join-Path $testBuildDir "SmartCCleaner.Tests.exe"
$testArgs = @(
    "/nologo",
    "/target:exe",
    "/utf8output",
    "/out:$testExe",
    "/r:$wpf\PresentationFramework.dll",
    "/r:$wpf\PresentationCore.dll",
    "/r:$wpf\WindowsBase.dll",
    "/r:$fw\System.Xaml.dll",
    "/r:$fw\System.Runtime.Serialization.dll",
    "/r:$fw\System.ServiceProcess.dll",
    "/r:$fw\System.Drawing.dll",
    (Join-Path $srcDir "Models.cs"),
    (Join-Path $srcDir "NativeFileScanner.cs"),
    (Join-Path $srcDir "SafetyGuard.cs"),
    (Join-Path $srcDir "RulesEngine.cs"),
    (Join-Path $srcDir "CleanerEngine.cs"),
    (Join-Path $srcDir "UiTheme.cs"),
    (Join-Path $srcDir "Uninstaller.cs"),
    (Join-Path $testDir "EngineTests.cs"),
    "/main:SmartCCleaner.Tests.EngineTests"
)

Write-Host "Compiling EngineTests (isolated in build\tests\)..."
& $csc @testArgs
if ($LASTEXITCODE -ne 0) {
    throw "Compilation of EngineTests failed with exit code $LASTEXITCODE"
}

Write-Host "Running automated v2.0 safety, engine & uninstaller tests..."
& $testExe
if ($LASTEXITCODE -ne 0) {
    throw "EngineTests failed with exit code $LASTEXITCODE"
}
