param(
  [string]$PngPath = "smartflow-ui/src-tauri/icons/icon.png",
  [string]$IcoPath = "smartflow-ui/src-tauri/icons/icon.ico"
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pngFullPath = Join-Path $root $PngPath
$icoFullPath = Join-Path $root $IcoPath
$tempDir = Join-Path $root "target/icon-build"

Add-Type -AssemblyName System.Drawing

function New-RoundedRectanglePath {
  param(
    [float]$X,
    [float]$Y,
    [float]$Width,
    [float]$Height,
    [float]$Radius
  )

  $diameter = $Radius * 2
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $path.AddArc($X, $Y, $diameter, $diameter, 180, 90)
  $path.AddArc($X + $Width - $diameter, $Y, $diameter, $diameter, 270, 90)
  $path.AddArc($X + $Width - $diameter, $Y + $Height - $diameter, $diameter, $diameter, 0, 90)
  $path.AddArc($X, $Y + $Height - $diameter, $diameter, $diameter, 90, 90)
  $path.CloseFigure()
  return $path
}

New-Item -ItemType Directory -Force (Split-Path $pngFullPath -Parent) | Out-Null
New-Item -ItemType Directory -Force (Split-Path $icoFullPath -Parent) | Out-Null
New-Item -ItemType Directory -Force $tempDir | Out-Null

$size = 512
$bitmap = New-Object System.Drawing.Bitmap $size, $size
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)

try {
  $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
  $graphics.Clear([System.Drawing.Color]::Transparent)

  $backgroundPath = New-RoundedRectanglePath 36 36 440 440 112
  $backgroundBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    ([System.Drawing.PointF]::new(64, 64)),
    ([System.Drawing.PointF]::new(448, 448)),
    ([System.Drawing.Color]::FromArgb(255, 13, 54, 89)),
    ([System.Drawing.Color]::FromArgb(255, 19, 164, 154))
  )
  $graphics.FillPath($backgroundBrush, $backgroundPath)

  $glowBrush = New-Object System.Drawing.Drawing2D.PathGradientBrush($backgroundPath)
  $glowBrush.CenterColor = [System.Drawing.Color]::FromArgb(120, 255, 255, 255)
  $glowBrush.SurroundColors = [System.Drawing.Color[]]@([System.Drawing.Color]::FromArgb(0, 255, 255, 255))
  $graphics.FillPath($glowBrush, $backgroundPath)

  $ringPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(52, 255, 255, 255), 8)
  $graphics.DrawPath($ringPen, $backgroundPath)

  $flowShadow = New-Object System.Drawing.Drawing2D.GraphicsPath
  $flowShadow.AddBezier(150, 122, 302, 42, 382, 172, 258, 222)
  $flowShadow.AddBezier(258, 222, 126, 280, 166, 422, 358, 378)
  $shadowPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(70, 8, 30, 48), 114)
  $shadowPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
  $shadowPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
  $shadowPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
  $graphics.DrawPath($shadowPen, $flowShadow)

  $flowPath = New-Object System.Drawing.Drawing2D.GraphicsPath
  $flowPath.AddBezier(142, 112, 294, 32, 374, 162, 250, 212)
  $flowPath.AddBezier(250, 212, 118, 270, 158, 412, 350, 368)

  $basePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 248, 252, 255), 92)
  $basePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
  $basePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
  $basePen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
  $graphics.DrawPath($basePen, $flowPath)

  $accentPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 123, 240, 221), 28)
  $accentPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
  $accentPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
  $accentPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
  $graphics.DrawPath($accentPen, $flowPath)

  $nodeBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 255, 187, 92))
  $nodeGlowBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(96, 255, 233, 185))
  $graphics.FillEllipse($nodeGlowBrush, 324, 90, 72, 72)
  $graphics.FillEllipse($nodeBrush, 336, 102, 48, 48)
  $graphics.FillEllipse($nodeGlowBrush, 112, 336, 72, 72)
  $graphics.FillEllipse($nodeBrush, 124, 348, 48, 48)

  $bitmap.Save($pngFullPath, [System.Drawing.Imaging.ImageFormat]::Png)
}
finally {
  $graphics.Dispose()
  $bitmap.Dispose()
  if ($backgroundBrush) { $backgroundBrush.Dispose() }
  if ($glowBrush) { $glowBrush.Dispose() }
  if ($ringPen) { $ringPen.Dispose() }
  if ($flowShadow) { $flowShadow.Dispose() }
  if ($shadowPen) { $shadowPen.Dispose() }
  if ($flowPath) { $flowPath.Dispose() }
  if ($basePen) { $basePen.Dispose() }
  if ($accentPen) { $accentPen.Dispose() }
  if ($nodeBrush) { $nodeBrush.Dispose() }
  if ($nodeGlowBrush) { $nodeGlowBrush.Dispose() }
  if ($backgroundPath) { $backgroundPath.Dispose() }
}

$iconSizes = 16, 24, 32, 48, 64, 128, 256
$scaledPngs = @()

foreach ($iconSize in $iconSizes) {
  $scaledPath = Join-Path $tempDir "icon-$iconSize.png"
  $scaledBitmap = New-Object System.Drawing.Bitmap $iconSize, $iconSize
  $scaledGraphics = [System.Drawing.Graphics]::FromImage($scaledBitmap)
  $sourceImage = [System.Drawing.Image]::FromFile($pngFullPath)

  try {
    $scaledGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $scaledGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $scaledGraphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $scaledGraphics.DrawImage(
      $sourceImage,
      0,
      0,
      $iconSize,
      $iconSize
    )
    $scaledBitmap.Save($scaledPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $scaledPngs += $scaledPath
  }
  finally {
    if ($sourceImage) { $sourceImage.Dispose() }
    $scaledGraphics.Dispose()
    $scaledBitmap.Dispose()
  }
}

$nodeScript = @"
import fs from 'fs';
import pngToIco from 'png-to-ico';

(async () => {
  const [, outPath, ...images] = process.argv;
  const buffer = await pngToIco(images);
  fs.writeFileSync(outPath, buffer);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
"@

node --input-type=module -e $nodeScript $icoFullPath @scaledPngs
if ($LASTEXITCODE -ne 0) {
  throw "png-to-ico conversion failed"
}

Write-Host "[SmartFlow] Generated icon assets:"
Write-Host "  PNG: $pngFullPath"
Write-Host "  ICO: $icoFullPath"
