param(
  [string]$SourcePath = "smartflow-ui/src-tauri/icons/brand/proxyduck-icon-source.png",
  [string]$PngPath = "smartflow-ui/src-tauri/icons/icon.png",
  [string]$IcoPath = "smartflow-ui/src-tauri/icons/icon.ico",
  [string]$UiAssetPath = "smartflow-ui/dist/assets/app-icon.png"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sourceFullPath = Join-Path $root $SourcePath
$pngFullPath = Join-Path $root $PngPath
$icoFullPath = Join-Path $root $IcoPath
$uiAssetFullPath = Join-Path $root $UiAssetPath
$tempDir = Join-Path $root "target/icon-build"

if (!(Test-Path -LiteralPath $sourceFullPath)) {
  throw "ProxyDuck icon source not found: $sourceFullPath"
}

Add-Type -AssemblyName System.Drawing

function Export-SquarePng {
  param(
    [string]$InputPath,
    [string]$OutputPath,
    [int]$Size
  )

  $source = [System.Drawing.Image]::FromFile($InputPath)
  $bitmap = New-Object System.Drawing.Bitmap $Size, $Size
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

  try {
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.DrawImage($source, 0, 0, $Size, $Size)
    $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
  }
  finally {
    $graphics.Dispose()
    $bitmap.Dispose()
    $source.Dispose()
  }
}

New-Item -ItemType Directory -Force (Split-Path $pngFullPath -Parent) | Out-Null
New-Item -ItemType Directory -Force (Split-Path $icoFullPath -Parent) | Out-Null
New-Item -ItemType Directory -Force (Split-Path $uiAssetFullPath -Parent) | Out-Null
New-Item -ItemType Directory -Force $tempDir | Out-Null

Export-SquarePng -InputPath $sourceFullPath -OutputPath $pngFullPath -Size 512
Export-SquarePng -InputPath $sourceFullPath -OutputPath $uiAssetFullPath -Size 128

$iconSizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$scaledPngs = @()
foreach ($iconSize in $iconSizes) {
  $scaledPath = Join-Path $tempDir "proxyduck-$iconSize.png"
  Export-SquarePng -InputPath $sourceFullPath -OutputPath $scaledPath -Size $iconSize
  $scaledPngs += $scaledPath
}

$nodeScript = @"
import fs from 'fs';
import pngToIco from 'png-to-ico';

const [, outPath, ...images] = process.argv;
const buffer = await pngToIco(images);
fs.writeFileSync(outPath, buffer);
"@

node --input-type=module -e $nodeScript $icoFullPath @scaledPngs
if ($LASTEXITCODE -ne 0) {
  throw "PNG to ICO conversion failed"
}

Write-Host "[ProxyDuck] Generated brand icon assets:"
Write-Host "  Source: $sourceFullPath"
Write-Host "  PNG:    $pngFullPath"
Write-Host "  ICO:    $icoFullPath"
Write-Host "  UI:     $uiAssetFullPath"
