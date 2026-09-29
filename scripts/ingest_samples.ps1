# ULPF Sample Log Ingest Script (PowerShell)
# Usage: .\scripts\ingest_samples.ps1
# Ingests all sample logs from sample_logs/ into the running ULPF instance

param(
    [string]$ApiBase = "http://localhost:8000"
)

$API = "$ApiBase/api/ingest"
$total = 0
$ok = 0
$failed = 0

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  ULPF Sample Log Ingest Script" -ForegroundColor Cyan
Write-Host "  Target: $API" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Check API is reachable
try {
    $health = Invoke-RestMethod -Uri "$ApiBase/api/health/ready" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "[OK] API is reachable" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Cannot reach API at $ApiBase. Is the server running?" -ForegroundColor Red
    Write-Host "  Start with: cd backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000"
    exit 1
}

$files = @(
    @{path="sample_logs\cisco_asa.log";      source="fw-perimeter-01";    ip="192.168.1.1";   desc="Cisco ASA Firewall"},
    @{path="sample_logs\palo_alto.log";      source="pa-dmz-01";          ip="192.168.1.2";   desc="Palo Alto NGFW"},
    @{path="sample_logs\fortinet.log";       source="fgt-branch-01";      ip="10.10.1.1";     desc="FortiGate Firewall"},
    @{path="sample_logs\cef_sample.log";     source="siem-collector-01";  ip="10.0.0.50";     desc="CEF Format Logs"},
    @{path="sample_logs\syslog_rfc3164.log"; source="router-core-01";     ip="10.0.0.1";      desc="Syslog RFC3164"},
    @{path="sample_logs\json_sample.log";    source="app-server-01";      ip="192.168.1.50";  desc="JSON Format Logs"},
    @{path="sample_logs\mixed.log";          source="mixed-source-01";    ip="0.0.0.0";       desc="Mixed Format Logs"}
)

foreach ($f in $files) {
    $fullPath = Resolve-Path $f.path -ErrorAction SilentlyContinue
    if (-not $fullPath) {
        Write-Host "[SKIP] File not found: $($f.path)" -ForegroundColor Yellow
        continue
    }

    [string[]]$lines = [System.IO.File]::ReadAllLines($fullPath)
    $fileOk = 0

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -eq "" -or $trimmed.StartsWith("#")) { continue }
        $total++
        try {
            $body = [ordered]@{
                raw_log   = $trimmed
                source_id = $f.source
                source_ip = $f.ip
            } | ConvertTo-Json -Compress

            $r = Invoke-RestMethod -Uri $API -Method POST -Body $body -ContentType "application/json" -ErrorAction Stop
            $ok++
            $fileOk++
        } catch {
            $failed++
            Write-Host "  [FAIL] $($_.Exception.Message.Substring(0, [Math]::Min(100, $_.Exception.Message.Length)))" -ForegroundColor Red
        }
    }

    Write-Host "  [$($f.desc)] $($f.source): $fileOk lines ingested" -ForegroundColor Green
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  INGEST COMPLETE" -ForegroundColor Cyan
Write-Host "  Total processed : $total" -ForegroundColor White
Write-Host "  Succeeded       : $ok" -ForegroundColor Green
Write-Host "  Failed          : $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "==================================================" -ForegroundColor Cyan

# Show final stats
try {
    $stats = Invoke-RestMethod -Uri "$ApiBase/api/stats" -Method GET
    Write-Host ""
    Write-Host "  DB Total Events : $($stats.total_events)" -ForegroundColor White
    Write-Host "  Active Sources  : $($stats.sources.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Events by outcome:" -ForegroundColor White
    $stats.events_by_outcome.PSObject.Properties | ForEach-Object {
        Write-Host "    $($_.Name): $($_.Value)"
    }
    Write-Host ""
    Write-Host "  Open the dashboard: $ApiBase" -ForegroundColor Cyan
} catch {}
