#!/bin/bash
# Ingest all sample logs into ULPF
API_URL="http://localhost:8000"

echo "Ingesting sample logs to ULPF at $API_URL..."

FILES=(
  "cisco_asa.log|fw-perimeter-01"
  "palo_alto.log|pa-dmz-01"
  "fortinet.log|fgt-branch-01"
  "cef_sample.log|siem-collector-01"
  "syslog_rfc3164.log|siem-collector-01"
  "json_sample.log|siem-collector-01"
  "mixed.log|siem-collector-01"
)

for item in "${FILES[@]}"; do
  file="${item%%|*}"
  source_id="${item##*|}"
  filepath="../sample_logs/$file"
  
  if [ -f "$filepath" ]; then
    echo "Processing $file (Source: $source_id)..."
    
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip empty lines
      [ -z "$line" ] && continue
      
      # Escape quotes for JSON payload
      escaped_line=$(echo "$line" | sed 's/"/\\"/g')
      
      curl -s -X POST "$API_URL/api/ingest" \
        -H "Content-Type: application/json" \
        -d "{\"source_id\": \"$source_id\", \"raw_log\": \"$escaped_line\"}" > /dev/null
    done < "$filepath"
    
    echo "  -> Done processing $file"
  else
    echo "Warning: File $filepath not found."
  fi
done

echo "Ingestion complete!"
