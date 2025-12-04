#!/bin/bash

# ==============================================================================
# Artifactory AQL Scanner (Shai-Hulud 2.0)
# ==============================================================================
# 1. Fetches Threat Intel from JFrog Research CSV.
# 2. Constructs filenames (name-version.tgz) for each entry.
# 3. Uses Artifactory Query Language (AQL) to find if these files exist.
# ==============================================================================

# --- Configuration ---
ARTIFACTORY_URL=$1
CSV_URL="https://research.jfrog.com/shai_hulud_2_packages.csv"
TEMP_DIR="aql_scan_tmp"
TARGET_LIST="$TEMP_DIR/targets.txt"
REPORT_FILE="aql_scan_report.csv"

# --- Pre-flight Checks ---
# Check if ARTIFACTORY_URL is empty
if [ -z "$1" ]; then
  echo "Error: Environment variable ARTIFACTORY_URL (\$1) is not set."
  echo "Usage: sh rt-aql-scanner.sh 'https://your-artifactory-url.com'"
  exit 1 # Exit with an error status
else
  echo "The ARTIFACTORY_URL (\$1) is: $1"
fi

if [ -z "$rt_token" ]; then
    echo "Error: Environment variable \$rt_token is not set."
    echo "Export it using: export rt_token='your_bearer_token'"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is required for this script."
    exit 1
fi

mkdir -p "$TEMP_DIR"

# ==============================================================================
# Step 1: Fetch and Parse CSV
# ==============================================================================

echo "[1/3] Fetching Threat Intelligence feed..."
echo "      Source: $CSV_URL"

# Download CSV
if curl -sL "$CSV_URL" -o "$TEMP_DIR/feed.csv"; then
    echo "  -> Download successful."
else
    echo "Error: Failed to download CSV."
    exit 1
fi

# Parse CSV:
# Columns: package_name ($1), package_type ($2), versions ($3), xray_ids ($4)
# Logic Update:
# 1. Clean Package Name: Remove quotes and spaces (Keep @ for now to handle scope correctly)
# 2. Clean Versions: Remove quotes, spaces, and square brackets '[]'
awk -F, 'NR>1 { 
    pkg=$1; 
    gsub(/["[:space:]]/, "", pkg);
    # sub(/^@/, "", pkg);     # Removed: We keep the @ so we can see the full scope
    
    # Clean brackets and quotes from Column 3 ($3)
    raw_vers=$3;
    gsub(/[\[\]"[:space:]]/, "", raw_vers); # Remove [ and ] and quotes

    # Split versions by || using regex safe method
    n=split(raw_vers, vers, "[|][|]");
    for(i=1; i<=n; i++) {
        v=vers[i];
        if(pkg != "" && v != "") print pkg, v
    }
}' "$TEMP_DIR/feed.csv" | sort | uniq > "$TARGET_LIST"

TOTAL_TARGETS=$(wc -l < "$TARGET_LIST")
echo "  -> List Prepared. Found $TOTAL_TARGETS potential files to search."

# ==============================================================================
# Step 2: Query Artifactory using AQL
# ==============================================================================

echo "[2/3] Searching Artifactory via AQL..."
echo "Package,Version,Filename,Status,Repo,Path" > "$REPORT_FILE"

COUNTER=0
while read -r pkg_name pkg_version; do
    COUNTER=$((COUNTER+1))
    
    # Construct Filename
    # Logic: 
    # 1. If scoped (@scope/pkg), remove everything up to the last slash to get 'pkg'.
    # 2. If normal (pkg), it stays 'pkg'.
    # Example: @accordproject/concerto-analysis -> concerto-analysis
    
    BASE_NAME="${pkg_name##*/}"
    FILE_NAME="${BASE_NAME}-${pkg_version}.tgz"

    # Progress bar effect
    printf "\rScanning [%s/%s]: %s                   " "$COUNTER" "$TOTAL_TARGETS" "$FILE_NAME"

    # Construct AQL Query
    # We search for items where the name equals our calculated filename
    AQL_QUERY="items.find({\"name\":{\"\$eq\":\"$FILE_NAME\"}})"

    # Execute API Call
    RESPONSE=$(curl -s -X POST "$ARTIFACTORY_URL/artifactory/api/search/aql" \
      -H "Authorization: Bearer $rt_token" \
      -H "Content-Type: text/plain" \
      -d "$AQL_QUERY")

    # Parse Response using jq
    # AQL returns { "results": [ ... ] }
    MATCH_COUNT=$(echo "$RESPONSE" | jq '.results | length')
    
    if [ "$MATCH_COUNT" -gt 0 ] 2>/dev/null; then
        echo ""
        echo "  [!] FOUND: $FILE_NAME"
        
        # Extract repo and path for the report
        echo "$RESPONSE" | jq -r --arg pkg "$pkg_name" --arg ver "$pkg_version" --arg fn "$FILE_NAME" \
            '.results[] | "\($pkg),\($ver),\($fn),FOUND,\(.repo),\(.path)"' >> "$REPORT_FILE"
    else
        echo "$pkg_name,$pkg_version,$FILE_NAME,NOT_FOUND,," >> "$REPORT_FILE"
    fi
    
done < "$TARGET_LIST"

echo "" 
echo "[3/3] Scan Complete."
echo "----------------------------------------------------"
grep ",FOUND," "$REPORT_FILE"
echo "----------------------------------------------------"
echo "Report saved to: $REPORT_FILE"

# Cleanup
rm -rf "$TEMP_DIR"