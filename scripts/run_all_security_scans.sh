#!/bin/bash

# Master script to run all security scans one by one
# Each scan launches in a new terminal window (for GUI systems)
# Opens the consolidated HTML report at the end

set -e  # Exit on error

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPTS_DIR")"
REPORT_DIR="$PROJECT_ROOT/security_reports"

cd "$PROJECT_ROOT"
mkdir -p "$REPORT_DIR"

echo ""
echo "========================================"
echo "Running All Security Scans"
echo "========================================"
echo ""

# Function to run a scan and render its report
run_scan_and_render() {
    local scan_name=$1
    local scan_script="run_${scan_name}.sh"
    local render_script="render_${scan_name}_html.sh"
    
    if [ ! -f "$SCRIPTS_DIR/$scan_script" ]; then
        echo "WARNING: $scan_script not found, skipping..."
        return
    fi
    
    echo "Starting: $scan_name scan..."
        bash "$SCRIPTS_DIR/$scan_script" "$REPORT_DIR/" "$PROJECT_ROOT" || echo "WARNING: $scan_script failed"
    echo "Completed: $scan_name scan"
    
    if [ -f "$SCRIPTS_DIR/$render_script" ]; then
        echo "Rendering: $scan_name report..."
            bash "$SCRIPTS_DIR/$render_script" "$REPORT_DIR/" "$PROJECT_ROOT" || echo "WARNING: $render_script failed"
        echo "Completed: $scan_name report"
    fi
    echo ""
}

# Run all security scans
run_scan_and_render "bandit"
run_scan_and_render "checkov"
run_scan_and_render "codeql"
run_scan_and_render "gitleaks"
run_scan_and_render "osv_scanner"
run_scan_and_render "pip_audit"
run_scan_and_render "safety"
run_scan_and_render "semgrep"
run_scan_and_render "tfsec"
run_scan_and_render "trivy"
run_scan_and_render "trufflehog"

# Generate consolidated report
echo ""
echo "========================================"
echo "Generating Consolidated Report"
echo "========================================"
echo ""

if [ -f "$SCRIPTS_DIR/render_consolidated_html.sh" ]; then
    echo "Rendering: Consolidated Security Report"
    bash "$SCRIPTS_DIR/render_consolidated_html.sh" "$REPORT_DIR" "$PROJECT_ROOT" || echo "WARNING: Consolidated report generation failed"
    echo "Completed: Consolidated Report"
    echo ""
fi

# Open the consolidated HTML report
CONSOLIDATED_REPORT="$REPORT_DIR/consolidated-security-report.html"

if [ -f "$CONSOLIDATED_REPORT" ]; then
    echo ""
    echo "========================================"
    echo "Opening Consolidated Security Report"
    echo "========================================"
    echo ""
    
    # Try different methods to open the report based on the OS
    if command -v xdg-open &> /dev/null; then
        # Linux
        xdg-open "$CONSOLIDATED_REPORT"
    elif command -v open &> /dev/null; then
        # macOS
        open "$CONSOLIDATED_REPORT"
    else
        echo "Could not automatically open report. Please open manually:"
        echo "$CONSOLIDATED_REPORT"
    fi
    
    echo "Report opened"
else
    echo ""
    echo "WARNING: Consolidated report not found at: $CONSOLIDATED_REPORT"
fi

echo ""
echo "========================================"
echo "All Security Scans Complete"
echo "========================================"
echo ""
