import sys
import os
import json
import re
import urllib.request

tool_matrix = {
    "codeql": {
        "repo": "github/codeql-action",
        "patterns": [r"codeql-bundle-win64\.tar\.gz$", r"codeql-bundle-win64\.zip$"],
    },
    "tfsec": {
        "repo": "aquasecurity/tfsec",
        "patterns": [r"tfsec-windows-amd64(?:\.exe)?$"],
    },
    "gitleaks": {
        "repo": "gitleaks/gitleaks",
        "patterns": [r"gitleaks_.*_windows_x64\.zip$"],
    },
    "trufflehog": {
        "repo": "trufflesecurity/trufflehog",
        "patterns": [r"trufflehog_.*_windows_amd64\.tar\.gz$", r"trufflehog_.*_windows_amd64\.zip$"],
    },
    "osv-scanner": {
        "repo": "google/osv-scanner",
        "patterns": [r"osv-scanner_.*_windows_amd64(?:\.exe)?(?:\.zip)?$", r"osv-scanner-windows-amd64(?:\.exe)?$"],
    },
}

def check_tools():
    for tool_name, cfg in tool_matrix.items():
        repo = cfg["repo"]
        patterns = cfg["patterns"]
        try:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{repo}/releases/latest",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "python-check-script"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                release = json.load(resp)
            
            assets = [a["name"] for a in release.get("assets", [])]
            match_found = False
            for pattern in patterns:
                regex = re.compile(pattern)
                for asset in assets:
                    if regex.search(asset):
                        print(f"{tool_name}: PASS (Matched asset: {asset})")
                        match_found = True
                        break
                if match_found:
                    break
            
            if not match_found:
                print(f"{tool_name}: FAIL (No asset matched patterns)")
                # Print available assets for debugging if call fails
                # print(f"  Available: {assets[:3]}...") 
                
        except Exception as e:
            print(f"{tool_name}: FAIL (Error: {e})")

if __name__ == "__main__":
    check_tools()
