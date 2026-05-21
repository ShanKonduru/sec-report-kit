# MCP Add Workspace Filesystem Scripts — Usage Guide

This document explains how to use the provided scripts to add any local folder (such as this repository) to your Docker Desktop MCP Toolkit profile as a filesystem server.

---

## Scripts Overview

- **mcp_add_workspace_filesystem.bat** — For Windows (cmd/PowerShell)
- **mcp_add_workspace_filesystem.sh** — For Linux, macOS, or Git Bash (Windows)

Both scripts automate:
- Adding the MCP filesystem server to your chosen profile (if not already present)
- Setting the allowed path(s) for the server to the folder you specify

---

## Prerequisites

- **Docker Desktop** must be installed and running
- **Docker MCP Toolkit** must be available in your PATH (the `docker mcp` command should work)
- You should have an existing MCP profile (e.g., `shan_s_mcp_hub`)

---

## Usage

### Windows (cmd/PowerShell)

```bat
scripts\mcp_add_workspace_filesystem.bat [profile] [folder]
```
- `profile` (optional): MCP profile name (default: `shan_s_mcp_hub`)
- `folder` (optional): Path to the folder to allow (default: parent of scripts folder)

**Example:**
```bat
scripts\mcp_add_workspace_filesystem.bat shan_s_mcp_hub C:\MyProjects\sec-report-kit
```

### Linux/macOS/Git Bash

```sh
./scripts/mcp_add_workspace_filesystem.sh [profile] [folder]
```
- `profile` (optional): MCP profile name (default: `shan_s_mcp_hub`)
- `folder` (optional): Path to the folder to allow (default: parent of scripts folder)

**Example:**
```sh
./scripts/mcp_add_workspace_filesystem.sh shan_s_mcp_hub /c/MyProjects/sec-report-kit
```

---

## What the Scripts Do

1. **Add the filesystem server** to your MCP profile (if not already present)
2. **Set the allowed path** for the server to the folder you specify
3. **Print the current allowed paths** for verification

---

## How to Use the MCP Server in Docker

1. **Start Docker Desktop**
2. **Start the MCP Gateway** with your profile:
   ```
   docker mcp gateway start --profile shan_s_mcp_hub
   ```
3. **Use MCP-compatible tools/clients** to interact with your workspace via the filesystem server (e.g., list files, read/write, etc.)
   - Example: List files
     ```
     docker mcp client call filesystem.list_directory --profile shan_s_mcp_hub --args path="C:\\MyProjects\\sec-report-kit"
     ```
4. **Stop the gateway** when done:
   ```
   docker mcp gateway stop
   ```

---

## Troubleshooting

- Ensure Docker Desktop is running and healthy
- Ensure `docker mcp` commands work in your terminal
- If you see permission errors, check that the folder path is correct and accessible
- You can run the script multiple times for different folders or profiles

---

## Notes

- The scripts are idempotent: running them again with the same arguments is safe
- You can add multiple folders by editing the profile config or running the script for each folder
- For advanced usage, see `docker mcp profile --help` and `docker mcp profile server add --help`

---

## Committing the Scripts

Be sure to commit both scripts and this help document to your repository:
- `scripts/mcp_add_workspace_filesystem.bat`
- `scripts/mcp_add_workspace_filesystem.sh`
- `scripts/mcp_add_workspace_filesystem_help.md`

---

For further help, see the official Docker MCP Toolkit documentation or ask your AI assistant.
