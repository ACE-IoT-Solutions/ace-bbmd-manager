# BBMD Manager

[![PyPI version](https://badge.fury.io/py/ace-bbmd-manager.svg)](https://pypi.org/project/ace-bbmd-manager/)
[![Container Image](https://ghcr-badge.egpl.dev/ace-iot-solutions/ace-bbmd-manager/size)](https://github.com/ACE-IoT-Solutions/ace-bbmd-manager/pkgs/container/ace-bbmd-manager)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A CLI tool for managing BACnet BBMD (BACnet Broadcast Management Device) Broadcast Distribution Tables with full audit logging and rollback capability.

## Features

- **Network Discovery**: Walk BBMD networks to discover topology
- **BDT Management**: Read and write Broadcast Distribution Table entries
- **Link Operations**: Add or delete links (unidirectional or bidirectional)
- **Audit Logging**: Full audit trail persisted to JSON
- **Rollback**: Snapshot-based rollback system to undo changes
- **Safe Operations**: Detailed change preview and confirmation before any mutation
- **Async Architecture**: Built on bacpypes3 with modern async/await patterns

## Installation

```bash
# Install from PyPI
pip install ace-bbmd-manager

# Or install with uv
uv pip install ace-bbmd-manager
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/ACE-IoT-Solutions/ace-bbmd-manager.git
cd ace-bbmd-manager

# Install with uv
uv sync

# Or install with pip in editable mode
pip install -e .
```

## Quick Start

```bash
# Set your local IP address (the interface to use for BACnet communication)
export BBMD_LOCAL_ADDRESS=192.168.1.100

# Discover the BBMD network starting from a known BBMD
bbmd-manager walk 192.168.1.1

# View the discovered network
bbmd-manager status

# View all links
bbmd-manager links
```

## Commands

### Network Discovery

#### `walk`
Walk the BBMD network starting from one or more seed addresses. Discovers all reachable BBMDs by following BDT entries.

```bash
bbmd-manager -l 192.168.1.100 walk 192.168.1.1
bbmd-manager -l 192.168.1.100 walk 192.168.1.1 192.168.1.2 --depth 5
```

#### `read`
Read the BDT from a single BBMD.

```bash
bbmd-manager -l 192.168.1.100 read 192.168.1.1
```

### Network Status

#### `status`
Show the cached network state with all BBMDs and their BDT entries.

```bash
bbmd-manager status
bbmd-manager status --format json
```

#### `links`
Display all links in the network, indicating which are bidirectional.

```bash
bbmd-manager links
```

### Link Management

#### `add-link`
Add a link from one BBMD to another. Shows a detailed preview of changes before applying.

```bash
# Add unidirectional link: A -> B
bbmd-manager -l 192.168.1.100 add-link 192.168.1.1 192.168.1.2

# Add bidirectional link: A <-> B
bbmd-manager -l 192.168.1.100 add-link 192.168.1.1 192.168.1.2 --bidirectional

# Skip confirmation prompt
bbmd-manager -l 192.168.1.100 add-link 192.168.1.1 192.168.1.2 -b -y
```

#### `delete-link`
Delete a link between BBMDs. Shows a detailed preview of changes before applying.

```bash
# Delete unidirectional link: A -> B
bbmd-manager -l 192.168.1.100 delete-link 192.168.1.1 192.168.1.2

# Delete bidirectional link: A <-> B and B <-> A
bbmd-manager -l 192.168.1.100 delete-link 192.168.1.1 192.168.1.2 --bidirectional
```

#### `delete-bbmd`
Remove a BBMD from the network entirely. This removes it from all other BBMDs' BDTs and clears its own BDT.

```bash
bbmd-manager -l 192.168.1.100 delete-bbmd 192.168.1.3
```

### Audit & Rollback

#### `audit`
View the audit log of all operations.

```bash
bbmd-manager audit
bbmd-manager audit --limit 50
bbmd-manager audit --action add_link
bbmd-manager audit --bbmd 192.168.1.1:47808
```

#### `snapshots`
List available snapshots for rollback.

```bash
bbmd-manager snapshots
bbmd-manager snapshots --limit 5
```

#### `diff`
Show differences between a snapshot and the current state.

```bash
bbmd-manager diff <snapshot-id>
```

#### `rewind`
Restore the network to a previous snapshot state.

```bash
# Preview what would change (dry run)
bbmd-manager rewind <snapshot-id> --dry-run

# Apply the rewind
bbmd-manager -l 192.168.1.100 rewind <snapshot-id>
```

### Utility Commands

#### `clear-state`
Clear the cached network state (does not affect actual BBMDs).

```bash
bbmd-manager clear-state
```

#### `clear-history`
Clear audit log and/or snapshots.

```bash
bbmd-manager clear-history        # Clear audit log only
bbmd-manager clear-history --all  # Clear audit log and snapshots
```

## Global Options

| Option | Environment Variable | Description |
|--------|---------------------|-------------|
| `-l, --local-address` | `BBMD_LOCAL_ADDRESS` | Local IP address for BACnet communication |
| `-s, --state-file` | | Path to state file (default: `.bbmd_state.json`) |
| `-a, --audit-file` | | Path to audit log file (default: `.bbmd_audit.json`) |
| `--snapshot-file` | | Path to snapshots file (default: `.bbmd_snapshots.json`) |
| `-v, --verbose` | | Enable verbose output |
| `-d, --debug` | | Enable debug output for BACnet protocol |

### Local Address Resolution

The local address is resolved in the following order of precedence:
1. `-l, --local-address` command line option
2. `BBMD_LOCAL_ADDRESS` environment variable
3. `address` field from `BACpypes.ini` in the current working directory

If you have a `BACpypes.ini` file (standard BACpypes configuration), the tool will automatically use the address from it:

```ini
[BACpypes]
address: 192.168.1.100/24
```

The CIDR suffix (e.g., `/24`) is automatically stripped when reading from the INI file.

## Example Workflow

```bash
# 1. Discover the network
bbmd-manager -l 10.0.0.100 walk 10.0.0.1

# 2. View current topology
bbmd-manager status
bbmd-manager links

# 3. Add a new BBMD to the network (bidirectional links to existing BBMD)
bbmd-manager -l 10.0.0.100 add-link 10.0.0.1 10.0.0.99 --bidirectional
# Review the proposed changes, then confirm

# 4. Oops! Need to undo that change
bbmd-manager snapshots  # Find the snapshot ID
bbmd-manager -l 10.0.0.100 rewind <snapshot-id>

# 5. Remove a BBMD from the network
bbmd-manager -l 10.0.0.100 delete-bbmd 10.0.0.50
# Review the proposed changes, then confirm
```

## Change Preview

All mutation commands show a detailed preview before making changes:

```
============================================================
PROPOSED CHANGES
============================================================

BBMD: 192.168.1.1:47808
  Action: Add entry -> 192.168.1.99:47808
  Current BDT: 192.168.1.2, 192.168.1.3
  New BDT:     192.168.1.2, 192.168.1.3, 192.168.1.99:47808

BBMD: 192.168.1.99:47808
  Action: Add entry -> 192.168.1.1:47808
  Current BDT: (empty)
  New BDT:     192.168.1.1:47808

============================================================
Total BBMDs to modify: 2
============================================================

Proceed with these changes? [y/N]:
```

## State Files

The tool maintains three JSON files for persistence:

| File | Description |
|------|-------------|
| `.bbmd_state.json` | Cached network topology |
| `.bbmd_audit.json` | Audit log of all operations |
| `.bbmd_snapshots.json` | Snapshots for rollback |

These files are created in the current working directory by default.

## Development

```bash
# Install dev dependencies
uv sync

# Run tests
pytest tests/ -v

# Run with debug output
bbmd-manager -l 192.168.1.100 -d read 192.168.1.1
```

## Docker

A container image is available on GitHub Container Registry, built on `python:3.12-alpine` with `uv` for fast startup.

### Quick Start

```bash
# Pull the latest image
docker pull ghcr.io/ace-iot-solutions/ace-bbmd-manager:latest

# Or pull a specific version
docker pull ghcr.io/ace-iot-solutions/ace-bbmd-manager:0.3.5
```

### Running Commands

```bash
# Run with host networking (required for BACnet UDP)
docker run --rm --network host \
  -v $(pwd):/data \
  ghcr.io/ace-iot-solutions/ace-bbmd-manager:latest \
  -l 192.168.1.100 walk 192.168.1.1

# View status from cached state
docker run --rm -v $(pwd):/data \
  ghcr.io/ace-iot-solutions/ace-bbmd-manager:latest status

# Add a bidirectional link
docker run --rm --network host \
  -v $(pwd):/data \
  ghcr.io/ace-iot-solutions/ace-bbmd-manager:latest \
  -l 192.168.1.100 add-link 192.168.1.1 192.168.1.2 -b -y
```

### Shell Alias

For convenience, add an alias to your shell configuration:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias bbmd-manager='docker run --rm --network host -v $(pwd):/data ghcr.io/ace-iot-solutions/ace-bbmd-manager:latest'

# Then use normally
bbmd-manager -l 192.168.1.100 walk 192.168.1.1
bbmd-manager status
```

### Networking Note

Host networking (`--network host`) is typically required for BACnet communication since it uses UDP port 47808 for broadcast messages. The `-v $(pwd):/data` mount persists state files (`.bbmd_state.json`, `.bbmd_audit.json`, `.bbmd_snapshots.json`) to your current directory.

## Requirements

- Python 3.8+
- bacpypes3 (BACnet protocol library)
- click (CLI framework)

## License

MIT
