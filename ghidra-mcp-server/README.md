# Ghidra MCP Server

An MCP (Model Context Protocol) server that provides headless binary analysis via Ghidra.

## Features

- **ghidra_analyze**: Import and analyze binary files
- **ghidra_search_strings**: Search for strings in analyzed binaries
- **ghidra_find_functions**: List and search functions
- **ghidra_decompile**: Decompile functions to C-like code
- **ghidra_search_instructions**: Search for instruction patterns
- **ghidra_get_xrefs**: Get cross-references to/from addresses
- **ghidra_run_script**: Run custom Ghidra Python scripts

## Requirements

- Python 3.10+
- Ghidra 11.x installed
- Java 17+ (required by Ghidra)

## Installation

```bash
# Set Ghidra path
export GHIDRA_HOME=~/ghidra/ghidra_11.2.1_PUBLIC

# Install with pip/uv
uv pip install -e .
```

## Usage with Claude Code

Add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "ghidra-mcp-server",
      "env": {
        "GHIDRA_HOME": "/path/to/ghidra"
      }
    }
  }
}
```

## Example Usage

```python
# Analyze a binary
ghidra_analyze(binary_path="/path/to/code.bin", processor="ARM:LE:32:v7")

# Search for strings
ghidra_search_strings(project_name="myproject", pattern="gsp")

# Decompile a function
ghidra_decompile(project_name="myproject", address="0x100000")

# Search for instruction patterns
ghidra_search_instructions(project_name="myproject", pattern="strb.*#0x44")
```

## Environment Variables

- `GHIDRA_HOME`: Path to Ghidra installation (required)
- `GHIDRA_PROJECT_DIR`: Directory for Ghidra projects (default: `/tmp/ghidra-mcp-projects`)

## License

MIT
