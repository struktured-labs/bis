#!/usr/bin/env python3
"""
Ghidra MCP Server - Provides headless binary analysis via MCP protocol.

Tools:
- analyze_binary: Import and analyze a binary file
- search_strings: Search for strings in analyzed binary
- find_functions: List or search functions
- decompile_function: Decompile a specific function
- search_instructions: Search for instruction patterns
- get_xrefs: Get cross-references to/from an address
- run_script: Run a custom Ghidra script
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Default Ghidra installation path
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", os.path.expanduser("~/ghidra/ghidra_11.2.1_PUBLIC"))
DEFAULT_PROJECT_DIR = os.environ.get("GHIDRA_PROJECT_DIR", "/tmp/ghidra-mcp-projects")

server = Server("ghidra-mcp-server")


def get_analyze_headless():
    """Get path to analyzeHeadless script."""
    return os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")


def run_ghidra_script(project_dir: str, project_name: str, script_content: str,
                      binary_path: str = None, processor: str = "ARM:LE:32:v7",
                      timeout: int = 300) -> tuple[str, str, int]:
    """
    Run a Ghidra script via analyzeHeadless.

    Returns: (stdout, stderr, returncode)
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script_content)
        script_path = f.name

    try:
        cmd = [
            get_analyze_headless(),
            project_dir,
            project_name,
        ]

        if binary_path:
            cmd.extend(["-import", binary_path, "-processor", processor])
        else:
            cmd.extend(["-process", "*"])

        cmd.extend([
            "-scriptPath", os.path.dirname(script_path),
            "-postScript", os.path.basename(script_path),
            "-noanalysis" if not binary_path else "",
        ])

        # Filter empty strings
        cmd = [c for c in cmd if c]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GHIDRA_HOME": GHIDRA_HOME}
        )

        return result.stdout, result.stderr, result.returncode

    finally:
        os.unlink(script_path)


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available Ghidra tools."""
    return [
        Tool(
            name="ghidra_analyze",
            description="Import and analyze a binary file with Ghidra. Returns analysis summary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Absolute path to the binary file to analyze"
                    },
                    "project_name": {
                        "type": "string",
                        "description": "Name for the Ghidra project (default: auto-generated)"
                    },
                    "processor": {
                        "type": "string",
                        "description": "Processor architecture (default: ARM:LE:32:v7)",
                        "default": "ARM:LE:32:v7"
                    }
                },
                "required": ["binary_path"]
            }
        ),
        Tool(
            name="ghidra_search_strings",
            description="Search for strings in an analyzed binary",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the Ghidra project"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "String pattern to search for (case-insensitive)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 50)",
                        "default": 50
                    }
                },
                "required": ["project_name", "pattern"]
            }
        ),
        Tool(
            name="ghidra_find_functions",
            description="List or search functions in analyzed binary",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the Ghidra project"
                    },
                    "name_pattern": {
                        "type": "string",
                        "description": "Function name pattern to search (optional)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 100)",
                        "default": 100
                    }
                },
                "required": ["project_name"]
            }
        ),
        Tool(
            name="ghidra_decompile",
            description="Decompile a function at a given address",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the Ghidra project"
                    },
                    "address": {
                        "type": "string",
                        "description": "Address of function to decompile (hex, e.g., '0x100000')"
                    },
                    "function_name": {
                        "type": "string",
                        "description": "Or specify function by name"
                    }
                },
                "required": ["project_name"]
            }
        ),
        Tool(
            name="ghidra_search_instructions",
            description="Search for instruction patterns (e.g., 'mov r0, #1')",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the Ghidra project"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Instruction pattern to search (e.g., 'strb', 'mov.*#1')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 100)",
                        "default": 100
                    }
                },
                "required": ["project_name", "pattern"]
            }
        ),
        Tool(
            name="ghidra_get_xrefs",
            description="Get cross-references to or from an address",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the Ghidra project"
                    },
                    "address": {
                        "type": "string",
                        "description": "Address to find references for (hex)"
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["to", "from", "both"],
                        "description": "Direction of references (default: both)",
                        "default": "both"
                    }
                },
                "required": ["project_name", "address"]
            }
        ),
        Tool(
            name="ghidra_run_script",
            description="Run a custom Ghidra Python script",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the Ghidra project"
                    },
                    "script": {
                        "type": "string",
                        "description": "Python script content to run in Ghidra"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)",
                        "default": 300
                    }
                },
                "required": ["project_name", "script"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""

    project_dir = DEFAULT_PROJECT_DIR
    os.makedirs(project_dir, exist_ok=True)

    if name == "ghidra_analyze":
        binary_path = arguments["binary_path"]
        project_name = arguments.get("project_name", Path(binary_path).stem)
        processor = arguments.get("processor", "ARM:LE:32:v7")

        script = '''
# Analysis summary script
from ghidra.program.model.listing import CodeUnit

func_count = currentProgram.getFunctionManager().getFunctionCount()
instr_count = currentProgram.getListing().getNumInstructions()
min_addr = currentProgram.getMinAddress()
max_addr = currentProgram.getMaxAddress()

print("ANALYSIS_RESULT_START")
print(f"Binary: {currentProgram.getExecutablePath()}")
print(f"Processor: {currentProgram.getLanguageID()}")
print(f"Address range: {min_addr} - {max_addr}")
print(f"Functions found: {func_count}")
print(f"Instructions: {instr_count}")
print("ANALYSIS_RESULT_END")
'''

        stdout, stderr, rc = run_ghidra_script(
            project_dir, project_name, script,
            binary_path=binary_path, processor=processor,
            timeout=600
        )

        # Extract result
        if "ANALYSIS_RESULT_START" in stdout:
            result = stdout.split("ANALYSIS_RESULT_START")[1].split("ANALYSIS_RESULT_END")[0].strip()
        else:
            result = f"Analysis completed. Return code: {rc}\n\nOutput:\n{stdout[-2000:]}\n\nErrors:\n{stderr[-1000:]}"

        return [TextContent(type="text", text=result)]

    elif name == "ghidra_search_strings":
        project_name = arguments["project_name"]
        pattern = arguments["pattern"]
        limit = arguments.get("limit", 50)

        script = f'''
# String search script
import re
pattern = "{pattern}".lower()
limit = {limit}

results = []
listing = currentProgram.getListing()
data_iter = listing.getDefinedData(True)

for data in data_iter:
    if data.hasStringValue():
        value = data.getValue()
        if value and pattern in str(value).lower():
            results.append(f"{{data.getAddress()}}: {{value}}")
            if len(results) >= limit:
                break

print("STRING_SEARCH_START")
for r in results:
    print(r)
print(f"Found {{len(results)}} matches")
print("STRING_SEARCH_END")
'''

        stdout, stderr, rc = run_ghidra_script(project_dir, project_name, script)

        if "STRING_SEARCH_START" in stdout:
            result = stdout.split("STRING_SEARCH_START")[1].split("STRING_SEARCH_END")[0].strip()
        else:
            result = f"Search failed. RC: {rc}\n{stderr[-500:]}"

        return [TextContent(type="text", text=result)]

    elif name == "ghidra_find_functions":
        project_name = arguments["project_name"]
        name_pattern = arguments.get("name_pattern", "")
        limit = arguments.get("limit", 100)

        script = f'''
# Function finder
import re
pattern = "{name_pattern}".lower()
limit = {limit}

func_mgr = currentProgram.getFunctionManager()
results = []

for func in func_mgr.getFunctions(True):
    name = func.getName()
    if not pattern or pattern in name.lower():
        results.append(f"{{func.getEntryPoint()}}: {{name}}")
        if len(results) >= limit:
            break

print("FUNC_SEARCH_START")
for r in results:
    print(r)
print(f"Total: {{len(results)}}")
print("FUNC_SEARCH_END")
'''

        stdout, stderr, rc = run_ghidra_script(project_dir, project_name, script)

        if "FUNC_SEARCH_START" in stdout:
            result = stdout.split("FUNC_SEARCH_START")[1].split("FUNC_SEARCH_END")[0].strip()
        else:
            result = f"Search failed. RC: {rc}\n{stderr[-500:]}"

        return [TextContent(type="text", text=result)]

    elif name == "ghidra_decompile":
        project_name = arguments["project_name"]
        address = arguments.get("address")
        func_name = arguments.get("function_name")

        if address:
            find_func = f'addr = currentProgram.getAddressFactory().getAddress("{address}")\nfunc = func_mgr.getFunctionContaining(addr)'
        else:
            find_func = f'''
for f in func_mgr.getFunctions(True):
    if f.getName() == "{func_name}":
        func = f
        break
'''

        script = f'''
# Decompiler
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

func_mgr = currentProgram.getFunctionManager()
func = None

{find_func}

if func:
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    result = decomp.decompileFunction(func, 60, monitor)

    print("DECOMPILE_START")
    if result.decompileCompleted():
        print(result.getDecompiledFunction().getC())
    else:
        print(f"Decompilation failed: {{result.getErrorMessage()}}")
    print("DECOMPILE_END")
else:
    print("DECOMPILE_START")
    print("Function not found")
    print("DECOMPILE_END")
'''

        stdout, stderr, rc = run_ghidra_script(project_dir, project_name, script, timeout=120)

        if "DECOMPILE_START" in stdout:
            result = stdout.split("DECOMPILE_START")[1].split("DECOMPILE_END")[0].strip()
        else:
            result = f"Decompile failed. RC: {rc}\n{stderr[-500:]}"

        return [TextContent(type="text", text=result)]

    elif name == "ghidra_search_instructions":
        project_name = arguments["project_name"]
        pattern = arguments["pattern"]
        limit = arguments.get("limit", 100)

        script = f'''
# Instruction search
import re
pattern = re.compile(r"{pattern}", re.IGNORECASE)
limit = {limit}

listing = currentProgram.getListing()
results = []

instr = listing.getInstructionAt(currentProgram.getMinAddress())
while instr and len(results) < limit:
    instr_str = instr.toString()
    if pattern.search(instr_str):
        results.append(f"{{instr.getAddress()}}: {{instr_str}}")
    instr = instr.getNext()

print("INSTR_SEARCH_START")
for r in results:
    print(r)
print(f"Found {{len(results)}} matches")
print("INSTR_SEARCH_END")
'''

        stdout, stderr, rc = run_ghidra_script(project_dir, project_name, script, timeout=300)

        if "INSTR_SEARCH_START" in stdout:
            result = stdout.split("INSTR_SEARCH_START")[1].split("INSTR_SEARCH_END")[0].strip()
        else:
            result = f"Search failed. RC: {rc}\n{stderr[-500:]}"

        return [TextContent(type="text", text=result)]

    elif name == "ghidra_get_xrefs":
        project_name = arguments["project_name"]
        address = arguments["address"]
        direction = arguments.get("direction", "both")

        script = f'''
# XRef finder
addr = currentProgram.getAddressFactory().getAddress("{address}")
ref_mgr = currentProgram.getReferenceManager()

print("XREF_START")
'''
        if direction in ["to", "both"]:
            script += '''
print("References TO this address:")
for ref in ref_mgr.getReferencesTo(addr):
    print(f"  {ref.getFromAddress()} -> {addr} ({ref.getReferenceType()})")
'''
        if direction in ["from", "both"]:
            script += '''
print("References FROM this address:")
for ref in ref_mgr.getReferencesFrom(addr):
    print(f"  {addr} -> {ref.getToAddress()} ({ref.getReferenceType()})")
'''
        script += 'print("XREF_END")'

        stdout, stderr, rc = run_ghidra_script(project_dir, project_name, script)

        if "XREF_START" in stdout:
            result = stdout.split("XREF_START")[1].split("XREF_END")[0].strip()
        else:
            result = f"XRef lookup failed. RC: {rc}\n{stderr[-500:]}"

        return [TextContent(type="text", text=result)]

    elif name == "ghidra_run_script":
        project_name = arguments["project_name"]
        script = arguments["script"]
        timeout = arguments.get("timeout", 300)

        stdout, stderr, rc = run_ghidra_script(project_dir, project_name, script, timeout=timeout)

        return [TextContent(type="text", text=f"Return code: {rc}\n\nOutput:\n{stdout}\n\nErrors:\n{stderr}")]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


def main():
    """Run the MCP server."""
    import sys

    # Verify Ghidra installation
    if not os.path.exists(get_analyze_headless()):
        print(f"Error: Ghidra not found at {GHIDRA_HOME}", file=sys.stderr)
        print("Set GHIDRA_HOME environment variable to your Ghidra installation", file=sys.stderr)
        sys.exit(1)

    asyncio.run(stdio_server(server))


if __name__ == "__main__":
    main()
