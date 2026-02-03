# tools/mcp_fs.py
from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("filesystem", json_response=True)


@mcp.tool()
def list_files(path: str = ".") -> list[str]:
    return os.listdir(path)


@mcp.tool()
def read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()


if __name__ == "__main__":
    # 🚨 MUST be stdio
    mcp.run(transport="stdio")
