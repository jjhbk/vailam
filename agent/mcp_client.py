import asyncio

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


class MCPClient:
    def __init__(self, command, args):
        self.params = StdioServerParameters(
            command=command,
            args=args,
        )
        self._session = None

    async def __aenter__(self):
        self._stdio = stdio_client(self.params)
        self._read, self._write = await self._stdio.__aenter__()
        self._session = ClientSession(self._read, self._write)
        await self._session.__aenter__()
        await self._session.initialize()
        return self

    async def __aexit__(self, *args):
        await self._session.__aexit__(*args)
        await self._stdio.__aexit__(*args)

    async def list_tools(self):
        result = await self._session.list_tools()
        return result.tools

    async def call_tool(self, name, arguments):
        result = await self._session.call_tool(name, arguments)
        return result
