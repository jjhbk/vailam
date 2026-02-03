import json
import asyncio
from secure_llm import secure_llm_call
from mcp_client import MCPClient

SYSTEM_PROMPT = """
You are an MCP agent.

You MUST follow these rules strictly:

1. You may respond with EXACTLY ONE JSON object.
2. The JSON must be ONE of the following forms:

TOOL CALL:
{
  "tool": "<tool_name>",
  "arguments": { ... }
}

FINAL ANSWER:
{
  "final": "<text>"
}

3. NEVER include both "tool" and "final".
4. NEVER guess or fabricate tool results.
5. After calling a tool, WAIT for its result before responding.
6. If a tool is required, you MUST call it.
7. If no tool is required, return a final answer.

Violating these rules is a critical error.
"""


async def run_agent_step(user_prompt, context):

    async with MCPClient(
        "python",
        ["-u", "../tools/mcp_fs.py"],
    ) as mcp:

        tools = await mcp.list_tools()

        prompt = f"""{SYSTEM_PROMPT}

Available tools:
{json.dumps([t.name for t in tools], indent=2)}

User request:
{user_prompt}
"""

        while True:
            raw = secure_llm_call(prompt, context)
            msg = json.loads(raw)

            if "tool" in msg:
                result = await mcp.call_tool(
                    msg["tool"],
                    msg.get("arguments", {}),
                )

                prompt = f"""
Tool `{msg["tool"]}` returned:

{json.dumps(result.structuredContent or {}, indent=2)}

Continue.
"""
                continue

            return msg
