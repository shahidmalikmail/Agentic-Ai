"""
Lightweight LangChain MCP test client.

Connects to mcp-server.py over stdio, lists every discovered tool, then
asks a local Ollama model a simple diagnostic question to exercise the
tool-calling path end to end. Requires Ollama running locally with the
model below pulled (or edit MODEL_NAME to one you have).
"""

import asyncio

from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_ollama import ChatOllama

MODEL_NAME = "minimax-m3:cloud"


async def main():
    client = MultiServerMCPClient(
        {
            "windows-ai": {
                "transport": "stdio",
                "command": "python",
                "args": ["mcp-server.py"],
            }
        }
    )

    tools = await client.get_tools()

    print(f"Discovered {len(tools)} tools:")
    for tool in tools:
        print(f"- {tool.name}")

    llm = ChatOllama(model=MODEL_NAME, temperature=0.2)
    agent = create_agent(model=llm, tools=tools)

    response = await agent.ainvoke(
        {
            "messages": [
                {"role": "user", "content": "What is the current CPU and memory usage on this laptop?"}
            ]
        }
    )

    print("\nAI Response:")
    print(response["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
