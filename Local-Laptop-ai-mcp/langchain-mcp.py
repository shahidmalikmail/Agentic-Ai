from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent
from langchain_ollama import ChatOllama
import asyncio


async def main():

    # Create MCP client
    client = MultiServerMCPClient(
        {
            "windows-ai": {
                "transport": "stdio",
                "command": "python",
                "args": ["mcp-server.py"],
            }
        }
    )

    # Get tools from MCP server
    tools = await client.get_tools()

    print("Available tools:")

    for tool in tools:
        print(f"- {tool.name}")

    # Create Ollama LLM
    llm = ChatOllama(
        model="minimax-m3:cloud",
        temperature=0.8
    )

    # Create Agent
    agent = create_agent(
        model=llm,
        tools=tools
    )

    # Send question to agent
    response = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "How many folders are in the D drive, excluding subfolders?"
                }
            ]
        }
    )

    # Print final response
    print("\nAI Response:")
    print(response["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())