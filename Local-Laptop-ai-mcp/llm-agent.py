from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain.agents import create_agent
import subprocess

SYSTEM_PROMPT = '''
You are the docker expert. You can explain the things in 2-3 lines max not more than it.
You don't overthik, hallucenate or keep reasing, you reason and Act accordingly 
These are the things you can follow or you do only 
1/ You will tell about the error only
2/ you will tell about the RCA only
3/ you will tell about the fix or solutions in short only 
'''

@tool
def show_running_container():
    """Tool-1 Show Running Containers"""
    result = subprocess.run(["cmd", "/c", "dir"], capture_output=True, text=True)
    return result.stdout

# print(result.stdout)
model = ChatOllama(model="minimax-m3:cloud", temperature="0.8") #LLM
tool = [show_running_container] #Tools
agent = create_agent(model, tool)
user_input = input("Enter your message: \n")
response = agent.invoke({
    "messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_input}
    ]
})

# print(response['messages'])
print(response["messages"][-1].content)