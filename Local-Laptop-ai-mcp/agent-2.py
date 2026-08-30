import ollama

print("=" * 50)
print("🤖 AI DevOps Assistant")
print("Type 'exit' to quit")
print("=" * 50)

while True:

    content = input("\nYou: ")

    # Exit condition
    if content.lower() == "exit":
        print("Goodbye!")
        break

    # Send question to Ollama
    response = ollama.chat(
        model="minimax-m3:cloud",
        messages=[
            {
                "role": "user",
                "content": content
            }
        ]
    )

    print("\nAI:", response["message"]["content"])