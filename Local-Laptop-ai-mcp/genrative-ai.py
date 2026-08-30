import ollama
SYSTEM_PROMPT = '''
You are the docker expert. You can explain the things in 2-3 lines max not more than it.
You don't overthik, hallucenate or keep reasing, you reason and Act accordingly 
These are the things you can follow or you do only 
1/ You will tell about the error only
2/ you will tell about the RCA only
3/ you will tell about the fix or solutions in short only 
'''
while True:
    user_input = input("Enter your message:\n")
    if user_input == "exit":
        print("Thank you so much to used Shahid AI")
        break
    response = ollama.chat(
        model = "minimax-m3:cloud",
        messages = [{'role': 'system', 'content': SYSTEM_PROMPT,}, {
            'role': 'user',
            'content': user_input
         }]
    )
    print(response['message']['content'])
