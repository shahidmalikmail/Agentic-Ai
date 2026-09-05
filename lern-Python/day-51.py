with open("myfile.txt", "w") as f:
    f.write("Hello, World!")
    f.truncate(5)  # Truncate the file to the first 5 characters
with open("myfile.txt", "r") as f:  
    text = f.read()
    # f.truncate(2)
    print(text)
