f = open("myfile.txt", "w")
# f.write("""Hello World and I am learning Python and I am enjoying it   
# This is my first file in Python and I am learning it step by step and I will become a good Python developer in future.
# I will learn Python and I will become a good Python developer in future.""")
f.write("Hello this is Test File -1")
f.close()

with open("myfile.txt", "a") as f:
    f.write("\nHello this is Test File -2")
    f.write("\nHello this is Test File -3")

f = open("myfile.txt", "r")
text = f.read()
print(text)
f.close()

h = open("myfile.txt", "r")
text = h.read()
print(text)
h.close()