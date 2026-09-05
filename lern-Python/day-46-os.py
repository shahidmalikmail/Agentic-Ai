import os

# if not os.path.exists("data"):
#     os.mkdir("data")

# for i in range(0, 100):
#     os.mkdir(f"data/Day{i+1}")
# for i in range(0, 100):
#     os.rename(f"data/Class{i+1}", f"data/Class-{i+1}")
folder = os.listdir("data")
print(folder)
for i in folder:
    print(os.listdir(f"data/{i}"))
# os.rmdir("data")
# os.removedirs("data")

