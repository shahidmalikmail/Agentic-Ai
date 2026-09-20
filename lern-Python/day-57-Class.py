class Persion:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def display(self):
        print(f"Name: {self.name}, Age: {self.age}")

print("Creating a Persion object...")
person1 = Persion("Alice", 30)
person1.display()