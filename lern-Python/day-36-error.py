a = input("Enter your number: ")
print(f"multiplication table of {a} is: ")

try:
    for i in range(1, 11):
        print(f"{int(a)} X {i} = {int(a)*i}")

except Exception as e:
    print(e)
except:
    print("Invalid Data , Please correct your data")


print("Program is ran successfully")
print("Program ended")