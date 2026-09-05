import shahid
shahid.wellcome()
def wellcome():
    print("Welcome to the main script!")

if __name__ == "__main__":
    print("This script is being run directly.")
else:
    print("This script is being imported as a module.") 
print(__name__)
# print(dir(wellcome))
print(dir(shahid))