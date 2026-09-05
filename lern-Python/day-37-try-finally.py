# try:
#     m = [1, 5, 9, 10]
#     n = int(input("enter the index: "))
#     print(m[n])
# except:
#     print("There is some error")
# finally:
#     print("I am always executed")
# #####################################
def func1():
    try:
        m = [1, 5, 9, 10]
        n = int(input("enter the index: "))
        print(m[n])
        return 200
    except:
        print("There is some error")
        return 503
    finally:
        print("I am always executed")
x = func1()
print(x)