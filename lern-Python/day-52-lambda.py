def double(x):
    return x * 2
double_lambda = lambda x: x * 2
print(double(5))  # Output: 10
print(double_lambda(5))  # Output: 10

cube = lambda x: x ** 3
print(cube(3))  # Output: 27    
average = lambda x, y, z: (x + y + z) / 3
print(average(10, 20, 30))  # Output: 20.0
