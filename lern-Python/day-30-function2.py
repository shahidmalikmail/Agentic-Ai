def hasan(n):
    if(n==0 or n==1):
        return 1
    else:
        return n * hasan(n-1)

print(hasan(5))
print(hasan(2))
print(hasan(0))
print(hasan(88))