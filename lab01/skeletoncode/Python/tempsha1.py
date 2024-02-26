import hashlib
import sys
import time

# Method to read a file
def get_file(inputFile):
    with open(inputFile) as f:
        a = f.read()
    return a

def print_time(encrypt_time):
    print("Encrypt time: ", encrypt_time * 1000000)

#initializing string
print('='*100)
# str = "SHA1 Clear text"
str = get_file(sys.argv[1])

start1 = time.time()
result = hashlib.sha1(str.encode()) 
encrypt_time = time.time() - start1

# printing the equivalent hexadecimal value. 
print("The hexadecimal equivalent of SHA1 digest is : ") 
print(result.hexdigest())
print_time(encrypt_time)
print('='*100)
