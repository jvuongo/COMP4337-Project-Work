#Following code reads its source file and computes an HMAC signature for it:
import hashlib
import hmac
import sys 
import time

# Method to print time
def print_time(encrypt_time):
    print("Encrypt time: ", encrypt_time * 1000000)

# A digestmod was needed for it to work, since according to the library, it says its required and can't be empty
# https://docs.python.org/3/library/hmac.html
secret_key = 'secret-shared-key-goes-here'.encode('utf-8')
digest_maker = hmac.new(secret_key, digestmod=hashlib.md5)#in your code replace key

# f = open('lorem.txt', 'rb')
f = open(sys.argv[1], 'rb')
try:
    while True:
        block = f.read(1024)
        if not block:
            break
        digest_maker.update(block)
finally:
    f.close()

start1 = time.time()
digest = digest_maker.hexdigest()
encrypt_time = time.time() - start1
print('='*100)
print(f"HMAC digest generated for \"{sys.argv[1]}\" file is:", digest)
print_time(encrypt_time)
print('='*100)
