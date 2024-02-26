from Crypto.Cipher import AES
from Crypto import Random
import sys
import time

def get_file(inputFile):
    with open(inputFile) as f:
        a = f.read()
    return a

def print_time(encrypt_time, decrypt_time):
    print("Encrypt time: ", encrypt_time * 1000000)
    print("Decrypt time: ", decrypt_time * 1000000)

cbc_key = Random.get_random_bytes(16)
print('=' * 100)
print('Key used: ', [x for x in cbc_key])

iv = Random.get_random_bytes(16)
print("IV used: ", [x for x in iv])
print('=' * 100)
aes1 = AES.new(cbc_key, AES.MODE_CBC, iv)
aes2 = AES.new(cbc_key, AES.MODE_CBC, iv)

# plain_text = 'hello world 1234'.encode('utf-8')  # <- 16 bytes
plain_text = get_file(sys.argv[1])
#print("Plaintext is: ", plain_text)

enc_text = plain_text.encode('utf-8')
while len(enc_text) % 16 != 0:
    plain_text += '\0'
    enc_text = plain_text.encode('utf-8')

# cipher_text = aes1.encrypt(plain_text)
start1 = time.time()
cipher_text = aes1.encrypt(enc_text)
encrypt_time = time.time() - start1
#print("Ciphertext is: ", cipher_text)

start2 = time.time()
msg = aes2.decrypt(cipher_text)
decrypt_time = time.time() - start2
msg = msg.decode('utf-8')
#print("Decrypted message: ", msg)
print_time(encrypt_time, decrypt_time)
print('=' * 100)
