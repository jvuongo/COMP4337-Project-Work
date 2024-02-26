import Crypto
# from ssl import _Cipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import ast
import sys
import time

# Method to read a file
def  get_file(inputFile):
    with open(inputFile) as f:
        a = f.read()
    return a

# Method to track time
def print_time(encrypt_time, decrypt_time):
    print("Encrypt time: ", encrypt_time * 1000000)
    print("Decrypt time: ", decrypt_time * 1000000)

random_generator = Random.new().read
key = RSA.generate(1024, random_generator)  # generate pub and priv key

publickey = key.publickey()  # pub key export for exchange
print('=' * 100)
# plain_text = 'abcdefghijklmnopqrst'
plain_text = get_file(sys.argv[1])
enc_text = plain_text.encode('utf-8')
#print("Plaintext is: ", plain_text)
# enc_text = plain_text.encode('utf-8')
# print

encryptor = PKCS1_OAEP.new(publickey)
start1 = time.time()
cipher_text = encryptor.encrypt(enc_text)
encrypt_time = time.time() - start1
# cipher_text = publickey.encrypt(plain_text, 32)  # message to encrypt is in the above line 'encrypt this message'
#print('Plaintext encrypted using Public Key is:', cipher_text)
# print
# decrypted code below
# decrypted = key.decrypt(ast.literal_eval(str(cipher_text)))
decryptor = PKCS1_OAEP.new(key)
start2 = time.time()
decrypted = decryptor.decrypt(ast.literal_eval(str(cipher_text)))
decrypt_time = time.time()-start2
print_time(encrypt_time, decrypt_time)
decoded_text = decrypted.decode('utf-8')
#print('Ciphertext decrypted with Private key is', decoded_text)
print('=' * 100)
