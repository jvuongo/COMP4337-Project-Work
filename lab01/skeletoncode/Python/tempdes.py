import binascii
from Crypto.Cipher import DES
from Crypto import Random
import sys
import time

# Get Key
# key: actual key to use, represented as a string comprised only out
# of hexadecimal digits.
def get_key(key):
    try:
        test = int(key, 16)
    except ValueError:
        print("Error: key must be 16 characters")
        exit(1)
    
    new_key = binascii.unhexlify(key)
    return new_key

# Get IV
# the actual IV to use, represented as a string comprised only
# out of hexadecimal digits
def get_IV(iv):
    try:
        test_iv = int(iv, 16)
    except ValueError:
        print("Error: iv must be only contain hexadecimal digits")
        exit(1)

    iv_bytestr = binascii.unhexlify(iv)
    return iv_bytestr

# Method to read a file
def get_file(inputFile):
    with open(inputFile) as f:
        a = f.read()
    return a

# Method to encrypt a message
# If the encoded message is not a multiple of 8 bytes, we append a null character to the original message
# and re-encode it until the length of the encoded message is a multiple of 8 bytes
def des_encrypt(msg, cbc_key, iv):
    new_msg = msg.encode('utf-8')
    while len(new_msg) % 8 != 0:
        msg+='\0'
        new_msg = msg.encode('utf-8')
    cipher = DES.new(cbc_key, DES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(new_msg)
    return cipher_text

# Method to decrypt a message
def des_decrypt(cipher_text, cbc_key, iv):
    cipher = DES.new(cbc_key, DES.MODE_CBC, iv)      
    decrypted_text = cipher.decrypt(cipher_text)
    decoded_text = decrypted_text.decode('utf-8')

    return decoded_text

if __name__ == '__main__':

	#- IV  = fedcba9876543210 (Hexadecimal values)
    #- Key = 40fedf386da13d57 (Hexadecimal values)

    #Need to check if the args is correct
    if (len(sys.argv) != 5):
        # Print error message                      0       0          1     2      3          4
        print("ArgumentError: Use tempdes.py as follow: python3 tempdes.py [iv] [key] [inputfile] [outputfile]")
        exit(1)

    # iv = get_IV(sys.argv[1])
    # key = get_key(sys.argv[2])

    # Take in inputs for iv, cbc key, input file and output file
    iv = str(sys.argv[1])
    iv = get_IV(iv)

    cbc_key = str(sys.argv[2])
    cbc_key = get_key(sys.argv[2])

    plain_text = get_file(sys.argv[3])

    dest_file = sys.argv[4]

    start1 = time.time()
    cipher_text = des_encrypt(plain_text, cbc_key, iv)
    cipher_time = time.time()-start1

    start2 = time.time()
    decrypted_text = des_decrypt(cipher_text, cbc_key, iv)
    decrypt_time = time.time()-start2
    #print(f'Plain text is: {plain_text}')
    #print(f'Cipher text is: {cipher_text}')
    #print(f'Decrypted text is: {decrypted_text}')
    print("Encrypt time: ", cipher_time * 1000000)
    print("Decrypt time: ", decrypt_time * 1000000)

    #Writes the encrypted message to an external file
    with open(dest_file,"wb") as external_file:
        external_file.write(cipher_text)
        external_file.close()