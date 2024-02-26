from ecdsa import ECDH, VerifyingKey, SECP112r1
from ecdsa.util import randrange

# Need to import ECDSA
# pip install ecdsa

# Use SECP112r1 because it's the elliptic curve algorithm 

# Creating shared secret key
def create_sharedsecret_key(ecdh, key):
    vk = VerifyingKey.from_string(key, curve=SECP112r1)
    ecdh.load_received_public_key(vk)
    secret = ecdh.generate_sharedsecret_bytes() 
    return secret

# Generate 16 byte EphID
def generate_ephID_public_key(ecdh):
    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()
    public_key_str = public_key.to_string("compressed")
    return public_key_str
    
# Generate ephID curve
def generate_ephID_ECDH():
    curve = SECP112r1
    return ECDH(curve)
