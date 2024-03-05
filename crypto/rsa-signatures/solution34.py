import hashlib
from math import ceil
import random
import sympy
import os

def generate_rsa_keypair():
    # Generate two prime numbers p and q using a cryptographically secure random number generator
    # Adjusted for 3072-bit RSA moduli, each prime should be approximately 1536 bits
    bytes_per_prime = 1536 // 8  # 192 bytes
    random_bits_p = os.urandom(bytes_per_prime)
    random_bits_q = os.urandom(bytes_per_prime)
    p = sympy.nextprime(int.from_bytes(random_bits_p, byteorder='big'))
    q = sympy.nextprime(int.from_bytes(random_bits_q, byteorder='big'))
    
    # Ensure p and q are distinct
    while p == q:
        random_bits_q = os.urandom(bytes_per_prime)
        q = sympy.nextprime(int.from_bytes(random_bits_q, byteorder='big'))
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose an integer e such that e and phi(n) are coprime
    e = 65537
    
    # Compute d, the mod inverse of e
    d = pow(e, -1, phi)
    
    # Return the public and private keys
    # Public key is (n, e) and private key is (n, d)
    return (n, e), (n, d)

def i2osp(i, length):
    return i.to_bytes(length, byteorder='big')

def os2ip(os):
    return int.from_bytes(os, 'big')

def mgf1(mgfSeed, maskLen, hash_func=hashlib.sha256):
    hLen = hash_func().digest_size
    T = b""
    for counter in range(ceil(maskLen / hLen)):
        C = counter.to_bytes(4, byteorder='big')
        T += hash_func(mgfSeed + C).digest()
    return T[:maskLen]

def emsa_pss_encode(M, emBits, sLen=32, hash_func=hashlib.sha256, mgf=mgf1):
    emLen = ceil(emBits / 8)
    mHash = hash_func(M).digest()
    hLen = hash_func().digest_size
    if emLen < hLen + sLen + 2:
        raise ValueError("Encoding Error")
    
    salt = os.urandom(sLen)
    M_prime = b'\x00'*8 + mHash + salt
    H = hash_func(M_prime).digest()
    PS = b'\x00' * (emLen - sLen - hLen - 2)
    DB = PS + b'\x01' + salt
    dbMask = mgf(H, emLen - hLen - 1, hash_func)
    maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))
    bitsToZero = 8 * emLen - emBits
    if bitsToZero:
        maskedDB = (maskedDB[0] & (0xFF >> bitsToZero)) .to_bytes(1, 'big') + maskedDB[1:]
    EM = maskedDB + H + b'\xbc'
    return EM

def emsa_pss_verify(M, EM, emBits, sLen=32, hash_func=hashlib.sha256, mgf=mgf1):
    emLen = ceil(emBits / 8)
    
    hLen = hash_func().digest_size
    # Step 1: Length checking for the message against hash function limitation
    if len(M) > (2**256 - 1):
        print("inconsistent 1")
        ValueError("length check fail")
    if len(EM) != emLen:
        raise ValueError("Inconsistent message length")
    #
    mHash = hash_func(M).digest()

    # Step 3: Check if emLen is less than expected
    if emLen < hLen + sLen + 2:
        print("inconsistent 3")
        return "inconsistent"

    #Step 4 check rightmost ocetet
    if EM[-1] != 0xbc:
        return False
    
    # Step 5: Split EM into maskedDB and H
    maskedDB = EM[:emLen-hLen-1]
    H = EM[emLen-hLen-1:-1]
    # Step 6: Check the leftmost 8emLen - emBits bits
    if maskedDB[0] & (0xFF >> (emBits % 8)) != 0:
        print("inconsistent 6")
        return "inconsistent"
    #Step 7 & 8 generating dbmask and compute db.
    dbMask = mgf(H, emLen - hLen - 1, hash_func)
    # Step 9: Set leftmost bits of DB to zero
    DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))
    if DB[0] & (0xFF >> (8*emLen - emBits)):
        return False
    # Step 10: Check the padding in DB
    PS = DB[:emLen - hLen - sLen - 2]
    if PS != b'\x00' * (emLen - hLen - sLen - 2):
        return False
    if DB[emLen - hLen - sLen - 2] != 1:
        return False
    # Step 11: Extract the salt from DB
    salt = DB[-sLen:]
    # Step 12 & 13: Compute H' and compare with H
    M_prime = b'\x00'*8 + mHash + salt
    H_prime = hash_func(M_prime).digest()
    #And check if H matches H'
    return H == H_prime

def rsa_verify(public_key, message, signature, emBits):
    n, e = public_key
    s = os2ip(signature)
    k = len(signature)
     # Step 1: Length checking
    if len(signature) != k:
        print("invalid signature length")
        return "invalid signature"
    # Step 2: RSA verification
    if s >= n:
        return False
    m = pow(s, e, n)
    EM = i2osp(m, ceil(emBits / 8))
    # Step 3: EMSA-PSS verification
    return emsa_pss_verify(message, EM, emBits)

def rsa_sign(private_key, message, emBits):
    n, d = private_key
    m = os2ip(message)
    k = len(message)
    # Step 1: Length checking
    if len(message) != k:
        print("invalid message length")
        return "invalid message"
    # Step 2: RSA signing
    if m >= n:
        return False
    s = pow(m, d, n)
    signature = i2osp(s, ceil(emBits / 8))
    return signature

# Generate an RSA keypair
public_key, private_key = generate_rsa_keypair()

# Example message
message = b"Hello, world!"

# Encode the message
emBits = public_key[0].bit_length() - 1
encoded_message = emsa_pss_encode(message, emBits)

# Simulate signing by encrypting with the private key
s = os2ip(encoded_message)
signature = pow(s, private_key[1], private_key[0])
signature_bytes = i2osp(signature, ceil(emBits / 8))

# Sign the message
signature = rsa_sign(private_key, encoded_message, emBits)

# Verify the signature
#valid_signature = rsa_verify(public_key, message, signature_bytes, emBits)
valid_signature = rsa_verify(public_key, message, signature, emBits)
print("result",valid_signature)
