import hashlib
from math import ceil
import random
import sympy
import os


# def generate_rsa_keypair(keysize):
#     # Generate two prime numbers p and q
#     p = sympy.nextprime(random.getrandbits(keysize // 2))
#     q = sympy.nextprime(random.getrandbits(keysize // 2))
#     n = p * q
#     phi = (p - 1) * (q - 1)
    

#     # Choose an integer e such that e and phi(n) are coprime
#     e = 65537

#     # Compute d, the mod inverse of e
#     d = pow(e, -1, phi)

#     # Return the public and private keys
#     # Public key is (n, e) and private key is (n, d)
#     return (n, e), (n, d)

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


# Generate an RSA keypair with a very small key size for demonstration purposes
public_key, private_key = generate_rsa_keypair()

def i2osp(i, emLen):
    """Integer to Octet String Primitive"""
    try:
        # Ensure the integer fits in the specified length
        os = i.to_bytes(emLen, byteorder='big')
    except OverflowError:
        return "integer too large"
    return os
def os2ip(os):
    """Octet String to Integer Primitive"""
    return int.from_bytes(os, byteorder='big')

def mgf1(mgfSeed, maskLen, hash_func=hashlib.sha256):
    hLen = hash_func().digest_size
    if maskLen > 2**32 * hLen:
        return "mask too long"
    
    T = b""
    for counter in range(0, -(-maskLen // hLen)):  # Ceiling division to ensure we cover the full maskLen
        C = i2osp(counter, 4)
        T += hash_func(mgfSeed + C).digest()
        print("counter, range", counter, -(-maskLen//hLen))
    
    return T[:maskLen]

def emsa_pss_encode(M, emBits, sLen = 32, maskGenFunc=mgf1, hash=hashlib.sha256):
    print("encode1")
    emLen = ceil(emBits/8)
    mHash = hash(M).digest()
    hLen = len(mHash)
    if emLen < hLen + 2 + 8:
        raise ValueError("encoding error")
    print("encode2")    
    salt = i2osp(random.getrandbits(8*sLen), sLen)
    M_prime = b"\x00"*8 + mHash + salt
    H = hash(M_prime).digest()
    print("encode3")
    assert len(H) == hLen
    PS = b"\x00"*(emLen-sLen-hLen-2)
    DB = PS + b"\x01" + salt
    assert len(DB) == emLen-hLen-1
    print("encode4")
    print("længde" , emLen-hLen-1)
    dbMask = maskGenFunc(H, emLen-hLen-1)
    print("encode5")
    maskedDB = bytes([DB[i] ^ dbMask[i] for i in range (len(dbMask))])
    maskedDB = (maskedDB[0] & (0xff >> (8*emLen - emBits))).to_bytes(1, byteorder='big') + maskedDB[1:]

    EM = maskedDB + H + b"\xbc"
    print("encode6")
    return EM
def emsa_pss_verify(M, EM, emBits, sLen):
    """Verify an RSA-PSS signature."""
    hash_func = hashlib.sha256
    hLen = hash_func().digest_size  # Length of hash output in bytes
    
    # Step 1: Length checking for the message against hash function limitation
    if len(M) > (2**61 - 1):
        print("inconsistent 1")
        return "inconsistent"
    
    # Step 2: Let mHash = Hash(M)
    mHash = hash_func(M).digest()
    
    emLen = -(-emBits // 8)  # Ceiling division to get length in bytes
    
    # Step 3: Check if emLen is less than expected
    if emLen < hLen + sLen + 2:
        print("inconsistent 3")
        return "inconsistent"
    
    # Step 4: Check if the rightmost octet of EM is 0xbc
    if EM[-1] != 0xbc:
        print("inconsistent 4 verify")
        return "inconsistent"
    
    # Step 5: Split EM into maskedDB and H
    maskedDB = EM[:emLen - hLen - 1]
    H = EM[emLen - hLen - 1:-1]
    
    # Step 6: Check the leftmost 8emLen - emBits bits
    if maskedDB[0] & (0xFF >> (emBits % 8)) != 0:
        print("inconsistent 6")
        return "inconsistent"
    
    # Step 7 & 8: Generate dbMask and compute DB
    dbMask = mgf1(H, emLen - hLen - 1)
    DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))
    
    # Step 9: Set leftmost bits of DB to zero
    first_byte_mask = (1 << (8 - emBits % 8)) - 1
    DB = bytes([DB[0] & first_byte_mask]) + DB[1:]
    
    # Step 10: Check the padding in DB
    if DB[:emLen - hLen - sLen - 2] != b'\x00' * (emLen - hLen - sLen - 2) or DB[emLen - hLen - sLen - 2] != 0x01:
        print("inconsistent 10")
        return "inconsistent"
    
    # Step 11: Extract the salt from DB
    salt = DB[-sLen:]
    
    # Step 12 & 13: Compute H' and compare with H
    M_prime = b'\x00'*8 + mHash + salt
    H_prime = hash_func(M_prime).digest()
    
    # Step 14: Check if H matches H'
    if H == H_prime:
        print("consistent 14")
        return "consistent"
    else:
        print("inconsistent 14")
        return "inconsistent"

def verify_signature(public_key, message, signature, modBits):
    n, e = public_key
    k = len(signature)
    
    # Step 1: Length checking
    if len(signature) != k:
        print("invalid signature length")
        return "invalid signature"
    
    # Step 2: RSA verification
    s = os2ip(signature)  # Convert signature to integer
    if s >= n:
        print("invalid signature step 2")
        return "invalid signature"
    
    m = pow(s, e, n)  # RSA verification primitive
    emLen = (modBits - 1) // 8
    EM = i2osp(m, emLen)  # Convert message representative to encoded message
    
    # Step 3: EMSA-PSS verification
    result = emsa_pss_verify(message, EM, modBits - 1, sLen=32)
    if result == "consistent":
        return "valid signature"
    else:
        print("invalid signature step 3")
        return "invalid signature"



message = b"Hel"
emBits = public_key[0].bit_length() - 1  # Effective modulus bits
print("efter embits")
encoded_message = emsa_pss_encode(message, emBits)
print("efter encoded")
s = os2ip(encoded_message)
print("efter s")
signature = i2osp(s, len(encoded_message))
signatureres = verify_signature(public_key, message, signature, emBits)
print("signatureres", signatureres)