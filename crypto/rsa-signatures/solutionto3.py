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
    
    e = 65537
    e
    d = pow(e, -1, phi)
    
    # Return the public and private keys
    # Public key is (n, e) and private key is (n, d)
    return (n, e), (n, d)


public_key, private_key = generate_rsa_keypair()

def i2osp(x, xLen):
    if x >= 256 ** xLen:
        return "integer too large", None

    bytes_representation = x.to_bytes(xLen, byteorder='big')

    return bytes_representation

def os2ip(X):
    return int.from_bytes(X, byteorder='big')

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
    emLen = ceil(emBits/8)
    mHash = hash(M).digest()
    hLen = len(mHash)
    if emLen < hLen + 2 + 8:
        return "inconsistent"
    salt = i2osp(random.getrandbits(8*sLen), sLen)
    M_prime = b"\x00"*8 + mHash + salt
    H = hash(M_prime).digest()
    assert len(H) == hLen
    PS = b"\x00"*(emLen-sLen-hLen-2)
    DB = PS + b"\x01" + salt
    assert len(DB) == emLen-hLen-1
    dbMask = maskGenFunc(H, emLen-hLen-1)
    maskedDB = bytes([DB[i] ^ dbMask[i] for i in range (len(dbMask))])
    maskedDB = int.to_bytes(maskedDB[0] & (0xff >> (8*emLen - emBits))) + maskedDB[1:]
    EM = maskedDB + H + b"\xbc"
    print("em_pss", EM)
    return EM

def emsa_pss_verify(M, EM, emBits, sLen):
    """Verify an RSA-PSS signature."""
    hash_func = hashlib.sha256
    hLen = hash_func().digest_size  # Length of hash output in bytes
    print("VerEM",EM)

    # Step 1: Length checking for the message against hash function limitation
    if len(M) > (2**256 - 1):
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
    if EM[-1] != 0xbc :
        print("EM2",EM[-1])
        print("inconsistent 4 verify")
        return "inconsistent"
    
    # Step 5: Split EM into maskedDB and H
    maskedDB = EM[:emLen - hLen - 1]
    H = EM[emLen - hLen - 1:-1]
    
    # Step 6: Check the leftmost 8emLen - emBits bits
    numZeroBits = 8 * emLen - emBits
    # Extracting the first octet of maskedDB
    firstOctet = maskedDB[0]
    # Creating a mask to check the leftmost numZeroBits are zero
    mask = (1 << numZeroBits) - 1 << (8 - numZeroBits)
    # Applying the mask to the first octet and checks if the result is zero
    if firstOctet & mask != 0:
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
    print("M_prime", M_prime)
    # Step 14: Check if H matches H'
    if H == H_prime:
        print("consistent 14")
        return "consistent"
    else:
        print("inconsistent 14")
        return "inconsistent"

def verify_signature(public_key, message, signature, modBits):
    #n, e = public_key
    modBits = public_key[0].bit_length()
    
    n = public_key[0]
    e = public_key[1]
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
    emLen = ceil(((modBits - 1) / 8))
    #emLen = (modBits - 1) // 8 + ((modBits - 1) % 8 > 0)
    #print("emlen", emLen)
    EM = i2osp(m, emLen)  # Convert message representative to encoded message
    #EM = emsa_pss_encode(message, modBits - 1, sLen=32)
    # Step 3: EMSA-PSS verification
    result = emsa_pss_verify(message, EM, modBits - 1, sLen=32)
    if result == "consistent":
        return "valid signature"
    else:
        print("invalid signature step 3")
        return "invalid signature"

message = b"Hel"
modBits = public_key[0].bit_length()
print("efter embits")
encoded_message = emsa_pss_encode(message, modBits)
print("efter encoded")
s = os2ip(encoded_message)
print("efter s")
signature = i2osp(s, len(encoded_message))
print("signature:" , signature)
signatureres = verify_signature(public_key, message, signature, modBits)
print("signatureres", signatureres)