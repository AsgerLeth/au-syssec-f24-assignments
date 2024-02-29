import base64
import json
import math
import secrets
import string
from urllib.parse import quote as url_quote
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key
import hashlib


def mgf1_sha256(seed: bytes, mask_length: int) -> bytes:
    counter = 0
    output = b''
    while len(output) < mask_length:
        hash_input = seed + counter.to_bytes(4, byteorder='big')
        hash_output = hashlib.sha256(hash_input).digest()
        output += hash_output
        counter += 1
    return output[:mask_length]

def encode_pss2(message: bytes, emBits: int) -> bytes:
    mHash = hashlib.sha256(message).digest()
    emLen = math.ceil(emBits / 8)
    hLen = len(mHash)
    sLen = 32  # Assuming the length of the salt is 256 bits (32 bytes)
    if emLen < hLen + sLen + 2:
        raise ValueError("Encoding error: emLen is too short")
    salt = secrets.token_bytes(sLen)
    M_ = b'\x00'*8 + mHash + salt
    H = hashlib.sha256(M_).digest()
    PS = b'\x00' * (emLen - sLen - hLen - 2)
    DB = PS + b'\x01' + salt
    dbMask = mgf1_sha256(H, emLen - hLen - 1)
    maskedDB = bytes([DB[i] ^ dbMask[i] for i in range(len(DB))])
    # Clearing the bits as per the standard, to make sure the encoded message is smaller than the RSA modulus
    maskedDB = bytes([maskedDB[0] & (0xFF >> (8 * emLen - emBits))]) + maskedDB[1:]
    EM = maskedDB + H + b'\xbc'
    return EM
def encode_pss(message, emBits):
    if len(message) > 2**(256)-1:
        return "encoding error"
    else:
        mHash = hashlib.sha256(message)
        emLen = emBits/8
        hLen = len(mHash)
        sLen = 256
        if emLen <  hLen + sLen + 2:
            return "encoding error"
        else:
            salt = secrets.token_bytes(32)
            M_ = [0x00]*8 + list(mHash.digest()) + salt
            H = hashlib.sha256(M_)
            PS = (emLen - sLen - hLen - 2*[0x00])
            DB = PS + [0x01] + salt
            dbMask = mgf1_sha256(H.digest(), emLen - hLen - 1)
            maskedDB = [DB[i] ^ dbMask[i] for i in range(len(DB))]
            maskedDB[0] = maskedDB[0] & (0xff >> (8*emLen - emBits))
            EM = maskedDB + H.digest() + [0xbc]
            return EM
def verify_pss2(message: bytes, EM: bytes, emBits: int) -> str:
    mHash = hashlib.sha256(message).digest()
    emLen = math.ceil(emBits / 8)
    hLen = len(mHash)
    sLen = 32  # Assuming the length of the salt is 256 bits (32 bytes)
    if len(EM) != emLen or emLen < hLen + sLen + 2 or EM[-1] != 0xbc:
        return "inconsistent"

    maskedDB = EM[:emLen - hLen - 1]
    H = EM[emLen - hLen - 1:-1]
    dbMask = mgf1_sha256(H, emLen - hLen - 1)
    DB = bytes([maskedDB[i] ^ dbMask[i] for i in range(len(maskedDB))])

    # Verify the DB structure
    if DB[0] & (0xFF << (8*emLen - emBits)) or DB[:emLen - sLen - hLen - 2] != b'\x00'*(emLen - sLen - hLen - 2) or DB[emLen - sLen - hLen - 2] != 0x01:
        return "inconsistent"

    salt = DB[-sLen:]
    M_ = b'\x00'*8 + mHash + salt
    H_ = hashlib.sha256(M_).digest()
    if H_ != H:
        return "inconsistent"
    return "consistent" 

def verify_pss(message, EM, emBits):
    if len(message) > 2**(256)-1:
        return "inconsistent"
    else:
        mHash = hashlib.sha256(message)
        hLen = len(mHash.digest())
        sLen = 256
        emLen = emBits/8
        if emLen <  hLen + sLen + 2:
            return "inconsistent"
        else:
            if EM[-1] != 0xbc:
                return "inconsistent"
            else:
                maskDB = EM[:emLen-hLen-1]
                H = EM[emLen-hLen-1:emLen-1]
                if maskDB[0] & (0xff << (8*emLen - emBits)):
                    return "inconsistent"
                else:
                    dbMask = mgf1_sha256(H, emLen - hLen - 1)
                    DB = [maskDB[i] ^ dbMask[i] for i in range(len(maskDB))]
                    DB[0] = DB[0] & (0xff >> (8*emLen - emBits))
                    if DB[:emLen-sLen-2-hLen] != [0x00]*8 or DB[emLen-sLen-1-hLen] != 0x01:
                        return "inconsistent"
                    else:
                        salt = DB[-sLen:]
                        M_ = [0x00]*8 + list(mHash.digest()) + salt
                        H_ = hashlib.sha256(M_)
                        if H_.digest() == H:
                            return "consistent"
                        else:
                            return "inconsistent"
def sign(message: bytes) -> bytes:
    """Sign a message using our private key."""
    # modulus and private exponent
    N = rsa_key['_n']
    d = rsa_key['_d']
    # interpret the bytes of the message as an integer stored in big-endian
    # byte order
    m = int.from_bytes(message, 'big')
    if not 0 <= m < N:
        raise ValueError('message too large')
    # compute the signature
    s = pow(m, d, N)
    # encode the signature into a bytes using big-endian byte order
    signature = s.to_bytes(math.ceil(N.bit_length() / 8), 'big')
    return signature

def generate_keypair(p, q):
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi)
    return ((n, e), (n, d))

def test_rsa_pss():
    # Generate key pair
    p, q = 61, 53
    public_key, private_key = generate_keypair(p, q)

    # Test message
    message = b"Test message"

    # Sign the message
    signature = sign(message)
    emBits = 2048
    # Verify the signature - should be consistent
    assert verify_pss2(message, signature, emBits) == "consistent", "Verification failed for a valid signature"

    # Alter the message
    altered_message = b"Test message altered"

    # Verify the altered message - should be inconsistent
    assert verify_pss2(altered_message, signature, emBits) == "inconsistent", "Altered message verification incorrectly passed"

def mock_sign(message: bytes, emBits: int) -> bytes:
    """Simulate signing by encoding the message with PSS padding."""
    # This would normally involve RSA encryption of the encoded message
    return encode_pss2(message, emBits)

def mock_verify(original_message: bytes, signed_message: bytes, emBits: int) -> bool:
    """Simulate verification by checking PSS padding of the signed message."""
    # This would normally involve RSA decryption to get the encoded message
    verification_result = verify_pss2(original_message, signed_message, emBits)
    return verification_result == "consistent"

def test_rsa_pss2():
    message = b"Hello, RSA-PSS!"
    emBits = 2048 - 1  # Assuming a 2048-bit RSA key, with 1 bit less for padding

    # Simulate signing the message
    signed_message = mock_sign(message, emBits)
    
    # Simulate verifying the signed message
    verification_success = mock_verify(message, signed_message, emBits)

    assert verification_success, "PSS verification failed"

    # Alter the message and verify again
    altered_message = b"Goodbye, RSA-PSS!"
    verification_fail = mock_verify(altered_message, signed_message, emBits)

    assert not verification_fail, "PSS verification incorrectly succeeded for altered message"

    print("PSS encoding and verification test passed.")

test_rsa_pss2()