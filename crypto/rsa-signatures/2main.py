import base64
import hashlib
import json
import math
import random
import secrets
import string
from flask import Flask, request, make_response, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret_data import encryption_key, secret
import logging
import rsa
from secret_data import rsa_key

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def lcm(a, b):
    return a * b // gcd(a, b)

# Placeholder functions for generating primes p and q
def generate_large_prime(bitsize=1536):
    """Generate a large prime number of given bit size.
    
    WARNING: This is a placeholder and not secure.
    """
    # In practice, use a secure and efficient prime generation algorithm.
    # Here we simulate it with a random large number for demonstration purposes.
    prime_candidate = random.getrandbits(bitsize)
    prime_candidate |= (1 << bitsize - 1) | 1  # Ensure it's odd and of the correct bit size
    return prime_candidate 

def generate_rsa_keys():
    p = generate_large_prime()
    q = generate_large_prime()
    while p == q:
        q = generate_large_prime()

    n = p * q
    lam_n = lcm(p-1, q-1)
    e = 65537  # Common choice for e
    d = modinv(e, lam_n)

    public_key = (n, e)
    private_key = (n, d)
    return private_key, public_key

def mgf1(input_str, length):
    """A mask generation function based on SHA-256."""
    counter = 0
    output = b''
    while len(output) < length:
        C = counter.to_bytes(4, byteorder='big')
        output += hashlib.sha256(input_str + C).digest()
        counter += 1
    return output[:length]

def emsa_pss_verify(M, EM, emBits, sLen):
    """Verify an RSA-PSS signature."""
    hash_func = hashlib.sha256
    hLen = hash_func().digest_size  # Length of hash output in bytes
    
    # Step 1: Length checking for the message against hash function limitation
    if len(M) > (2**61 - 1):
        return "inconsistent"
    
    # Step 2: Let mHash = Hash(M)
    mHash = hash_func(M).digest()
    
    emLen = -(-emBits // 8)  # Ceiling division to get length in bytes
    
    # Step 3: Check if emLen is less than expected
    if emLen < hLen + sLen + 2:
        return "inconsistent"
    
    # Step 4: Check if the rightmost octet of EM is 0xbc
    if EM[-1] != 0xbc:
        return "inconsistent"
    
    # Step 5: Split EM into maskedDB and H
    maskedDB = EM[:emLen - hLen - 1]
    H = EM[emLen - hLen - 1:-1]
    
    # Step 6: Check the leftmost 8emLen - emBits bits
    if maskedDB[0] & (0xFF >> (emBits % 8)) != 0:
        return "inconsistent"
    
    # Step 7 & 8: Generate dbMask and compute DB
    dbMask = mgf1(H, emLen - hLen - 1)
    DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))
    
    # Step 9: Set leftmost bits of DB to zero
    DB = (0xFF >> (8 - emBits % 8)) & DB[0].to_bytes(1, byteorder='big') + DB[1:]
    
    # Step 10: Check the padding in DB
    if DB[:emLen - hLen - sLen - 2] != b'\x00' * (emLen - hLen - sLen - 2) or DB[emLen - hLen - sLen - 2] != 0x01:
        return "inconsistent"
    
    # Step 11: Extract the salt from DB
    salt = DB[-sLen:]
    
    # Step 12 & 13: Compute H' and compare with H
    M_prime = b'\x00'*8 + mHash + salt
    H_prime = hash_func(M_prime).digest()
    
    # Step 14: Check if H matches H'
    if H == H_prime:
        return "consistent"
    else:
        return "inconsistent"

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


def verify_signature(public_key, message, signature, modBits):
    n, e = public_key
    k = len(signature)
    
    # Step 1: Length checking
    if len(signature) != k:
        return "invalid signature"
    
    # Step 2: RSA verification
    s = os2ip(signature)  # Convert signature to integer
    if s >= n:
        return "invalid signature"
    
    m = pow(s, e, n)  # RSA verification primitive
    emLen = (modBits - 1) // 8
    EM = i2osp(m, emLen)  # Convert message representative to encoded message
    
    # Step 3: EMSA-PSS verification
    result = emsa_pss_verify(message, EM, modBits - 1)
    if result == "consistent":
        return "valid signature"
    else:
        return "invalid signature"
    
def rsasp1(n, d, m):
    """Perform RSASP1 signing operation with a private key (n, d) on message m."""
    if not (0 <= m < n):
        raise ValueError("Message representative out of range")
    
    s = pow(m, d, n)  # Compute m^d mod n efficiently
    return s
    
emBits = 2048  # Example modulus size in bits
sLen = 32  # Example salt length in bytes

app = Flask(__name__)
quotes = open('quotes.txt', 'r').readlines()


def sign(message: bytes) -> bytes:
    """Sign a message using our RSA private key."""
    # Extract the modulus and private exponent from rsa_key
    n = rsa_key['_n']
    d = rsa_key['_d']
    
    # Convert the message to an integer
    m = os2ip(message)
    
    # Sign the message using RSASP1
    s = rsasp1(n, d, m)
    
    # Convert the signature back to bytes
    signature = i2osp(s, math.ceil(n.bit_length() / 8))
    
    return signature


def verify(message: bytes, signature: bytes) -> bool:
    """Verify a signature using our public key."""
    # modulus and private exponent
    N = rsa_key['_n']
    e = rsa_key['_e']
    # interpret the bytes of the message and the signature as integers stored
    # in big-endian byte order
    m = int.from_bytes(message, 'big')
    s = int.from_bytes(signature, 'big')
    if not 0 <= m < N or not 0 <= s < N:
        raise ValueError('message or signature too large')
    # verify the signature
    mm = pow(s, e, N)
    return m == mm


def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str


def cookie_to_json(base64_as_str: str) -> str:
    """Decode json data stored in a cookie-friendly way using base64."""
    # Check that the input looks like base64 data
    assert all(char in (string.ascii_letters + string.digits + '-_=') for char in base64_as_str), \
            f"input '{base64_as_str}' is no valid base64"
    # decode the base64 data
    json_as_bytes = base64.b64decode(base64_as_str, altchars=b'-_')
    # b64decode returns bytes, we want string -> decode it
    json_as_str = json_as_bytes.decode()
    return json_as_str
app.route('/')
def index():
    """Redirect to the grade page."""
    return redirect(url_for('grade'))


@app.route('/pk/')
def pk():
    """Publish our public key as JSON."""
    N = int(rsa_key['_n'])
    e = int(rsa_key['_e'])
    return {'N': N, 'e': e}


@app.route('/grade/')
def grade():
    """Grade student's work and store the grade in a cookie."""
    if 'grade' in request.cookies:  # there is a grade cookie, try to load and verify it
        try:
            # decode the base 64 encoded cookie from the request
            c = cookie_to_json(request.cookies.get('grade'))
            # deserialize the JSON object which we expect in the cookie
            j = json.loads(c)
            # decode the hexadecimal encoded byte strings
            msg = bytes.fromhex(j['msg'])
            signature = bytes.fromhex(j['signature'])
            # check if the signature is valid
            valid = verify_signature(rsa_key['_n'], rsa_key['_e'], msg, signature)
            if not valid:
                return '<p>Hm, are you trying to cheat?</p>'
            return f'<p>{msg.decode()}</p>'
        except Exception as e:
            # if something goes wrong, delete the cookie and try again
            response = redirect(url_for('grade'))
            response.delete_cookie('grade')
            return response
    else:  # the student has not yet been graded, lets do this
        # think very hard, which grade the student deserves
        g = secrets.choice(['-3', '00', '02', '4', '7', '10']) # nobody gets a 12 in my course
        # create the message and UTF-8 encode it into bytes
        msg = f'You get a only get a {g} in System Security. I am very disappointed by you.'.encode()
        # sign the message
        signature = sign(msg)
        # serialize message and signature into a JSON object; for the byte
        # strings we use hexadecimal encoding
        j = json.dumps({'msg': msg.hex(), 'signature': signature.hex()})
        # encode the json data cookie-friendly using base 64
        c = json_to_cookie(j)
        # create a response object
        response = make_response('<p>Here is your grade, and take a cookie!</p>')
        # and store the created JSON object into a cookie
        response.set_cookie('grade', c)
        return response



@app.route('/quote/')
def quote():
    """Show a quote to good students."""
    try:
        # decode the base 64 encoded cookie from the request
        c = cookie_to_json(request.cookies.get('grade'))
        # deserialize the JSON object which we expect in the cookie
        j = json.loads(c)
        # decode the hexadecimal encoded byte strings
        msg = bytes.fromhex(j['msg'])
        signature = bytes.fromhex(j['signature'])
    except Exception as e:
        return '<p>Grading is not yet done, come back next year.</p>'
    # check if the signature is valid
    if not verify(msg, signature):
        return '<p>Hm, are you trying to cheat?.</p>'
    # check if the student is good
    if msg == b'You got a 12 because you are an excellent student! :)':
        return f'<quote>\n{secrets.choice(quotes)}</quote>'
    else:
        return '<p>You should have studied more!</p>'


# students always want me to sign their stuff, better automate this
@app.route('/sign_random_document_for_students/<data>/')
def sign_random_document_for_student(data):
    """Sign a given message as long as it does not contain a grade.

    The data is expected in hexadecimal encoding as part of the URL.  E.g.,
    `/sign_random_document_for_students/42424242/` returns a signature of the
    string 'BBBB'.
    """
    # hex-decode the data
    msg = bytes.fromhex(data)
    # check if there are any forbidden words in the message
    if any(x.encode() in msg for x in ['grade', '12', 'twelve', 'tolv']):
        return '<p>Haha, nope!</p>'
    try:  # try to sign the message
        signature = sign(msg)
        # return message and signature hexadecimal encoded in a JSON object
        return {'msg': msg.hex(), 'signature': signature.hex()}
    except Exception as e:  # something went wrong
        return {'error': str(e)}