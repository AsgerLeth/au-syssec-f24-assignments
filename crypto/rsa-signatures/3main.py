import base64
import hashlib
import json
import math
import secrets
import string
from urllib.parse import quote as url_quote
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from sympy import nextprime, randprime
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)
quotes = open('quotes.txt', 'r').readlines()
def generate_rsa_keypair(key_size):
    # Step 1: Generate two distinct prime numbers p and q.
    half_key_size = key_size // 2
    p = randprime(2**(half_key_size - 1), 2**half_key_size)
    q = nextprime(p)
    
    # Ensure p and q are distinct
    while q == p:
        q = nextprime(q)
    
    # Step 2: Compute n = pq and phi = (p-1)(q-1)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Step 3: Choose e
    e = 65537  # Common choice for e
    
    # Step 4: Compute d, the mod inverse of e
    d = pow(e, -1, phi)
    
    # The public key is (e, n) and the private key is (d, n)
    return ((e, n), (d, n))
key_size = 2048  # Use a secure key size
public_key, private_key = generate_rsa_keypair(key_size)

# Convert private and public keys into a format usable by the cryptography library


private_key_cryptography = rsa.RSAPrivateNumbers(
    p=private_key[0], q=private_key[1],
    d=private_key[2], dmp1=private_key[3],
    dmq1=private_key[4], iqmp=private_key[5],
    public_numbers=rsa.RSAPublicNumbers(e=public_key[0], n=public_key[1])
).private_key(default_backend())

public_key_cryptography = private_key_cryptography.public_key()



def pss_encode(message, private_key):
    """Encode a message using RSA-PSS."""
    # Using SHA-256 and MGF1 padding as specified, with a 32-byte salt length
    pss_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=32
    )
    signature = private_key.sign(
        message,
        pss_padding,
        hashes.SHA256()
    )
    return signature
def mgf1(input_bytes, length, hash_class=hashlib.sha256):
    """Mask Generation Function based on a hash function."""
    counter = 0
    output_bytes = b''
    while len(output_bytes) < length:
        C = counter.to_bytes(4, byteorder='big')
        output_bytes += hash_class(input_bytes + C).digest()
        counter += 1
    return output_bytes[:length]

def pss_verify(message, signature, public_key, salt_length=32):
    """Verify an RSA-PSS signature."""
    # Step 1: "Decrypt" signature to get the encoded message
    modulus_length = len(public_key) // 8
    encoded_message = pow(int.from_bytes(signature, byteorder='big'), public_key.public_numbers().e, public_key.public_numbers().n)
    encoded_message_bytes = encoded_message.to_bytes(modulus_length, byteorder='big')

    # Step 2: Separate the encoded message into its components
    hash_length = hashlib.sha256().digest_size
    DB = encoded_message_bytes[:-hash_length-1]
    H = encoded_message_bytes[-hash_length-1:-1]
    sentinel = encoded_message_bytes[-1]

    if sentinel != 0xbc:
        raise ValueError("Decoding error")

    # Step 3: Perform MGF1 mask generation and apply mask
    dbMask = mgf1(H, len(DB), hashlib.sha256)
    maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))

    # The padding string PS should be 0, and then a 0x01 byte before the salt
    # Verify the PS and 0x01 separator
    ps_index = maskedDB.index(b'\x01')
    PS = maskedDB[:ps_index]
    if any(x != 0 for x in PS):
        raise ValueError("Invalid padding")
    # Extract salt
    salt = maskedDB[ps_index+1:]

    # Step 4: Hash the message with the salt and compare it to H
    M_prime = b'\x00' * 8 + hashlib.sha256(message).digest() + salt
    H_prime = hashlib.sha256(M_prime).digest()

    if H != H_prime:
        raise ValueError("Signature verification failed")

    return True


def sign(message: bytes) -> bytes:

    return pss_encode(message, private_key_cryptography)


def verify(message: bytes, signature: bytes) -> bool:
    
    return pss_verify(message, signature, public_key_cryptography)


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


@app.route('/')
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
            if not verify(msg, signature):
                return '<p>Hm, are you trying to cheat?.</p>'
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