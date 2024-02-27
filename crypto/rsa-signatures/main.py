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
print("New version")
def generate_large_prime(n_bits):
    random_int = secrets.randbits(n_bits)
    # Ensure the random number is odd to increase the chance it's prime
    random_int |= 1
    return nextprime(random_int)

def generate_rsa_keypair(key_size=3072):
    p = generate_large_prime(key_size // 2)
    q = generate_large_prime(key_size // 2)
    while q == p:
        q = generate_large_prime(key_size // 2)
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537  # Common choice for e
    d = pow(e, -1, phi)
    return ((e, n), (d, n)) 
def mgf1(input_bytes, length, hash_class=hashlib.sha256):
    counter = 0
    output_bytes = b''
    while len(output_bytes) < length:
        C = counter.to_bytes(4, byteorder='big')
        output_bytes += hash_class(input_bytes + C).digest()
        counter += 1
    return output_bytes[:length]
def hash_message(message, hash_class=hashlib.sha256):
    return hash_class(message).digest()

def pss_encode(message, salt_length=32):
    hash_len = hashlib.sha256().digest_size
    salt = secrets.token_bytes(salt_length)
    m_hash = hash_message(message)
    
    # Prepare the data block for masking
    M_prime = b'\x00' * 8 + m_hash + salt
    H = hash_message(M_prime)
    PS = b'\x00' * (salt_length + hash_len + 2 - hash_len - 2)
    DB = PS + b'\x01' + salt
    
    # Generate mask and apply it to the DB
    db_mask = mgf1(H, salt_length + hash_len + 2 - hash_len - 1)
    masked_DB = bytes([db ^ mask for db, mask in zip(DB, db_mask)])
    
    # Concatenate masked DB, hash, and the trailer byte
    EM = masked_DB + H + b'\xbc'
    return EM
def pss_verify(signature, message, public_key, salt_length=32):
    hash_len = hashlib.sha256().digest_size
    m_hash = hash_message(message)
    
    # Decrypt the signature to get the encoded message (EM)
    # Assuming `public_key` is a tuple (e, n) and `signature` is an integer
    EM = pow(signature, public_key[0], public_key[1])
    
    # Convert EM back to bytes
    EM_bytes = EM.to_bytes(public_key[1].bit_length() // 8, byteorder='big')
    
    # Extract the components from EM
    masked_DB = EM_bytes[:-hash_len-1]
    H = EM_bytes[-hash_len-1:-1]
    trailer = EM_bytes[-1]
    if trailer != 0xbc:
        return False
    
    # Generate DB mask using H
    db_mask = mgf1(H, len(masked_DB))
    DB = bytes([masked ^ mask for masked, mask in zip(masked_DB, db_mask)])
    
    # Verify the padding is correct
    padding_length = len(DB) - salt_length - 1
    if DB[:padding_length] != b'\x00' * padding_length or DB[padding_length] != b'\x01':
        return False
    
    # Extract salt and verify M'
    salt = DB[-salt_length:]
    M_prime = b'\x00' * 8 + m_hash + salt
    H_verify = hash_message(M_prime)
    
    return H == H_verify



def sign(message, private_key):
    encoded_message = pss_encode(message, private_key)
    # RSA sign the encoded message
    # Return the signature

def verify(signature, message, public_key):
    if pss_verify(signature, message, public_key):
        # Message verified successfully
        return True
    else:
        # Verification failed
        return False

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