#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

# Given encryption key and secret
encryption_key = b'\xdak5\xe8\x06\xd1\x9ctchX\xd9\x93\xa2\xa8C'
secret = 'I should have used authenticated encryption because ...'

# The additional message to meet the validation criteria
validation_message = 'plain CBC is not secure!'

# Construct the full plaintext
plaintext = (secret + validation_message).encode()

# Encrypt the plaintext
def encrypt_message(plaintext, key):
    # Generate a random IV
    iv = secrets.token_bytes(16)
    # Initialize the cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the plaintext and encrypt
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Return IV and ciphertext
    return iv + ciphertext

# Decrypt the ciphertext
def decrypt_message(ciphertext, key):
    # Extract the IV from the beginning of the payload
    iv = ciphertext[:16]
    # Initialize the cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt and unpad the plaintext
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext


def single_block(base_url):
    BLOCK_SIZE = 16
    zeroing_iv = [0] * BLOCK_SIZE
    cookie = requests.get(f'{base_url}')
    cookie_header = cookie.headers.get('Set-Cookie')    
    authtoken = cookie_header.split('=')[1].split(';')[0]
    new_ciphertext = bytes.fromhex(authtoken)
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()})

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if res != "Padding is incorrect.":
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not res != "Padding is incorrect.":
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

def full_attack(iv,ct):
    msg = iv
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    result = b''
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block(ct)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct
    return result

def test_systems_security(base_url):
    encryption_key = b'\xdak5\xe8\x06\xd1\x9ctchX\xd9\x93\xa2\xa8C'
    secret = 'I should have used authenticated encryption because ...'
    validation_message = ' plain CBC is not secure!'

    # Construct the full plaintext
    plaintext = (secret + validation_message).encode()

    # Function to encrypt the message
    def encrypt_message(plaintext, key):
        iv = secrets.token_bytes(16)  # Generate a random IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ciphertext  # Prepend IV to the ciphertext

    # Encrypt the constructed plaintext
    ciphertext = encrypt_message(plaintext, encryption_key)

    # Convert the ciphertext (with IV) to a hex string for the cookie
    ciphertext_hex = ciphertext.hex()

    # Assuming the base URL is known and accessible for this exercise
    quote_url = f'{base_url}/quote'

    # Send the request with the crafted token
    response = requests.get(quote_url, cookies={'authtoken': ciphertext_hex})

    # Print the response from the server
    print(f'Server response: {response.text}')
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])

