#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
from http.cookies import SimpleCookie
from flask import Flask, request, make_response, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
base_url = "http://127.0.0.1:5000"
#base_url = "https://cbc-rsa.syssec.dk:8000/"

def oracle(block):
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': block.hex()} )
	
    if res.text.__contains__("PKCS#7 padding is incorrect") or res.text.__contains__("Padding is incorrect."):
        return False
    else:
        print(res.text)
        return True
    
def get_token():
    #The requests for getting the cookie
    res = requests.get(f'{base_url}/quote/')
    #extraticn the cipertext from the requests result from the cookie
    cipertext = res.cookies.get("authtoken")
    
    #Changing the cipertext to hex from 
    cipertext = bytes.fromhex(cipertext)
	
    return cipertext

def full_attack(iv, ct):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

def single_block_attack(block):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv+block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv+block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

def test_systems_security(base_url):
    new_ciphertext = bytes.fromhex('2cc9a9fc7cb4dc60f1df7babc4bf82c1122b12cbd8a1c10e1d7f1d4cf57c60ed8cb3703e30ff4b1a2a9af418df999c71b331721a24e713668d0478351a4ccad77fa6abff498d919b3773e6e25fcad5556545a6339b9d4f42c854f96e940a538342424242424242424242424242424242')    
    token = get_token()
   
    res = full_attack(token[:BLOCK_SIZE], token[BLOCK_SIZE:])
    plaintext = unpad(res, 16)
    print("Recovered plaintext:", plaintext)


if __name__ == '__main__':
    #base_url = "http://127.0.0.1:5000"
    #new_url = "https://cbc-rsa.syssec.dk:8000/"
    test_systems_security(base_url)