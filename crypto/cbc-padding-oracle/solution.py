#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def single_block(base_url,block,i,res,BLOCK_SIZE=AES.block_size):
    '''Perform a padding oracle attack on a single block of ciphertext.'''
    zeroing_iv = [0] * BLOCK_SIZE # initialize the zeroing IV
    g_gues = [0] * BLOCK_SIZE
    block = bytes.fromhex(block)
    for pad_val in range(1, BLOCK_SIZE+1): # iterate over the padding values
                                           # (1, 2, ..., BLOCK_SIZE) in reverse order
                                           # padding with 0x01, 0x02, ..., 0x10
                                           # Assuming PKCS7 padding, if full block then 0x10
        padding_iv = [pad_val ^ b for b in g_gues]

        for candidate in range(256): # 2⁸ = 256 bits for each byte
            print(pad_val)
            padding_iv[-pad_val] = candidate # set the guessed byte, try all 256 possibilities
            #g_gues[-pad_val] = candidate 
            iv = bytes(padding_iv)
            
            block = bytes([b ^ g for b, g in zip(block, padding_iv)]) # xor the block with the guessed bytes
            res = requests.get(f'{base_url}/quote/', cookies={'authtoken': block.hex()})
            if res != "Padding is incorrect.":
                #print("Padding is correct")
                g_gues[-pad_val] = candidate ^ pad_val
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not res != "Padding is incorrect.":
                        continue  # false positive; keep searching
                break
            print("Padding is incorrect")
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

    return g_gues


def single_block2(base_url, block, BLOCK_SIZE=AES.block_size):
    '''Perform a padding oracle attack on a single block of ciphertext.'''
    zeroing_iv = [0] * BLOCK_SIZE
    block = bytes.fromhex(block)
    for pad_val in range(1,2):#, BLOCK_SIZE+1): 
        #padding_iv = [pad_val ^ b for b in zeroing_iv]
        padding_iv = zeroing_iv
        print(pad_val)
        padding_iv[-pad_val] = padding_iv[-pad_val] ^ pad_val
        print(padding_iv)
        for candidate in range(256): 
            padding_iv[-pad_val] = candidate
            #print(padding_iv)
            iv = bytes(padding_iv)
            block_copy = block[:]
            block_copy = bytes(b ^ g for b, g in zip(block_copy, padding_iv))
            print(len(block_copy), "taber")
            authtoken = bytes(a ^ b for a, b in zip(iv, block_copy))
            print(len(authtoken))
            res = requests.get(f'{base_url}/quote/', cookies={'authtoken': authtoken.hex()})
            print(res.text)
            if res.text != "Padding is incorrect.":
                zeroing_iv[-pad_val] = candidate ^ pad_val  
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if res.text == "Padding is incorrect.":
                        continue  
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")
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

def full_attack2(iv,ct):
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
    cookie = requests.get(f'{base_url}') # get the cookie
    cookie_header = cookie.headers.get('Set-Cookie') # get the cookie header
    authtoken = cookie_header.split('=')[1].split(';')[0] # get the authtoken
    new_ciphertext = bytes.fromhex(authtoken) # convert the authtoken to bytes
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()}) # get the quote

    # Assume `authtoken` is your encrypted data
    block_size = 32  # For AES
    zeroing_iv = None
    # Split the authtoken into blocks
    blocks = [authtoken[i:i+block_size] for i in range(0, len(authtoken), block_size)]
    #print(len(blocks[0]))
    # Now you can pass each block to the `single_block` function
    result = b''
    zeroing_iv = single_block(base_url, blocks[0])
    #for i, block in enumerate(blocks): #Skal man starte bagfra??
        # Assume `known_plaintext = res` is the known part of the plaintext
        #zeroing_iv = single_block2(base_url, block, i, res)
        #print(zeroing_iv)
        #result += full_attack2(zeroing_iv,block)
    print(zeroing_iv)
    print(result)
    #print(f'[+] done:\n{res.text}')
    #print("cookie:", authtoken)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])

