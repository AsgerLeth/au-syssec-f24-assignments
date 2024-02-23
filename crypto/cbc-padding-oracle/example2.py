from operator import xor
import requests
import sys
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


def oracle(iv, ciphertext):
    ciphertext_hex = hex(ciphertext ^ iv)
    response = requests.get(ciphertext, cookies={'authtoken': ciphertext_hex})
    if response.text == "Padding is incorrect.":
        return print("Correct padding")
    else:
        return False
    
base_url = "http://127.0.0.1:5000"
quote_url = "http://127.0.0.1:5000/quote"
cookie = requests.get(f'{base_url}')
cookie_header = cookie.headers.get('Set-Cookie')    
authtoken = cookie_header.split('=')[1].split(';')[0]
new_ciphertext = bytes.fromhex(authtoken)
print(authtoken)
res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()})
print(res.text)

BLOCK_SIZE = 16


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
            if oracle(iv, block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return print(zeroing_iv)


def full_attack(iv, ct, oracle):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    for ct in blocks[1:]:
        dec = single_block_attack(ct, oracle)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    return result

single_block_attack(new_ciphertext)



