import sys
import requests
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def oracle(url, ciphertext):
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    result = b''
    iv = blocks[0] # IV is the first block
    zero_iv = None
    for block in blocks[1:]:
        zero_iv = [0] * 16 # Create a zero IV
        for pad_val in range(1,block_size+1):
            padding_iv = [pad_val ^ b for b in zero_iv] # Create the padding IV
            
            for candidate in range(256):
                padding_iv[-pad_val] = candidate
                response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()})
                temp = None
                if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                    temp = False
                else:
                    temp = True
                if temp: # IF the padding is correct then we can break
                    if pad_val == 1:
                        # make sure the padding really is of length 1 by changing
                        # the penultimate block and querying the oracle again
                        padding_iv[-2] ^= 1
                        response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()})
                        if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                            temp = False
                        else:
                            temp = True
                        if not temp:
                            continue  # false positive; keep searching
                    break
            else:
                raise Exception("no valid padding byte found (is the oracle working correctly?)")
            zero_iv[-pad_val] = candidate ^ pad_val
        pt = bytes(a ^ b for a,b in zip(iv,zero_iv))
        result = result + pt
        iv = block
    return result, zero_iv

def oracle_attack_decrypt(url, block):
    block_size = 16
    zero_iv = [0] * 16 # Create a zero IV
    for pad_val in range(1,block_size+1):
        padding_iv = [pad_val ^ b for b in zero_iv] # Create the padding IV
        
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()})
            temp = None
            if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                temp = False
            else:
                temp = True
            if temp: # IF the padding is correct then we can break
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()})
                    if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                        temp = False
                    else:
                        temp = True
                    if not temp:
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("no valid padding byte found (is the oracle working correctly?)")
        zero_iv[-pad_val] = candidate ^ pad_val
    return zero_iv

def padding_oracle_attack(url, ciphertext):
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    result = b''
    iv = blocks[0] # IV is the first block
    for block in blocks[1:]:
        zero_iv = oracle_attack_decrypt(url, block)
        pt = bytes(a ^ b for a,b in zip(iv,zero_iv))
        result = result + pt
        iv = block
    return result

def create_new_ciphertext(URL, new_plaintext):
    block_size = 16
    new_plaintext = pad(new_plaintext, block_size)
    M = [new_plaintext[i:i+block_size] for i in range(0, len(new_plaintext), block_size)]
    C_n = get_random_bytes(16)
    result = b'' + C_n
    for block in reversed(M):
        P_n = oracle_attack_decrypt(URL, C_n)
        C_n1 = bytes(a ^ b for a,b in zip(P_n, block))
        result = C_n1 + result
        C_n = C_n1
    
    return result


def main():
    #BASE_URL = 'http://localhost:5000'
    BASE_URL = 'https://cbc-rsa.syssec.dk:8000/'
    cookie = requests.get(f'{BASE_URL}') # base_url is the first argument
    cookie_header = cookie.headers.get('Set-Cookie') # get the cookie header
    authtoken = cookie_header.split('=')[1].split(';')[0] # get the authtoken
    res = padding_oracle_attack(f'{BASE_URL}',bytes.fromhex(authtoken)) # call the oracle and run padding oracle attack
    print("Recovered plaintext:", unpad(res,16))
    secret = res.split(b'"')[1]
    print("Secret:", secret)

    # Create a new plaintext
    new_plain = secret + ' plain CBC is not secure!'
    print(len(new_plain), type(new_plain),len(bytes(new_plain, 'utf-8')))
    new_plain_bytes = bytes(new_plain, 'utf-8')
    res = create_new_ciphertext(BASE_URL, new_plain_bytes)
    print("Encrypted plaintext:", res)
    # Get quote
    response = requests.get(f'{BASE_URL}/quote/', cookies={'authtoken': res.hex()})
    print(response.text)
    
if __name__ == '__main__':
    main()