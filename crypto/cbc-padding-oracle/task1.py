import sys
import requests
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

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
    plain_blocks = [new_plaintext[i:i+block_size] for i in range(0, len(new_plaintext), block_size)]
    # Random chiptext for the last block
    last_block = bytes([0] * 16)
    for block in reversed(plain_blocks[:-1]):
        last_block = xor(block, last_block)
        last_block = encrypt_block(URL, last_block)
    return ciphertext


def main():
    BASE_URL = 'http://localhost:5000'
    #BASE_URL = 'https://cbc-rsa.syssec.dk:8000/'
    cookie = requests.get(f'{BASE_URL}') # base_url is the first argument
    cookie_header = cookie.headers.get('Set-Cookie') # get the cookie header
    authtoken = cookie_header.split('=')[1].split(';')[0] # get the authtoken
    res = padding_oracle_attack(f'{BASE_URL}',bytes.fromhex(authtoken)) # call the oracle and run padding oracle attack
    print("Recovered plaintext:", unpad(res,16))
    secret = res.split(b'"')[1]
    print("Secret:", secret)
    """
    # Extract the IV from the authtoken
    iv = bytes.fromhex(authtoken[:32])  # Assuming the IV is the first 16 bytes of the authtoken

    # Forge a new ciphertext with the desired plaintext and extracted IV
    desired_plaintext = secret + bytes(' plain CBC is not secure!', 'utf-8')
    #desired_plaintext = pad(desired_plaintext, 16)
    print(len(desired_plaintext))
    #new_ciphertext = create_new_ciphertext(authtoken, res, desired_plaintext)  # Include the IV in the ciphertext
    new_ciphertext = create_new_ciphertext(authtoken, iv, unpad(res,16), desired_plaintext)
    # Print or use the new ciphertext
    print("New Ciphertext:", new_ciphertext)

    # Send the forged ciphertext to the server and observe the response
    response = requests.get(f'{BASE_URL}/quote/', cookies={'authtoken': new_ciphertext.hex()})
    print(response.text)
    """ 

if __name__ == '__main__':
    main()