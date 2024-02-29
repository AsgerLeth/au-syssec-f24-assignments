import sys
import requests
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def oracle(url, ciphertext):
    #blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)] # Split the ciphertext into blocks
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    result = b''
    iv = blocks[0] # IV is the first block
    for block in blocks[1:]:
        zero_iv = [0] * 16 # Create a zero IV
        #print(len(blocks))
        for pad_val in range(1,block_size+1):
            padding_iv = [pad_val ^ b for b in zero_iv]
            #padding_iv = [pad_val ^ b for b in zero_iv] # Create the padding IV
            
            for candidate in range(256):
                padding_iv[-pad_val] = candidate
                #print("padding_iv", padding_iv)

                #results = [a ^ b for a,b in zip(block, bytes(padding_iv))]
                #authtoken = ''.join(hex(i)[2:].zfill(2) for i in results)
                response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()} )
                #response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()}) #"No quote for you!" in response.text or 
                temp = None
                if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                    temp = False
                else:
                    temp = True
                if temp: # IF the padding is correct then we can break
                    #zero_iv[-pad_val] = candidate ^ pad_val # Intermediary value
                    print("IF",response.text)
                    if pad_val == 1:
                        # make sure the padding really is of length 1 by changing
                        # the penultimate block and querying the oracle again
                        padding_iv[-2] ^= 1
                        response = requests.get(f'{url}/quote/', cookies={'authtoken': (bytes(padding_iv) + block).hex()})
                        if response.text.__contains__("PKCS#7 padding is incorrect") or response.text.__contains__("Padding is incorrect."):
                            temp = False
                        else:
                            temp = True
                        if not temp: #"No quote for you!" in response.text or 
                            continue  # false positive; keep searching
                    break
            else:
                raise Exception("no valid padding byte found (is the oracle working correctly?)")
                    #break
            zero_iv[-pad_val] = candidate ^ pad_val # Intermediary value
        print("done")
        pt = bytes(a ^ b for a,b in zip(iv,zero_iv))
        result = pt + result
        iv = block
    return result

def main():
    BASE_URL = 'http://localhost:5000'
    #BASE_URL = 'https://cbc-rsa.syssec.dk:8000/'
    cookie = requests.get(f'{BASE_URL}') # base_url is the first argument
    cookie_header = cookie.headers.get('Set-Cookie')    
    authtoken = cookie_header.split('=')[1].split(';')[0]
    res = oracle(f'{BASE_URL}',bytes.fromhex(authtoken))
    print(res)
    print(len(res))
    #plaintext = unpad(res, 16)
    #print("Recovered plaintext:", plaintext)

if __name__ == '__main__':
    #if len(sys.argv) != 2:
    #    print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
    #    exit(1)
    main() #sys.argv[0]