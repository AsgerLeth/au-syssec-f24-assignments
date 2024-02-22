import sys
import requests
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def oracle(url, ciphertext):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)] # Split the ciphertext into blocks
    zero_iv = [0] * 16 # Create a zero IV

    for i in range(1, len(blocks)):
        block = blocks[i]
        #print(len(blocks))
        for pad_val in range(1,17):
            padding_iv = [pad_val ^ b for b in zero_iv] # Create the padding IV
            
            for candidate in range(256):
                padding_iv[-pad_val] = candidate

                results = [a ^ b for a,b in zip(bytes.fromhex(block), padding_iv)]
                #print(type(results), type(padding_iv))
                authtoken = [a^b for a,b in zip(results, padding_iv)]
                #print(authtoken)
                authtoken = ''.join(hex(i)[2:].zfill(2) for i in authtoken)

                print(len(authtoken))
                respone = requests.get(f'{url}/quote/', cookies={'authtoken': authtoken})
                print(respone.text)
                #print(len(authtoken))
                if respone.text != "Padding is incorrect.": # IF the padding is correct then we can break
                    zero_iv[-pad_val] = candidate ^ pad_val # Intermediary value
                    break
                
        
    return zero_iv
    #iv = Blocks[0] # The first block is the IV

def main():
    cookie = requests.get('http://localhost:5000') # base_url is the first argument
    cookie_header = cookie.headers.get('Set-Cookie')    
    authtoken = cookie_header.split('=')[1].split(';')[0]
    iv = oracle('http://localhost:5000',authtoken) #sys.argv[0]
    print(iv)

if __name__ == '__main__':
    #if len(sys.argv) != 2:
    #    print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
    #    exit(1)
    main() #sys.argv[0]