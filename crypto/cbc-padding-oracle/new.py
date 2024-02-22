from time import sleep
import requests


def get_padding_error(ciphertext, url):
    # Send the manipulated ciphertext to the server and return True if a padding error occurred
    response = requests.get(url, cookies={'authtoken': ciphertext.hex()})
    print(response.text)
    return 'Padding is incorrect.' in response.text

def decrypt_block(target_block, previous_block, url, block_num, total_blocks):
    decrypted_text = bytearray(len(target_block))
    print(f"Decrypting block {block_num+1}/{total_blocks}...")
    for byte_index in reversed(range(len(target_block))):
        pad_value = len(target_block) - byte_index
        print(f"\tDecrypting byte {len(target_block)-byte_index}/{len(target_block)} with expected pad {pad_value}...")
        for guess in range(256):
            sleep(0.005)
            manipulated_block = bytearray(previous_block)
            # Prepare the block for the correct padding by manipulating bytes we already found
            for i in range(1, pad_value):
                manipulated_block[-i] = decrypted_text[-i] ^ pad_value ^ previous_block[-i]
            manipulated_block[byte_index] = guess ^ previous_block[byte_index] ^ pad_value
            manipulated_ciphertext = manipulated_block + target_block
            if not get_padding_error(manipulated_ciphertext, url):
                # Calculate the plaintext byte
                decrypted_byte = (guess ^ previous_block[byte_index] ^ pad_value)
                decrypted_text[byte_index] = decrypted_byte
                break  # Found the correct padding, move to the next byte
    return decrypted_text

# Example usage
url = "http://127.0.0.1:5000/quote"
# Example ciphertext, replace '...' with the actual hex string
response = requests.get("http://127.0.0.1:5000")
cookie = response.cookies['authtoken']
ciphertext_hex = cookie 
ciphertext = bytearray.fromhex(ciphertext_hex)
total_blocks = len(ciphertext)
decrypted_message = bytearray()

for i in range(0, len(ciphertext), 16):
    if i + 16 > len(ciphertext):
        break  # Skip if there's not enough bytes for a full block
    block = ciphertext[i:i+16]
    if i == 0:
        previous_block = bytearray([0]*16)  # For the first block, IV is considered as the previous block
    else:
        previous_block = ciphertext[i-16:i]
    decrypted_block = decrypt_block(block, previous_block, url, i//16, total_blocks)
    decrypted_message += decrypted_block

print("Decrypted message:", decrypted_message)
