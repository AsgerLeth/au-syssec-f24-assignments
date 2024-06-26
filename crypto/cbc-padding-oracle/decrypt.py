import requests

decrypted_message = bytearray(b'\x00\x0f\x0e\x00\x0c\x0b\n\t\x08\x07\x06\x05\x04\x03\x02a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xae\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!')
# Assuming you've converted your decrypted message to hex format
decrypted_token_hex = decrypted_message.hex()

# The URL to access the quote, as per your scenario
quote_url = "http://127.0.0.1:5000/quote"

# Attempt to use the decrypted token to access the protected resource
response = requests.get(quote_url, cookies={'authtoken': decrypted_token_hex})

if response.status_code == 200:
    print("Success! The decrypted message is likely correct:", response.text)
else:
    print("Failed to access the resource with the decrypted token.")