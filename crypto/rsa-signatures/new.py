import requests
import json
import base64

baseURL = "http://127.0.0.1:5000"
# Server's public key parameters (you'd obtain these from the /pk/ endpoint)
N = 3679577145104151303099119843273355663902168287050387015666321029143382632335783733519546824840620726519782787759539815117270016858531853676624950848415477183956722217870626711008998451739612114377763073300188023685798879932134024507321342717418877072251507595469506099126686557248352239380754840193551506122569698460540278906487275276999876761648935473987948588066595107762923328314759624796735513444943123077362417460471776019413352328968364370658050504038901283230496388854451515240033886696075141276245581756634903910014572299524285334365586562042893374784131693965738583695420334982728206021531322470433785512205410728137564445897500399152396601151189400899390912055649987317486918740277183269805210265197646898144332172144212085395230843843051877645469226751477964519114341533145803117552699648385633365505489692886706322549259601223814299359589594261083804692406328766054031663807281640847001958438993566327493046666799
e = 65537

def find_m1_m2(desired_message, N):
    # Choose a part of the desired message as m1 that the server is willing to sign.
    m1 = "You got a 1"  # For example, "1" is not a forbidden word.
    m1_int = int.from_bytes(m1.encode(), 'big')
    
    # Calculate m2_int
    desired_message_int = int.from_bytes(desired_message.encode(), 'big')
    m2_int = desired_message_int * pow(m1_int, -1, N) % N
    
    # Convert m2_int back to bytes and then to a string
    m2_length = (m2_int.bit_length() + 7) // 8  # Calculate the byte length of m2
    m2_bytes = m2_int.to_bytes(m2_length, 'big')
    m2 = m2_bytes
    
    return m1, m2

def combine_signatures(s1, s2):
    """Combine two RSA signatures."""
    combined = s1 * s2
    mm = pow(combined, e, N)
    #print("mm",mm)

    #print(mm == 2963568610001545030334693797041012763967927250566689853470901359885453663717221481071572781321000838804476495826426044375187929)
    return (s1 * s2) % N

def get_signature_for_hex_data(hex_data):
    """Get the signature from the server for the provided hex data."""
    response = requests.get(f'http://127.0.0.1:5000/sign_random_document_for_students/{hex_data}/')
    if response.status_code == 200:
        #print("got signatures")
        return response.json()['signature']
    else:
        raise ValueError('Could not get the signature from the server')

# Construct the messages
m = "You got a 12 because you are an excellent student! :)"
m1 = "You got a 1"  # "ten" is not on the forbidden list and can be a placeholder
m2 = "2 because you are an excellent student! :)"  # "Two" combined with "ten" can imply "twelve" without using the forbidden word
m1f,m2f = find_m1_m2(m,N)

# Convert messages to hexadecimal
m1_hex = m1f.encode().hex()
m2_hex = bytes.hex(m2f) 

# Get signatures from the server for m1 and m2
s1_hex = get_signature_for_hex_data(m1_hex)
s2_hex = get_signature_for_hex_data(m2_hex)

# Convert signatures from hex to integers
s1 = int(s1_hex, 16)
s2 = int(s2_hex, 16)

# Combine the signatures using the multiplicative property of RSA
combined_signature_int = combine_signatures(s1, s2)
combined_signature_hex = hex(combined_signature_int)[2:]

# Prepare the cookie content with the combined message and forged signature
combined_message = m1 + m2
#print(combined_message)
cookie_content = json.dumps({'msg': combined_message.encode().hex(), 'signature': combined_signature_hex})
cookie_base64 = base64.b64encode(cookie_content.encode(), altchars=b'-_').decode()

# Set the forged grade cookie
cookies = {'grade': cookie_base64}

# Now make a request to the grade endpoint with the forged cookie
grade_response = requests.get('http://127.0.0.1:5000/grade/', cookies=cookies)
if grade_response.status_code == 200:
    print("Grade Page Response:", grade_response.text)
else:
    print("Failed to get the grade page")
grade_response = requests.get('http://127.0.0.1:5000/quote/', cookies=cookies)
if grade_response.status_code == 200:
    print("Grade Page Response:", grade_response.text)
else:
    print("Failed to get the grade page")

