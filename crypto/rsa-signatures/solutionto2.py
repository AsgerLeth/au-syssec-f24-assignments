import requests
import json
import base64

# Server's public key parameters (you'd obtain these from the /pk/ endpoint)
N = 3347752952664162112522016889691738562339972666836621741627714172651995325002087108705064507513582631038197553343427152083711024713409925844303004545778746538606786770096346061504414337654738854264935919696637301113085578132666631360562592399987580255570582325688977891698768049935795873277803671043126351965913638993339332396347588902534933686402839038279888861510227341527527922413731837927716659539074718232767265308946725836661373270297066385487686320149863373110670548337897750789017735058874778869104756280411554030250748759851252906384863089901931255764757050932975935777857199070236180023314381522342163883374121019767353514037139827450397952627492898469242447665975662713437580378965790057125994986330898175971455616861493493670144320773693813801570548364425306442461262296145069971426136361428576280002522930026601119714964246741315413751938095415440908588836096925533240599433573694353597350861752717288476790663993
e = 65537

def find_m1_m2(desired_message, N):
    m1 = "You got a 1"
    m1_int = int.from_bytes(m1.encode(), 'big')
    
    # Calculate m2_int
    desired_message_int = int.from_bytes(desired_message.encode(), 'big')
    m2_int = desired_message_int * pow(m1_int, -1, N) % N
    
    # Converting m2_int back to bytes and to string
    m2_length = (m2_int.bit_length() + 7) // 8 
    m2_bytes = m2_int.to_bytes(m2_length, 'big')
    m2 = m2_bytes
    
    return m1, m2

def combine_signatures(s1, s2):
    #Combine the two RSA signatures
    return (s1 * s2) % N

def get_signature_for_hex_data(hex_data):
    #Get the signature for the hex data
    response = requests.get(f'https://cbc-rsa.syssec.dk:8001/sign_random_document_for_students/{hex_data}/')
    if response.status_code == 200:
        return response.json()['signature']
    else:
        raise ValueError('Could not get the signature from the server')


m = "You got a 12 because you are an excellent student! :)"
m1 = "You got a 1"  
m2 = "2 because you are an excellent student! :)"  
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

# Combining signatures
combined_signature_int = combine_signatures(s1, s2)
combined_signature_hex = hex(combined_signature_int)[2:]

# Prepare cookie content with the combined message and forged signature
combined_message = m1 + m2
cookie_content = json.dumps({'msg': combined_message.encode().hex(), 'signature': combined_signature_hex})
cookie_base64 = base64.b64encode(cookie_content.encode(), altchars=b'-_').decode()

# Set forged grade cookie
cookies = {'grade': cookie_base64}

# Request to the grade endpoint with the forged cookie
grade_response = requests.get('https://cbc-rsa.syssec.dk:8001/grade/', cookies=cookies)
if grade_response.status_code == 200:
    print("Grade Page Response:", grade_response.text)
else:
    print("Failed to get the grade page")
grade_response = requests.get('https://cbc-rsa.syssec.dk:8001/quote/', cookies=cookies)
if grade_response.status_code == 200:
    print("Quote Page Response:", grade_response.text)
else:
    print("Failed to get the grade page")

